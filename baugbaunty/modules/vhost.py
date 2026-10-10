"""Virtual-host discovery.

Many servers host multiple sites on one IP, switching on the ``Host`` header.
Some of those vhosts never appear in public DNS (internal apps, staging). By
sending in-scope candidate hostnames as the ``Host`` header to an in-scope IP
and comparing the response to a baseline, we surface those hidden sites.

Both the IP we connect to AND the Host header we send must be in scope.
"""

from __future__ import annotations

import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import Context, Module
from ..core.scope import Verdict


def _sig(status: int, length: int) -> tuple[int, int]:
    # Bucket content-length so trivial dynamic differences don't create noise.
    return status, length // 256


class VhostModule(Module):
    name = "vhost"
    active = True

    def __init__(self, ips: list[str] | None = None, candidates: list[str] | None = None) -> None:
        self.ips = ips
        self.candidates = candidates

    def _ips(self, ctx: Context) -> list[str]:
        raw = self.ips or [a["value"] for a in ctx.store.assets() if a["kind"] == "ip"]
        return [ip for ip in raw if ctx.scope.check(ip).verdict is Verdict.IN_SCOPE]

    def _candidates(self, ctx: Context) -> list[str]:
        if self.candidates:
            cands = self.candidates
        else:
            cands = [
                a["value"] for a in ctx.store.assets()
                if a["kind"] in ("subdomain", "domain")
            ]
        maxn = int(ctx.config.get("modules.vhost.max_hosts", 300))
        in_scope = [c for c in cands if ctx.scope.check(c).verdict is Verdict.IN_SCOPE]
        return in_scope[:maxn]

    def run(self, ctx: Context) -> dict:
        ips = self._ips(ctx)
        candidates = self._candidates(ctx)
        if not ips:
            ctx.log.warn("[vhost] no in-scope IPs; run dns first")
            return {"ips": 0, "vhosts": 0}
        if not candidates:
            ctx.log.warn("[vhost] no candidate hostnames")
            return {"ips": len(ips), "vhosts": 0}

        ctx.log.info(f"[vhost] {len(ips)} IP(s) x {len(candidates)} candidate host(s)")
        found = 0
        for ip in ips:
            found += self._scan_ip(ctx, ip, candidates)
        ctx.log.success(f"[vhost] {found} virtual host(s) discovered")
        return {"ips": len(ips), "vhosts": found}

    def _baseline(self, ctx: Context, ip: str) -> tuple[str, tuple[int, int]] | None:
        rand = "".join(random.choices(string.ascii_lowercase, k=16)) + ".invalid"
        for scheme in ("https", "http"):
            resp = ctx.http.get(f"{scheme}://{ip}", headers={"Host": rand})
            if resp.ok and resp.status:
                return scheme, _sig(resp.status, len(resp.body))
        return None

    def _scan_ip(self, ctx: Context, ip: str, candidates: list[str]) -> int:
        base = self._baseline(ctx, ip)
        if base is None:
            return 0
        scheme, base_sig = base
        found = 0
        workers = min(int(ctx.config.get("limits.concurrency", 20)), 30)

        def check(host: str) -> tuple[str, int, int] | None:
            resp = ctx.http.get(f"{scheme}://{ip}", headers={"Host": host})
            if not resp.ok or not resp.status:
                return None
            sig = _sig(resp.status, len(resp.body))
            # Different from the catch-all baseline and not an error page.
            if sig != base_sig and resp.status not in (400, 404, 421, 502, 503):
                return host, resp.status, len(resp.body)
            return None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(check, h) for h in candidates]
            for fut in as_completed(futs):
                res = fut.result()
                if not res:
                    continue
                host, status, length = res
                found += 1
                ctx.store.add_finding(
                    target=ip, module="vhost",
                    name=f"Virtual host on {ip}: {host} ({status})",
                    severity="info",
                    evidence=f"Host: {host} -> HTTP {status}, {length} bytes "
                             f"(differs from catch-all baseline) via {scheme}",
                    vhost=host, scheme=scheme,
                )
        return found
