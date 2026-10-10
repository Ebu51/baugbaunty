"""DNS resolution, wildcard detection and CNAME extraction.

Turns the raw list of candidate subdomains into *resolvable* hosts, which is
the foundation every active phase depends on. It also detects wildcard DNS so
you don't drown in phantom subdomains that all point at the same catch-all IP.

Resolution is considered non-intrusive recon (it queries public/authoritative
resolvers, not the target's web application), so this module is passive and
does not require the authorization gate. It uses ``dnsx`` when available,
otherwise the standard library resolver.
"""

from __future__ import annotations

import random
import socket
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import Context, Module
from ..core.scope import Verdict
from ..integrations import external


def _resolve(host: str) -> tuple[list[str], list[str]]:
    """Return (ips, cname_aliases) for a host, best-effort, stdlib only."""

    ips: set[str] = set()
    aliases: list[str] = []
    try:
        name, alias_list, ipaddrs = socket.gethostbyname_ex(host)
        ips.update(ipaddrs)
        aliases = [a for a in alias_list if a != host]
    except (socket.gaierror, socket.herror, OSError, UnicodeError):
        pass
    # IPv6 best-effort.
    try:
        for info in socket.getaddrinfo(host, None, socket.AF_INET6):
            ips.add(info[4][0])
    except (socket.gaierror, OSError, UnicodeError):
        pass
    return sorted(ips), aliases


class DnsModule(Module):
    name = "dns"
    active = False  # resolution only; not traffic to the web target

    def __init__(self, hosts: list[str] | None = None) -> None:
        self.hosts = hosts

    def _targets(self, ctx: Context) -> list[str]:
        raw = self.hosts or [
            a["value"]
            for a in ctx.store.assets()
            if a["kind"] in ("subdomain", "domain")
        ]
        return [h for h in raw if ctx.scope.check(h).verdict is Verdict.IN_SCOPE]

    def _wildcard_ips(self, ctx: Context, domain: str) -> set[str]:
        """Resolve a few random labels; shared IPs indicate wildcard DNS."""

        count = int(ctx.config.get("modules.dns.wildcard_test_count", 3))
        seen: list[set[str]] = []
        for _ in range(count):
            label = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
            ips, _ = _resolve(f"{label}.{domain}")
            if ips:
                seen.append(set(ips))
        if not seen:
            return set()
        # Intersection of IPs that showed up for random (non-existent) names.
        wildcard = set.intersection(*seen) if len(seen) > 1 else seen[0]
        if wildcard:
            ctx.log.warn(f"[dns] wildcard DNS detected on {domain}: {sorted(wildcard)}")
        return wildcard

    def run(self, ctx: Context) -> dict:
        targets = self._targets(ctx)
        if not targets:
            ctx.log.warn("[dns] no in-scope hosts to resolve")
            return {"resolved": 0, "wildcard_filtered": 0}

        if ctx.config.get("modules.dns.use_external", True) and external.have("dnsx"):
            # dnsx gives authoritative CNAME/A data fast; still filter by scope.
            return self._run_dnsx(ctx, targets)

        # Learn wildcard IPs per apex domain first.
        roots = {r.lstrip("*.") for r in ctx.config.get("scope.include", [])}
        wildcard_ips: dict[str, set[str]] = {}
        if ctx.config.get("modules.dns.detect_wildcard", True):
            for root in roots:
                wildcard_ips[root] = self._wildcard_ips(ctx, root)

        resolved = 0
        wild = 0
        workers = min(int(ctx.config.get("limits.concurrency", 20)), 40)

        def work(host: str) -> tuple[str, list[str], list[str]]:
            ips, aliases = _resolve(host)
            return host, ips, aliases

        filter_wc = bool(ctx.config.get("modules.dns.filter_wildcard", True))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(work, h) for h in targets]
            for fut in as_completed(futs):
                host, ips, aliases = fut.result()
                if not ips:
                    ctx.store.update_asset_data(host, "subdomain", resolved=False)
                    continue
                # Is this host ONLY pointing at a wildcard catch-all?
                apex = next((r for r in roots if host.endswith(r)), "")
                wc = wildcard_ips.get(apex, set())
                is_wild = bool(wc) and set(ips).issubset(wc)
                ctx.store.update_asset_data(
                    host, "subdomain",
                    resolved=True, ips=ips, cname=aliases, wildcard=is_wild,
                )
                if is_wild and filter_wc:
                    wild += 1
                    continue
                resolved += 1
                # Record discovered IPs as assets too.
                for ip in ips:
                    ctx.store.add_asset(ip, "ip", source="dns", in_scope=ctx.scope.is_allowed(ip))

        ctx.log.success(
            f"[dns] resolved {resolved} host(s); {wild} wildcard-only filtered"
        )
        return {"resolved": resolved, "wildcard_filtered": wild}

    def _run_dnsx(self, ctx: Context, targets: list[str]) -> dict:
        ctx.log.info(f"[dns] using external dnsx on {len(targets)} hosts")
        argv = ["dnsx", "-silent", "-json", "-a", "-aaaa", "-cname", "-resp"]
        resolved = 0
        for row in external.stream_jsonl(argv, stdin="\n".join(targets), timeout=300):
            host = row.get("host", "")
            if not host or not ctx.scope.is_allowed(host):
                continue
            ips = (row.get("a", []) or []) + (row.get("aaaa", []) or [])
            cname = row.get("cname", []) or []
            ctx.store.update_asset_data(
                host, "subdomain", resolved=bool(ips), ips=ips, cname=cname
            )
            if ips:
                resolved += 1
                for ip in ips:
                    ctx.store.add_asset(ip, "ip", "dnsx", ctx.scope.is_allowed(ip))
        ctx.log.success(f"[dns] dnsx resolved {resolved} host(s)")
        return {"resolved": resolved, "wildcard_filtered": 0}
