"""Live host probing: which assets answer HTTP(S), and what are they?

For each in-scope host we try https:// then http://, record status, title,
server and detected tech, and also flag a few passive, non-intrusive security
observations (missing security headers, verbose server banners). Nothing here
is an exploit attempt — it is observation of normally returned responses.

If ``httpx`` is installed it is used for speed and richer detection; otherwise
the built-in stdlib prober runs.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import Context, Module
from . import fingerprint
from ..core.scope import Verdict
from ..integrations import external

# Headers whose absence is a low-severity, reportable hardening gap.
_SECURITY_HEADERS = [
    ("strict-transport-security", "Missing HSTS header"),
    ("content-security-policy", "Missing Content-Security-Policy"),
    ("x-frame-options", "Missing X-Frame-Options (clickjacking)"),
    ("x-content-type-options", "Missing X-Content-Type-Options"),
]


class ProbeModule(Module):
    name = "probe"
    active = True

    def __init__(self, hosts: list[str] | None = None) -> None:
        self.hosts = hosts

    def _targets(self, ctx: Context) -> list[str]:
        if self.hosts:
            raw = self.hosts
        else:
            raw = [a["value"] for a in ctx.store.assets(in_scope_only=True)]
        # Only ever probe in-scope hosts.
        return [h for h in raw if ctx.scope.check(h).verdict is Verdict.IN_SCOPE]

    def run(self, ctx: Context) -> dict:
        targets = self._targets(ctx)
        if not targets:
            ctx.log.warn("[probe] no in-scope hosts to probe")
            return {"probed": 0, "live": 0}

        ctx.log.info(f"[probe] probing {len(targets)} in-scope hosts")

        if ctx.config.get("modules.subdomains.use_external", True) and external.have("httpx"):
            return self._probe_httpx(ctx, targets)
        return self._probe_native(ctx, targets)

    # --- external (httpx) -------------------------------------------------
    def _probe_httpx(self, ctx: Context, targets: list[str]) -> dict:
        ctx.log.debug("[probe] using external httpx")
        live = 0
        for row in external.httpx_probe(targets):
            url = row.get("url") or row.get("input") or ""
            if not url or not ctx.scope.is_allowed(url):
                continue
            tech = row.get("tech") or row.get("technologies") or []
            ctx.store.add_service(
                url,
                host=row.get("host") or row.get("input"),
                status=row.get("status_code") or row.get("status-code"),
                title=row.get("title", ""),
                server=row.get("webserver") or row.get("server", ""),
                tech=tech if isinstance(tech, list) else [tech],
                content_length=row.get("content_length") or row.get("content-length"),
            )
            live += 1
        ctx.log.success(f"[probe] httpx: {live} live services")
        return {"probed": len(targets), "live": live}

    # --- native (stdlib) --------------------------------------------------
    def _probe_native(self, ctx: Context, targets: list[str]) -> dict:
        live = 0
        workers = int(ctx.config.get("limits.concurrency", 20))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(self._probe_one, ctx, h): h for h in targets}
            for fut in as_completed(futs):
                try:
                    if fut.result():
                        live += 1
                except Exception as e:  # pragma: no cover
                    ctx.log.debug(f"[probe] error on {futs[fut]}: {e}")
        ctx.log.success(f"[probe] native: {live} live services")
        return {"probed": len(targets), "live": live}

    def _probe_one(self, ctx: Context, host: str) -> bool:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            resp = ctx.http.get(url)
            if not resp.ok or resp.status == 0:
                continue
            tech = fingerprint.fingerprint(resp)
            title = fingerprint.extract_title(resp.body)
            clen = resp.header("content-length")
            ctx.store.add_service(
                url,
                host=host,
                status=resp.status,
                title=title,
                server=resp.header("server"),
                tech=tech,
                content_length=int(clen) if clen.isdigit() else len(resp.body),
            )
            self._passive_header_checks(ctx, url, resp)
            return True
        return False

    def _passive_header_checks(self, ctx: Context, url: str, resp) -> None:
        # Only meaningful for successful HTML responses over HTTPS.
        for header, desc in _SECURITY_HEADERS:
            if header == "strict-transport-security" and not url.startswith("https"):
                continue
            if not resp.header(header):
                ctx.store.add_finding(
                    target=url,
                    module="probe",
                    name=desc,
                    severity="low" if header in ("content-security-policy",) else "info",
                    evidence=f"Response to GET {url} lacks '{header}'",
                )
