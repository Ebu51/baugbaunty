"""Port scanning.

Prefers ``naabu`` (fast, respectful SYN/CONNECT scanner). If it is not
installed, falls back to a conservative stdlib TCP-connect scan over a small
set of common ports, routed through the rate limiter. Port scanning is active
traffic, so authorization is required.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import Context, Module
from ..core.scope import Verdict
from ..integrations import external

# A modest common-ports list for the native fallback.
_COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 6379, 8000, 8008, 8080, 8443, 8888, 9200,
    9300, 27017,
]


class PortsModule(Module):
    name = "ports"
    active = True

    def __init__(self, hosts: list[str] | None = None) -> None:
        self.hosts = hosts

    def _targets(self, ctx: Context) -> list[str]:
        raw = self.hosts or [
            a["value"]
            for a in ctx.store.assets(in_scope_only=True)
            if a["kind"] in ("subdomain", "domain", "ip")
        ]
        return [h for h in raw if ctx.scope.check(h).verdict is Verdict.IN_SCOPE]

    def run(self, ctx: Context) -> dict:
        targets = self._targets(ctx)
        if not targets:
            ctx.log.warn("[ports] no in-scope hosts")
            return {"hosts": 0, "open": 0}

        if ctx.config.get("modules.ports.use_external", True) and external.have("naabu"):
            return self._scan_naabu(ctx, targets)
        return self._scan_native(ctx, targets)

    def _scan_naabu(self, ctx: Context, targets: list[str]) -> dict:
        ctx.log.info(f"[ports] naabu scanning {len(targets)} hosts")
        top = int(ctx.config.get("modules.ports.top_ports", 100))
        open_count = 0
        for row in external.naabu(targets, top_ports=top):
            host = row.get("host") or row.get("ip")
            port = row.get("port")
            if not host or port is None or not ctx.scope.is_allowed(str(host)):
                continue
            ctx.store.add_asset(
                f"{host}:{port}", "service-port", source="naabu", in_scope=True
            )
            ctx.store.add_finding(
                target=f"{host}:{port}", module="ports",
                name=f"Open port {port} on {host}", severity="info",
                evidence=f"naabu reported {host}:{port} open",
            )
            open_count += 1
        ctx.log.success(f"[ports] naabu: {open_count} open ports")
        return {"hosts": len(targets), "open": open_count}

    def _scan_native(self, ctx: Context, targets: list[str]) -> dict:
        ctx.log.info(f"[ports] native TCP-connect scan on {len(targets)} hosts")
        open_count = 0
        workers = min(int(ctx.config.get("limits.concurrency", 20)), 50)

        jobs = [(h, p) for h in targets for p in _COMMON_PORTS]

        def check(host: str, port: int) -> tuple[str, int] | None:
            ctx.limiter.acquire(host)
            try:
                with socket.create_connection((host, port), timeout=3):
                    return (host, port)
            except (OSError, socket.timeout):
                return None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(check, h, p): (h, p) for h, p in jobs}
            for fut in as_completed(futs):
                res = fut.result()
                if not res:
                    continue
                host, port = res
                open_count += 1
                ctx.store.add_asset(f"{host}:{port}", "service-port", "native", True)
                ctx.store.add_finding(
                    target=f"{host}:{port}", module="ports",
                    name=f"Open port {port} on {host}", severity="info",
                    evidence=f"TCP connect succeeded to {host}:{port}",
                )
        ctx.log.success(f"[ports] native: {open_count} open ports")
        return {"hosts": len(targets), "open": open_count}
