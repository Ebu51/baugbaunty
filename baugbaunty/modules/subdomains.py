"""Passive subdomain enumeration.

Sources used here are PASSIVE: they query third-party datasets (certificate
transparency logs via crt.sh, and optionally the ``subfinder`` tool which
aggregates many passive sources). We never brute-force the target's DNS here,
so this module is safe to run before authorization is confirmed — though the
results are still only actionable within program scope.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request

from .base import Context, Module
from ..core.scope import Verdict
from ..integrations import external


class SubdomainModule(Module):
    name = "subdomains"
    active = False  # passive OSINT only

    def __init__(self, domains: list[str]) -> None:
        self.domains = domains

    def run(self, ctx: Context) -> dict:
        found: set[str] = set()
        for domain in self.domains:
            domain = domain.strip().lower().lstrip("*.")
            if not domain:
                continue
            ctx.log.info(f"[subdomains] enumerating {domain}")
            before = len(found)

            found |= self._crtsh(ctx, domain)

            if ctx.config.get("modules.subdomains.use_external", True) and external.have("subfinder"):
                subs = external.subfinder(domain)
                if subs:
                    ctx.log.debug(f"[subdomains] subfinder returned {len(subs)}")
                    found |= {s.lower() for s in subs}

            ctx.log.success(
                f"[subdomains] {domain}: +{len(found) - before} (total {len(found)})"
            )

        # Persist, tagging each with its scope verdict.
        in_scope = 0
        for sub in sorted(found):
            decision = ctx.scope.check(sub)
            allowed = decision.verdict is Verdict.IN_SCOPE
            ctx.store.add_asset(sub, "subdomain", source="passive", in_scope=allowed)
            if allowed:
                in_scope += 1

        ctx.log.success(
            f"[subdomains] done: {len(found)} unique, {in_scope} in scope"
        )
        return {"total": len(found), "in_scope": in_scope}

    def _crtsh(self, ctx: Context, domain: str) -> set[str]:
        """Query crt.sh certificate transparency logs (third-party, passive)."""

        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        ctx.limiter.acquire("crt.sh")
        results: set[str] = set()
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": ctx.http.user_agent}
            )
            ctx_ssl = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=30, context=ctx_ssl) as resp:
                raw = resp.read()
            data = json.loads(raw.decode("utf-8", errors="replace"))
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain) and "@" not in name:
                        results.add(name)
        except (urllib.error.URLError, json.JSONDecodeError, ssl.SSLError, OSError) as e:
            ctx.log.warn(f"[subdomains] crt.sh failed for {domain}: {e}")
        return results
