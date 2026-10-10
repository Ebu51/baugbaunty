"""Passive subdomain enumeration.

Sources used here are PASSIVE: they query third-party datasets — certificate
transparency (crt.sh), free passive-DNS/OSINT APIs (HackerTarget, RapidDNS,
Anubis/jldc, AlienVault OTX) and optionally the ``subfinder`` tool which
aggregates many more. We never brute-force the target's DNS here, so this module
is safe to run before authorization is confirmed — though the results are still
only actionable within program scope.
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request

from .base import Context, Module
from ..core.scope import Verdict
from ..integrations import external

_HOST_RE = re.compile(r"[a-z0-9_.-]+", re.I)


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

            sources = ctx.config.get(
                "modules.subdomains.sources",
                ["crtsh", "hackertarget", "rapiddns", "anubis", "otx"],
            )
            source_map = {
                "crtsh": self._crtsh,
                "hackertarget": self._hackertarget,
                "rapiddns": self._rapiddns,
                "anubis": self._anubis,
                "otx": self._otx,
            }
            for src in sources:
                fn = source_map.get(src)
                if fn:
                    found |= fn(ctx, domain)

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

    def _fetch(self, ctx: Context, url: str, host_label: str, timeout: int = 30) -> bytes | None:
        ctx.limiter.acquire(host_label)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ctx.http.user_agent})
            with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
                return resp.read()
        except (urllib.error.URLError, ssl.SSLError, OSError) as e:
            ctx.log.warn(f"[subdomains] {host_label} failed for {url}: {e}")
            return None

    def _harvest(self, text: str, domain: str) -> set[str]:
        """Pull every host under ``domain`` out of an arbitrary text blob."""

        out: set[str] = set()
        for token in _HOST_RE.findall(text.lower()):
            token = token.strip(".").lstrip("*.")
            if token.endswith(domain) and "@" not in token and ".." not in token:
                out.add(token)
        return out

    def _hackertarget(self, ctx: Context, domain: str) -> set[str]:
        raw = self._fetch(ctx, f"https://api.hackertarget.com/hostsearch/?q={domain}",
                           "api.hackertarget.com")
        if not raw:
            return set()
        text = raw.decode("utf-8", errors="replace")
        if "error" in text.lower() and "," not in text:
            return set()
        return {line.split(",")[0].strip().lower() for line in text.splitlines()
                if line.strip() and line.split(",")[0].strip().lower().endswith(domain)}

    def _rapiddns(self, ctx: Context, domain: str) -> set[str]:
        raw = self._fetch(ctx, f"https://rapiddns.io/subdomain/{domain}?full=1",
                          "rapiddns.io")
        if not raw:
            return set()
        return self._harvest(raw.decode("utf-8", errors="replace"), domain)

    def _anubis(self, ctx: Context, domain: str) -> set[str]:
        raw = self._fetch(ctx, f"https://jldc.me/anubis/subdomains/{domain}", "jldc.me")
        if not raw:
            return set()
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return set()
        return {str(s).strip().lower() for s in data
                if str(s).strip().lower().endswith(domain)} if isinstance(data, list) else set()

    def _otx(self, ctx: Context, domain: str) -> set[str]:
        raw = self._fetch(
            ctx,
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            "otx.alienvault.com",
        )
        if not raw:
            return set()
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return set()
        out: set[str] = set()
        for rec in data.get("passive_dns", []) or []:
            hn = str(rec.get("hostname", "")).strip().lower().lstrip("*.")
            if hn.endswith(domain) and "@" not in hn:
                out.add(hn)
        return out
