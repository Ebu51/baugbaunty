"""Historical URL mining from public archives (passive).

Pulls previously-seen URLs for the target's domains from the Wayback Machine
and AlienVault OTX. These archives are third-party OSINT (not the target), so
requests go to the archives directly and are rate-limited but not scope-gated.
Every *returned* URL is then filtered through the program scope before being
stored — out-of-scope archive hits are dropped.

Historical URLs are a rich source of forgotten endpoints, old parameters and
deprecated APIs that are still live.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse

from .base import Context, Module

# Extensions worth flagging as potentially interesting when found in history.
_INTERESTING_EXT = {
    ".json", ".xml", ".sql", ".bak", ".config", ".env", ".log", ".yml",
    ".yaml", ".zip", ".tar", ".gz", ".git", ".swp", ".old", ".backup",
}


class WaybackModule(Module):
    name = "wayback"
    active = False  # third-party archives only

    def __init__(self, domains: list[str] | None = None) -> None:
        self.domains = domains

    def run(self, ctx: Context) -> dict:
        domains = self.domains or [
            r.lstrip("*.") for r in ctx.config.get("scope.include", [])
        ]
        sources = ctx.config.get("modules.wayback.sources", ["wayback", "otx"])
        max_urls = int(ctx.config.get("modules.wayback.max_urls", 5000))

        all_urls: set[str] = set()
        for domain in domains:
            ctx.log.info(f"[wayback] mining history for {domain}")
            if "wayback" in sources:
                all_urls |= self._wayback(ctx, domain, max_urls)
            if "otx" in sources:
                all_urls |= self._otx(ctx, domain)

        stored, interesting = 0, 0
        for url in all_urls:
            host = urlparse(url).hostname or ""
            if not host or not ctx.scope.is_allowed(host):
                continue
            ctx.store.add_asset(url, "url", source="archive", in_scope=True)
            stored += 1
            if self._is_interesting(url):
                interesting += 1
                ctx.store.add_finding(
                    target=url, module="wayback",
                    name="Interesting archived URL",
                    severity="info",
                    evidence=f"Historical URL from public archives: {url}",
                )

        ctx.log.success(
            f"[wayback] {stored} in-scope archived URLs ({interesting} interesting)"
        )
        return {"urls": stored, "interesting": interesting}

    def _fetch(self, ctx: Context, url: str, host_label: str, timeout: int = 60) -> bytes | None:
        ctx.limiter.acquire(host_label)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ctx.http.user_agent})
            with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
                return resp.read()
        except (urllib.error.URLError, ssl.SSLError, OSError) as e:
            ctx.log.warn(f"[wayback] fetch failed ({host_label}): {e}")
            return None

    def _wayback(self, ctx: Context, domain: str, max_urls: int) -> set[str]:
        q = urllib.parse.quote(f"*.{domain}/*", safe="")
        url = (
            f"https://web.archive.org/cdx/search/cdx?url={q}"
            f"&output=json&collapse=urlkey&fl=original&limit={max_urls}"
        )
        raw = self._fetch(ctx, url, "web.archive.org")
        if not raw:
            return set()
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return set()
        # First row is the header (["original"]).
        return {row[0] for row in data[1:] if row}

    def _otx(self, ctx: Context, domain: str) -> set[str]:
        urls: set[str] = set()
        page_url = (
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
            f"?limit=500&page=1"
        )
        raw = self._fetch(ctx, page_url, "otx.alienvault.com")
        if not raw:
            return urls
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return urls
        for entry in data.get("url_list", []):
            u = entry.get("url")
            if u:
                urls.add(u)
        return urls

    @staticmethod
    def _is_interesting(url: str) -> bool:
        path = urlparse(url).path.lower()
        if any(path.endswith(ext) for ext in _INTERESTING_EXT):
            return True
        # URLs carrying parameters are worth revisiting for injection testing.
        return "?" in url and "=" in url
