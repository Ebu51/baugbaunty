"""Seed the attack surface from robots.txt, sitemap.xml and favicons.

These are freely served files that often reveal paths the site owner would
rather keep quiet (admin areas, staging routes, API bases) and let you
correlate technology by favicon hash. Everything discovered is scope-filtered
before storage. This phase reads only normally-served resources.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urljoin, urlparse

from .base import Context, Module

try:  # optional: mmh3 gives Shodan-compatible favicon hashes
    import mmh3  # type: ignore

    _HAVE_MMH3 = True
except Exception:
    _HAVE_MMH3 = False

import base64

_ROBOTS_PATH_RE = re.compile(r"(?im)^(?:dis)?allow\s*:\s*(\S+)")
_ROBOTS_SITEMAP_RE = re.compile(r"(?im)^sitemap\s*:\s*(\S+)")
_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)


class SeedsModule(Module):
    name = "seeds"
    active = True

    def __init__(self, services: list[str] | None = None) -> None:
        self.services = services

    def _bases(self, ctx: Context) -> list[str]:
        if self.services:
            return [s for s in self.services if ctx.scope.is_allowed(s)]
        return [s["url"] for s in ctx.store.services() if ctx.scope.is_allowed(s["url"])]

    def run(self, ctx: Context) -> dict:
        bases = self._bases(ctx)
        if not bases:
            ctx.log.warn("[seeds] no in-scope services; run probe first")
            return {"paths": 0, "favicons": 0}

        paths, favicons = 0, 0
        want_favicon = bool(ctx.config.get("modules.seeds.favicon", True))
        for base in bases:
            base = base.rstrip("/")
            paths += self._robots(ctx, base)
            paths += self._sitemap(ctx, f"{base}/sitemap.xml")
            if want_favicon and self._favicon(ctx, base):
                favicons += 1

        ctx.log.success(f"[seeds] {paths} seeded path(s), {favicons} favicon hash(es)")
        return {"paths": paths, "favicons": favicons}

    def _store_url(self, ctx: Context, url: str) -> bool:
        host = urlparse(url).hostname or ""
        if not host or not ctx.scope.is_allowed(host):
            return False
        ctx.store.add_asset(url, "endpoint", source="seeds", in_scope=True)
        return True

    def _robots(self, ctx: Context, base: str) -> int:
        resp = ctx.http.get(f"{base}/robots.txt")
        if not resp.ok or resp.status != 200:
            return 0
        body = resp.text(limit=200_000)
        n = 0
        for path in _ROBOTS_PATH_RE.findall(body):
            if path and path != "/":
                if self._store_url(ctx, urljoin(base + "/", path.lstrip("/"))):
                    n += 1
        for sm in _ROBOTS_SITEMAP_RE.findall(body):
            n += self._sitemap(ctx, sm)
        return n

    def _sitemap(self, ctx: Context, sitemap_url: str) -> int:
        if not ctx.scope.is_allowed(sitemap_url):
            return 0
        resp = ctx.http.get(sitemap_url)
        if not resp.ok or resp.status != 200:
            return 0
        n = 0
        for loc in _LOC_RE.findall(resp.text(limit=1_000_000)):
            loc = loc.strip()
            # Nested sitemaps end in .xml; recurse once.
            if loc.lower().endswith(".xml") and loc != sitemap_url:
                n += self._sitemap(ctx, loc)
            elif self._store_url(ctx, loc):
                n += 1
        return n

    def _favicon(self, ctx: Context, base: str) -> bool:
        resp = ctx.http.get(f"{base}/favicon.ico")
        if not resp.ok or resp.status != 200 or not resp.body:
            return False
        md5 = hashlib.md5(resp.body).hexdigest()
        attrs = {"favicon_md5": md5}
        if _HAVE_MMH3:
            b64 = base64.encodebytes(resp.body)
            attrs["favicon_mmh3"] = str(mmh3.hash(b64))
        ctx.store.add_finding(
            target=base, module="seeds",
            name="Favicon hash captured", severity="info",
            evidence=f"favicon md5={md5}"
            + (f" mmh3={attrs.get('favicon_mmh3')}" if _HAVE_MMH3 else ""),
            **attrs,
        )
        return True
