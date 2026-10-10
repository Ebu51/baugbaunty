"""Lightweight in-scope web crawler (spider).

Inspired by katana/gospider: starting from each live service, it follows links
within scope, bounded by page and depth limits, and harvests:

  * URLs / endpoints (stored as assets, feeding content/params/webchecks),
  * query parameters seen on links,
  * HTML forms (their action + input names), and
  * links to other in-scope subdomains (fed back as subdomain assets, so
    recursive discovery can resolve and probe them).

Every request goes through the scope gate and rate limiter; the crawler never
leaves the program scope.
"""

from __future__ import annotations

import re
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs

from .base import Context, Module

_HREF_RE = re.compile(r"""<a\s[^>]*?href\s*=\s*['"]([^'"#]+)['"]""", re.I)
_SRC_RE = re.compile(r"""<(?:script|iframe|link)\s[^>]*?(?:src|href)\s*=\s*['"]([^'"#]+)['"]""", re.I)
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_ACTION_RE = re.compile(r"""action\s*=\s*['"]([^'"]*)['"]""", re.I)
_METHOD_RE = re.compile(r"""method\s*=\s*['"]([^'"]*)['"]""", re.I)
_INPUT_RE = re.compile(r"""<(?:input|select|textarea)\s[^>]*?name\s*=\s*['"]([^'"]+)['"]""", re.I)
_NONPAGE = re.compile(r"\.(png|jpe?g|gif|svg|webp|css|woff2?|ttf|eot|ico|pdf|zip|mp4|webm)($|\?)", re.I)


class CrawlModule(Module):
    name = "crawl"
    active = True

    def __init__(self, services: list[str] | None = None) -> None:
        self.services = services

    def _seeds(self, ctx: Context) -> list[str]:
        if self.services:
            return [s for s in self.services if ctx.scope.is_allowed(s)]
        return [s["url"] for s in ctx.store.services() if ctx.scope.is_allowed(s["url"])]

    def run(self, ctx: Context) -> dict:
        seeds = self._seeds(ctx)
        if not seeds:
            ctx.log.warn("[crawl] no in-scope services; run probe first")
            return {"pages": 0, "urls": 0, "forms": 0}

        max_pages = int(ctx.config.get("modules.crawl.max_pages", 200))
        max_depth = int(ctx.config.get("modules.crawl.max_depth", 3))

        # Optional headless rendering for JS/SPA pages (katana -headless style).
        headless = bool(ctx.config.get("modules.crawl.headless", False))
        browser = page = pw = None
        if headless:
            if _playwright_available():
                from playwright.sync_api import sync_playwright
                pw = sync_playwright().start()
                browser = pw.chromium.launch(args=["--no-sandbox", "--ignore-certificate-errors"])
                page = browser.new_context(ignore_https_errors=True,
                                           user_agent=ctx.http.user_agent).new_page()
                ctx.log.info("[crawl] headless rendering enabled")
            else:
                ctx.log.warn("[crawl] headless requested but Playwright unavailable — "
                             "falling back to static crawl")

        visited: set[str] = set()
        queued: set[str] = set()
        queue: deque[tuple[str, int]] = deque()
        for s in seeds:
            u = s.rstrip("/")
            queue.append((u, 0))
            queued.add(u)

        pages = 0
        urls_found = 0
        forms_found = 0

        while queue and pages < max_pages:
            url, depth = queue.popleft()
            if url in visited or not ctx.scope.is_allowed(url):
                continue
            visited.add(url)
            if page is not None:
                html, base, ctype = self._render(ctx, url, page)
                if html is None:
                    continue
            else:
                resp = ctx.http.get(url)
                if not resp.ok or resp.status == 0:
                    continue
                ctype = resp.header("content-type")
                if "html" not in ctype and ctype:
                    continue
                html = resp.text(limit=1_000_000)
                base = resp.final_url or url
            pages += 1

            # 1) forms
            forms_found += self._harvest_forms(ctx, base, html)

            # 2) links
            links = set(_HREF_RE.findall(html)) | set(_SRC_RE.findall(html))
            for raw in links:
                full = urljoin(base, raw.strip())
                full = full.split("#")[0]
                if not full.startswith("http"):
                    continue
                host = urlparse(full).hostname or ""
                if not host or not ctx.scope.is_allowed(full):
                    continue
                # Record the URL/endpoint and any parameters.
                kind = "url" if "?" in full else "endpoint"
                ctx.store.add_asset(full, kind, source="crawl", in_scope=True)
                urls_found += 1
                # Feed a newly-seen subdomain back for recursive discovery.
                ctx.store.add_asset(host, "subdomain", source="crawl", in_scope=True)
                # Enqueue same-scope HTML-ish pages for further crawling.
                if (depth < max_depth and full not in queued
                        and not _NONPAGE.search(full)):
                    queue.append((full, depth + 1))
                    queued.add(full)

        if browser is not None:
            try:
                browser.close()
                pw.stop()
            except Exception:  # pragma: no cover
                pass

        ctx.log.success(
            f"[crawl] {pages} page(s), {urls_found} in-scope URL(s), {forms_found} form(s)"
        )
        return {"pages": pages, "urls": urls_found, "forms": forms_found}

    def _render(self, ctx: Context, url: str, page):
        """Render a page headlessly; return (html, final_url, content_type)."""
        from urllib.parse import urlparse

        ctx.limiter.acquire(urlparse(url).hostname or "")
        timeout = int(float(ctx.config.get("limits.timeout", 10)) * 1000)
        try:
            page.goto(url, timeout=timeout, wait_until="domcontentloaded")
            return page.content(), page.url, "text/html"
        except Exception as e:  # pragma: no cover - env dependent
            ctx.log.debug(f"[crawl] headless render failed {url}: {e}")
            return None, url, ""

    def _harvest_forms(self, ctx: Context, base: str, html: str) -> int:
        n = 0
        # Pair each <form ...> opening tag with its body for action/method.
        for opening, body in re.findall(r"(<form\b[^>]*>)(.*?)</form>", html, re.I | re.S):
            action = _ACTION_RE.search(opening)
            method = _METHOD_RE.search(opening)
            action_url = urljoin(base, action.group(1)) if action and action.group(1) else base
            if not ctx.scope.is_allowed(action_url):
                continue
            inputs = _INPUT_RE.findall(body)
            verb = (method.group(1).upper() if method else "GET")
            ctx.store.add_asset(action_url, "endpoint", source="crawl-form", in_scope=True)
            if inputs:
                ctx.store.add_finding(
                    target=action_url, module="crawl",
                    name=f"Form discovered ({verb}, {len(inputs)} field(s))",
                    severity="info",
                    evidence=f"{verb} form at {action_url} with fields: {', '.join(inputs[:20])}",
                    method=verb, fields=inputs,
                )
            n += 1
        return n


def _playwright_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401

        return True
    except Exception:
        return False
