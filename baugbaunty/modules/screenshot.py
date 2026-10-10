"""Screenshot live services for fast visual triage.

A wall of screenshots is the quickest way to spot the interesting hosts among
hundreds of live services (login panels, default installs, error pages, staging
dashboards). This module captures each in-scope service and records the image
path on the service.

Capture backend, in order of preference:
  1. Playwright (Python) driving the bundled Chromium, if importable.
  2. The ``gowitness`` CLI, if installed.
  3. Otherwise it logs a notice and skips — the rest of the pipeline is
     unaffected.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import Context, Module
from ..integrations import external


def _safe_name(url: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", url)[:120] + ".png"


class ScreenshotModule(Module):
    name = "screenshot"
    active = True

    def __init__(self, services: list[str] | None = None) -> None:
        self.services = services

    def _targets(self, ctx: Context) -> list[str]:
        if self.services:
            return [s for s in self.services if ctx.scope.is_allowed(s)]
        return [s["url"] for s in ctx.store.services() if ctx.scope.is_allowed(s["url"])]

    def run(self, ctx: Context) -> dict:
        targets = self._targets(ctx)
        if not targets:
            ctx.log.warn("[screenshot] no in-scope services; run probe first")
            return {"captured": 0}

        out_dir = Path(ctx.config.get("output.dir", "output")) / "screenshots"
        out_dir.mkdir(parents=True, exist_ok=True)

        if _playwright_available():
            n = self._capture_playwright(ctx, targets, out_dir)
        elif external.have("gowitness"):
            n = self._capture_gowitness(ctx, targets, out_dir)
        else:
            ctx.log.warn("[screenshot] no backend (install playwright or gowitness) — skipping")
            return {"captured": 0, "skipped": True}

        ctx.log.success(f"[screenshot] captured {n} screenshot(s) -> {out_dir}")
        return {"captured": n, "dir": str(out_dir)}

    def _capture_playwright(self, ctx: Context, targets: list[str], out_dir: Path) -> int:
        from playwright.sync_api import sync_playwright  # type: ignore

        timeout = int(float(ctx.config.get("limits.timeout", 10)) * 1000)
        n = 0
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox", "--ignore-certificate-errors"])
            ctxb = browser.new_context(ignore_https_errors=True,
                                       user_agent=ctx.http.user_agent)
            for url in targets:
                # Honour the rate limiter even for the browser backend.
                from urllib.parse import urlparse
                ctx.limiter.acquire(urlparse(url).hostname or "")
                path = out_dir / _safe_name(url)
                try:
                    page = ctxb.new_page()
                    page.goto(url, timeout=timeout, wait_until="domcontentloaded")
                    page.screenshot(path=str(path), full_page=False)
                    page.close()
                    ctx.store.add_service(url, data={"screenshot": str(path)})
                    n += 1
                except Exception as e:  # pragma: no cover - env dependent
                    ctx.log.debug(f"[screenshot] failed {url}: {e}")
            browser.close()
        return n

    def _capture_gowitness(self, ctx: Context, targets: list[str], out_dir: Path) -> int:
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            list_path = f.name
        res = external.run(
            ["gowitness", "file", "-f", list_path, "--screenshot-path", str(out_dir)],
            timeout=600,
        )
        if not res.ok:
            ctx.log.warn(f"[screenshot] gowitness failed: {res.stderr[:200]}")
        # Count produced PNGs.
        return len(list(out_dir.glob("*.png")))


def _playwright_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401

        return True
    except Exception:
        return False
