"""Content / endpoint discovery.

Probes a wordlist of paths against each in-scope live service to find
interesting endpoints (admin panels, backups, config files, API routes).

Politeness is paramount: requests flow through the shared rate limiter, and we
use a baseline/soft-404 calibration so we don't report every path on servers
that answer 200 to everything.
"""

from __future__ import annotations

import os
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .base import Context, Module

# Small built-in list so the module works with no external wordlist. A real
# engagement should point ``modules.content.wordlist`` at something bigger
# (e.g. SecLists raft / common.txt).
_BUILTIN_PATHS = [
    "admin", "login", "dashboard", "api", "api/v1", "api/v2", "graphql",
    ".git/config", ".env", ".env.local", "config.json", "config.php",
    "backup", "backup.zip", "backup.sql", "db.sql", "dump.sql",
    "robots.txt", "sitemap.xml", ".well-known/security.txt",
    "server-status", "phpinfo.php", "info.php", "debug", "test",
    "swagger", "swagger.json", "swagger-ui.html", "openapi.json",
    "actuator", "actuator/health", "actuator/env", "metrics",
    "wp-admin", "wp-login.php", "wp-json", "xmlrpc.php",
    "static", "uploads", "files", "console", "status",
]

# Paths worth flagging as findings if present and accessible.
_SENSITIVE = {
    ".git/config", ".env", ".env.local", "backup.zip", "backup.sql",
    "db.sql", "dump.sql", "phpinfo.php", "info.php", "actuator/env",
    "swagger.json", "openapi.json",
}


class ContentModule(Module):
    name = "content"
    active = True

    def __init__(self, services: list[str] | None = None) -> None:
        self.services = services

    def _load_wordlist(self, ctx: Context) -> list[str]:
        wl = ctx.config.get("modules.content.wordlist", "")
        if wl and Path(wl).exists():
            words = [
                l.strip()
                for l in Path(wl).read_text(encoding="utf-8", errors="ignore").splitlines()
                if l.strip() and not l.startswith("#")
            ]
            ctx.log.info(f"[content] loaded {len(words)} paths from {wl}")
            return words
        ctx.log.info(f"[content] using built-in list ({len(_BUILTIN_PATHS)} paths)")
        return list(_BUILTIN_PATHS)

    def _base_urls(self, ctx: Context) -> list[str]:
        if self.services:
            return [s for s in self.services if ctx.scope.is_allowed(s)]
        return [s["url"] for s in ctx.store.services() if ctx.scope.is_allowed(s["url"])]

    def _expand(self, ctx: Context, words: list[str]) -> list[str]:
        """Apply extension permutations to each word."""

        exts = ctx.config.get("modules.content.permute_ext", []) or []
        if not exts:
            return words
        out: list[str] = []
        for w in words:
            out.append(w)
            # Don't double-append extensions to words that already have a dot path.
            if "." in w.split("/")[-1]:
                continue
            for ext in exts:
                out.append(w + ext)
        # De-dup while preserving order.
        return list(dict.fromkeys(out))

    def run(self, ctx: Context) -> dict:
        bases = self._base_urls(ctx)
        if not bases:
            ctx.log.warn("[content] no in-scope services; run probe first")
            return {"checked": 0, "found": 0}

        words = self._expand(ctx, self._load_wordlist(ctx))
        allow = set(ctx.config.get("modules.content.status_allow", [200, 301, 302, 401, 403]))
        recurse = bool(ctx.config.get("modules.content.recurse", False))
        max_depth = int(ctx.config.get("modules.content.max_depth", 1))
        total_found = 0

        for base in bases:
            base = base.rstrip("/")
            found = self._scan_recursive(
                ctx, base, "", words, allow, recurse, max_depth, depth=0, seen=set()
            )
            total_found += found
            ctx.log.success(f"[content] {base}: {found} interesting paths")

        return {"checked": len(bases), "found": total_found}

    def _calibrate(self, ctx: Context, base: str, prefix: str) -> int | None:
        """Request a random path to learn the server's 'not found' status."""

        rand = "".join(random.choices(string.ascii_lowercase, k=16))
        root = f"{base}/{prefix}".rstrip("/")
        resp = ctx.http.get(f"{root}/{rand}", follow_redirects=False)
        return resp.status if resp.ok else None

    def _scan_recursive(
        self, ctx: Context, base: str, prefix: str, words: list[str], allow: set,
        recurse: bool, max_depth: int, depth: int, seen: set,
    ) -> int:
        root = f"{base}/{prefix}".rstrip("/")
        soft404 = self._calibrate(ctx, base, prefix)
        found = 0
        recurse_into: list[str] = []
        workers = int(ctx.config.get("limits.concurrency", 20))

        def check(path: str) -> tuple[str, int] | None:
            url = f"{root}/{path.lstrip('/')}"
            if not ctx.scope.is_allowed(url):
                return None
            # Don't follow redirects: a 301/302 is itself a discovery signal.
            resp = ctx.http.get(url, follow_redirects=False)
            if not resp.ok or resp.status == 0:
                return None
            if soft404 is not None and resp.status == soft404 and resp.status not in (401, 403):
                return None
            if resp.status in allow:
                return (path, resp.status)
            return None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(check, w): w for w in words}
            for fut in as_completed(futs):
                res = fut.result()
                if not res:
                    continue
                path, status = res
                rel = f"{prefix}/{path.lstrip('/')}".lstrip("/")
                url = f"{base}/{rel}"
                if url in seen:
                    continue
                seen.add(url)
                found += 1
                severity = "info"
                name = f"Discovered path: /{rel} ({status})"
                if path in _SENSITIVE and status in (200, 301, 302):
                    severity = "medium"
                    name = f"Sensitive path exposed: /{rel} ({status})"
                ctx.store.add_finding(
                    target=url, module="content", name=name,
                    severity=severity, evidence=f"HTTP {status} at {url}",
                )
                # Directory-like hits are recursion candidates.
                if recurse and depth < max_depth and self._dir_like(path, status):
                    recurse_into.append(rel.rstrip("/"))

        for sub in recurse_into:
            found += self._scan_recursive(
                ctx, base, sub, words, allow, recurse, max_depth, depth + 1, seen
            )
        return found

    @staticmethod
    def _dir_like(path: str, status: int) -> bool:
        last = path.rstrip("/").split("/")[-1]
        # No file extension and a redirect/success -> likely a directory.
        return "." not in last and status in (200, 301, 302, 403)
