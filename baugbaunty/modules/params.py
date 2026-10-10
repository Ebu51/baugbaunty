"""Hidden parameter discovery (Arjun-style).

Web endpoints often accept parameters that aren't referenced anywhere in the
HTML or JS. Finding them expands the testable surface for access-control,
injection and logic bugs. We detect a parameter when supplying it either:

  * reflects our unique probe value into the response, or
  * measurably changes the response (status or length) versus the baseline.

Requests are chunked and rate-limited to stay polite. Values are harmless
random markers — this phase discovers parameters, it does not attack them.
"""

from __future__ import annotations

import random
import string
from pathlib import Path
from urllib.parse import urlencode, urlparse

from .base import Context, Module

_BUILTIN_PARAMS = [
    "id", "page", "search", "q", "query", "lang", "debug", "test", "admin",
    "user", "username", "email", "token", "api_key", "key", "callback",
    "redirect", "redirect_uri", "return", "returnurl", "next", "url", "dest",
    "destination", "continue", "file", "path", "dir", "download", "action",
    "cmd", "exec", "code", "format", "view", "template", "include", "type",
    "sort", "order", "filter", "limit", "offset", "start", "end", "ref",
    "source", "mode", "status", "state", "role", "access", "preview", "draft",
    "show", "hide", "enable", "disable", "force", "raw", "json", "xml", "data",
]


def _rand(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class ParamsModule(Module):
    name = "params"
    active = True

    def __init__(self, targets: list[str] | None = None) -> None:
        self.targets = targets

    def _load_params(self, ctx: Context) -> list[str]:
        wl = ctx.config.get("modules.params.wordlist", "")
        if wl and Path(wl).exists():
            words = [
                l.strip() for l in Path(wl).read_text(encoding="utf-8", errors="ignore").splitlines()
                if l.strip() and not l.startswith("#")
            ]
            return words[: int(ctx.config.get("modules.params.max_params", 500))]
        return list(_BUILTIN_PARAMS)

    def _targets(self, ctx: Context) -> list[str]:
        if self.targets:
            cands = self.targets
        else:
            # Prefer live services; they are the clearest baseline.
            cands = [s["url"] for s in ctx.store.services()]
        seen, out = set(), []
        for u in cands:
            key = u.split("?")[0]
            if key in seen or not ctx.scope.is_allowed(u):
                continue
            seen.add(key)
            out.append(key)
        return out

    def run(self, ctx: Context) -> dict:
        targets = self._targets(ctx)
        if not targets:
            ctx.log.warn("[params] no in-scope targets; run probe first")
            return {"targets": 0, "params": 0}

        params = self._load_params(ctx)
        chunk = int(ctx.config.get("modules.params.chunk_size", 25))
        ctx.log.info(f"[params] {len(targets)} target(s) x {len(params)} param name(s)")
        total = 0
        for url in targets:
            total += self._discover(ctx, url, params, chunk)
        ctx.log.success(f"[params] {total} parameter(s) discovered")
        return {"targets": len(targets), "params": total}

    def _discover(self, ctx: Context, url: str, params: list[str], chunk: int) -> int:
        baseline = ctx.http.get(url)
        if not baseline.ok or not baseline.status:
            return 0
        base_len = len(baseline.body)
        base_status = baseline.status
        discovered: set[str] = set()

        for i in range(0, len(params), chunk):
            group = params[i : i + chunk]
            markers = {p: _rand() for p in group}
            qs = urlencode(markers)
            resp = ctx.http.get(f"{url}?{qs}")
            if not resp.ok:
                continue
            body = resp.text()
            # 1) reflection: which marker values came back?
            reflected = [p for p, v in markers.items() if v in body]
            for p in reflected:
                discovered.add(p)
            # 2) response changed materially -> isolate which param(s).
            changed = resp.status != base_status or abs(len(resp.body) - base_len) > 64
            if changed and len(reflected) < len(group):
                for p in group:
                    if p in discovered:
                        continue
                    one = ctx.http.get(f"{url}?{urlencode({p: markers[p]})}")
                    if not one.ok:
                        continue
                    # Reflected value, or a material status/length change.
                    if (
                        markers[p] in one.text()
                        or one.status != base_status
                        or abs(len(one.body) - base_len) > 48
                    ):
                        discovered.add(p)

        for p in sorted(discovered):
            ctx.store.add_finding(
                target=url, module="params",
                name=f"Hidden parameter discovered: {p}",
                severity="info",
                evidence=f"Parameter '{p}' changed or reflected in the response of {url}",
                param=p,
            )
        return len(discovered)
