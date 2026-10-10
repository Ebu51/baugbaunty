"""GitHub code-search dorking for leaked references to the target (passive).

Developers accidentally push internal hostnames, API keys and config to public
repositories all the time. This phase searches GitHub's code index for mentions
of the target's domains alongside secret-ish keywords and records each hit as a
lead (repository + path + URL) — it never stores file contents or any secret
value, and it touches GitHub, not the target, so it is passive.

Requires a GitHub token (code search is authenticated-only). Set it via
``modules.githubdork.token`` or the ``GITHUB_TOKEN`` environment variable. With
no token the phase logs a notice and skips.
"""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from .base import Context, Module

_DORK_TERMS = ["password", "api_key", "apikey", "secret", "token", "aws_access", "authorization"]
_API = "https://api.github.com/search/code"


class GithubDorkModule(Module):
    name = "githubdork"
    active = False  # searches GitHub, not the target

    def __init__(self, domains: list[str] | None = None) -> None:
        self.domains = domains

    def _token(self, ctx: Context) -> str:
        return (
            ctx.config.get("modules.githubdork.token", "")
            or os.environ.get("GITHUB_TOKEN", "")
            or os.environ.get("GH_TOKEN", "")
        )

    def run(self, ctx: Context) -> dict:
        token = self._token(ctx)
        if not token:
            ctx.log.warn("[githubdork] no GitHub token (modules.githubdork.token or "
                         "GITHUB_TOKEN) — skipping")
            return {"skipped": True, "leads": 0}

        domains = self.domains or [r.lstrip("*.") for r in ctx.config.get("scope.include", [])]
        terms = ctx.config.get("modules.githubdork.terms", _DORK_TERMS)
        max_per_query = int(ctx.config.get("modules.githubdork.max_results", 20))
        leads = 0

        for domain in domains:
            for term in terms:
                query = f'"{domain}" {term}'
                items = self._search(ctx, token, query, max_per_query)
                for it in items:
                    repo = (it.get("repository") or {}).get("full_name", "")
                    path = it.get("path", "")
                    html = it.get("html_url", "")
                    leads += 1
                    ctx.store.add_finding(
                        target=domain, module="githubdork",
                        name=f"Possible leak in GitHub repo {repo}",
                        severity="medium",
                        evidence=f"Query '{query}' matched {repo}/{path}",
                        repo=repo, path=path, url=html, dork=term,
                    )
                    ctx.log.warn(f"[githubdork] {domain}: {repo}/{path}")
                # GitHub search API: 30 req/min authenticated — stay well under.
                time.sleep(2.2)

        ctx.log.success(f"[githubdork] {leads} lead(s) across {len(domains)} domain(s)")
        return {"leads": leads}

    def _search(self, ctx: Context, token: str, query: str, per_page: int) -> list[dict]:
        url = f"{_API}?q={urllib.parse.quote(query)}&per_page={per_page}"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": ctx.http.user_agent,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30, context=ssl.create_default_context()) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            return data.get("items", []) or []
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                ctx.log.warn("[githubdork] rate-limited by GitHub; backing off")
                time.sleep(10)
            else:
                ctx.log.warn(f"[githubdork] search failed ({e.code}) for '{query}'")
            return []
        except (urllib.error.URLError, ssl.SSLError, OSError, json.JSONDecodeError) as e:
            ctx.log.warn(f"[githubdork] search error: {e}")
            return []
