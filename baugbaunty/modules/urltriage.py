"""URL pattern triage — gf-style prioritisation of the discovered URL corpus.

Pure analysis (no traffic): it scans every URL/endpoint asset gathered by
wayback, crawl, jsintel, seeds and openapi, and tags those whose parameters
match well-known vulnerability-prone patterns (open redirect, SSRF, SQLi, XSS,
LFI, IDOR, SSTI, command injection). The output is a prioritised to-test list so
you aim manual effort where it is most likely to pay off.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

from .base import Context, Module

# Parameter-name patterns per likely vulnerability class (gf-inspired).
_PATTERNS: dict[str, set[str]] = {
    "redirect": {"url", "redirect", "redirect_uri", "redirecturl", "next", "return",
                 "returnurl", "returnto", "dest", "destination", "continue", "goto",
                 "out", "target", "rurl", "u", "link", "forward"},
    "ssrf": {"url", "uri", "u", "link", "src", "source", "dest", "callback", "webhook",
             "feed", "host", "port", "to", "out", "image", "imageurl", "img", "proxy",
             "fetch", "resource", "domain", "site", "load", "endpoint"},
    "sqli": {"id", "select", "report", "role", "update", "query", "user", "name",
             "sort", "where", "search", "params", "process", "row", "view", "table",
             "from", "sel", "results", "sleep", "fetch", "order", "column", "field",
             "delete", "string", "number", "filter"},
    "xss": {"q", "s", "search", "query", "keyword", "keywords", "id", "page", "message",
            "name", "comment", "callback", "lang", "redirect", "return", "token"},
    "lfi": {"file", "document", "folder", "root", "path", "pg", "style", "pdf",
            "template", "php_path", "doc", "page", "name", "cat", "dir", "action",
            "board", "date", "detail", "download", "prefix", "include", "inc", "locate",
            "show", "site", "type", "view", "content", "layout", "mod", "conf"},
    "idor": {"id", "user", "user_id", "account", "uid", "number", "no", "order",
             "order_id", "invoice", "doc", "document_id", "key", "email", "group",
             "profile", "edit", "report", "customer", "member", "member_id"},
    "ssti": {"template", "preview", "id", "view", "activity", "name", "content",
             "redirect"},
    "cmdi": {"cmd", "exec", "command", "execute", "ping", "query", "jump", "code",
             "reg", "do", "func", "arg", "option", "load", "process", "step", "read",
             "feature", "exe", "module", "payload", "run", "print"},
}


class UrlTriageModule(Module):
    name = "urltriage"
    active = False  # analysis of stored URLs; no traffic

    def run(self, ctx: Context) -> dict:
        assets = [a for a in ctx.store.assets()
                  if a["kind"] in ("url", "endpoint") and ctx.scope.is_allowed(a["value"])]
        if not assets:
            ctx.log.warn("[urltriage] no URLs to triage; run wayback/crawl/jsintel first")
            return {"urls": 0, "flagged": 0}

        counts: dict[str, int] = {k: 0 for k in _PATTERNS}
        flagged = 0
        for a in assets:
            cats = self._classify(a["value"])
            if not cats:
                continue
            flagged += 1
            for c in cats:
                counts[c] += 1
            ctx.store.add_finding(
                target=a["value"], module="urltriage",
                name=f"Testable URL — {', '.join(sorted(cats))}",
                severity="info",
                evidence=f"{a['value']} has parameter(s) matching: {', '.join(sorted(cats))}",
                categories=sorted(cats),
            )

        summary = ", ".join(f"{k}:{v}" for k, v in counts.items() if v)
        ctx.log.success(f"[urltriage] {flagged}/{len(assets)} URL(s) flagged [{summary or 'none'}]")
        return {"urls": len(assets), "flagged": flagged, "by_category": counts}

    @staticmethod
    def _classify(url: str) -> set[str]:
        params = set(parse_qs(urlparse(url).query).keys())
        if not params:
            return set()
        lowered = {p.lower() for p in params}
        cats: set[str] = set()
        for cat, names in _PATTERNS.items():
            if lowered & names:
                cats.add(cat)
        return cats
