"""JavaScript intelligence: endpoint and secret extraction from live JS.

Modern web apps expose much of their attack surface in client-side JavaScript:
internal API routes, hidden parameters, and — all too often — hard-coded
secrets (API keys, tokens, cloud credentials). This module fetches the JS
referenced by in-scope live services and mines it for:

  * endpoints / API paths (stored as URL assets for later testing), and
  * high-confidence secret patterns (reported as findings).

It only reads resources that the target already serves publicly; it does not
attempt to use any secret it finds. Treat any discovered secret as sensitive:
validate out-of-band and report it through the program, never test it live.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

from .base import Context, Module

# --- secret signatures (label, severity, compiled regex) -----------------
_SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("AWS Access Key ID", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret Access Key", "high",
     re.compile(r"(?i)aws_secret[^\"'\n]{0,20}['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("Google API Key", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Google OAuth", "medium", re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b")),
    ("Slack Token", "high", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")),
    ("Slack Webhook", "medium", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("GitHub Token", "high", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b")),
    ("Stripe Live Key", "high", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("Stripe Publishable", "low", re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b")),
    ("Twilio SID", "medium", re.compile(r"\bAC[0-9a-fA-F]{32}\b")),
    ("Mailgun Key", "high", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    ("SendGrid Key", "high", re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b")),
    ("Private Key Block", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("JWT", "low", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("Generic API Key assignment", "medium",
     re.compile(r"(?i)(api[_-]?key|apikey|secret|token|passwd|password)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z_\-]{16,}['\"]")),
    ("Firebase URL", "low", re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com")),
]

# --- endpoint extraction -------------------------------------------------
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.I)
_ENDPOINT_RE = re.compile(
    r"""['"`]((?:https?:)?/{1,2}[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{2,}?|/[A-Za-z0-9._\-/]{2,}?)['"`]"""
)
# Noise paths we don't want as "endpoints".
_ENDPOINT_IGNORE = re.compile(
    r"\.(png|jpe?g|gif|svg|webp|css|woff2?|ttf|eot|ico|map|mp4|webm)(\?|$)", re.I
)


class JsIntelModule(Module):
    name = "jsintel"
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
            ctx.log.warn("[jsintel] no in-scope services; run probe first")
            return {"js_files": 0, "endpoints": 0, "secrets": 0}

        max_files = int(ctx.config.get("modules.jsintel.max_files", 200))
        scan_secrets = bool(ctx.config.get("modules.jsintel.scan_secrets", True))

        # 1. Collect candidate JS URLs from each service's homepage.
        js_urls: set[str] = set()
        for base in bases:
            resp = ctx.http.get(base)
            if not resp.ok:
                continue
            html = resp.text(limit=500_000)
            for src in _SCRIPT_SRC_RE.findall(html):
                full = urljoin(resp.final_url or base, src)
                if full.lower().split("?")[0].endswith(".js") and ctx.scope.is_allowed(full):
                    js_urls.add(full)

        js_urls = set(list(js_urls)[:max_files])
        ctx.log.info(f"[jsintel] analysing {len(js_urls)} JS file(s)")

        endpoints: set[str] = set()
        secrets = 0
        workers = min(int(ctx.config.get("limits.concurrency", 20)), 30)

        def analyse(js_url: str) -> tuple[set[str], int]:
            resp = ctx.http.get(js_url)
            if not resp.ok:
                return set(), 0
            text = resp.text()
            found_eps = self._extract_endpoints(text, js_url)
            sec = self._extract_secrets(ctx, text, js_url) if scan_secrets else 0
            return found_eps, sec

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(analyse, u) for u in js_urls]
            for fut in as_completed(futs):
                eps, sec = fut.result()
                endpoints |= eps
                secrets += sec

        # Store discovered endpoints as URL assets, scope-filtered.
        stored_eps = 0
        for ep in endpoints:
            host = urlparse(ep).hostname
            # Relative endpoints (no host) are kept as-is; absolute ones are scope-checked.
            if host and not ctx.scope.is_allowed(host):
                continue
            ctx.store.add_asset(ep, "endpoint", source="jsintel", in_scope=True)
            stored_eps += 1

        ctx.log.success(
            f"[jsintel] {len(js_urls)} JS files -> {stored_eps} endpoints, {secrets} secrets"
        )
        return {"js_files": len(js_urls), "endpoints": stored_eps, "secrets": secrets}

    def _extract_endpoints(self, text: str, source: str) -> set[str]:
        out: set[str] = set()
        for m in _ENDPOINT_RE.findall(text):
            ep = m.strip()
            if len(ep) < 3 or _ENDPOINT_IGNORE.search(ep):
                continue
            if ep.startswith("//"):
                ep = "https:" + ep
            out.add(ep)
        return out

    def _extract_secrets(self, ctx: Context, text: str, source: str) -> int:
        count = 0
        for label, severity, pattern in _SECRET_PATTERNS:
            for match in set(pattern.findall(text)):
                sample = match if isinstance(match, str) else str(match)
                # Redact the middle of the value in the stored evidence.
                redacted = _redact(sample)
                ctx.store.add_finding(
                    target=source,
                    module="jsintel",
                    name=f"Possible {label} in JavaScript",
                    severity=severity,
                    evidence=f"Pattern '{label}' matched in {source}: {redacted}",
                    secret_type=label,
                )
                ctx.log.warn(f"[jsintel] {label} in {source}")
                count += 1
        return count


def _redact(value: str, keep: int = 4) -> str:
    if len(value) <= keep * 2:
        return value[:1] + "***"
    return f"{value[:keep]}…{value[-keep:]} (len {len(value)})"
