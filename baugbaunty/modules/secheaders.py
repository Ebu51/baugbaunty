"""Deep security-header analysis: CSP weaknesses and cookie flags.

`probe` flags *missing* headers; this goes deeper into the values that are
present. It fetches each in-scope service once and reports:

  * Content-Security-Policy weaknesses (`unsafe-inline`, `unsafe-eval`,
    wildcard sources, missing `object-src`/`base-uri`, or no CSP at all), and
  * cookies missing the `HttpOnly`, `Secure` or `SameSite` attributes.

These are configuration findings (low/info) — real, reportable hardening gaps
that are easy to miss by eye.
"""

from __future__ import annotations

import re

from .base import Context, Module

_CSP_BAD = [
    ("unsafe-inline", "allows inline scripts/styles (weakens XSS protection)"),
    ("unsafe-eval", "allows eval() (weakens XSS protection)"),
    ("data:", "allows data: URIs as a source"),
]


class SecHeadersModule(Module):
    name = "secheaders"
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
            ctx.log.warn("[secheaders] no in-scope services; run probe first")
            return {"checked": 0, "findings": 0}

        n = 0
        for base in bases:
            resp = ctx.http.get(base)
            if not resp.ok or not resp.status:
                continue
            n += self._analyze_csp(ctx, base, resp.header("content-security-policy"))
            n += self._analyze_cookies(ctx, base, resp)

        ctx.log.success(f"[secheaders] {n} header/cookie finding(s)")
        return {"checked": len(bases), "findings": n}

    def _analyze_csp(self, ctx: Context, base: str, csp: str) -> int:
        if not csp:
            return 0  # 'missing CSP' already covered by probe
        low = csp.lower()
        n = 0
        for token, desc in _CSP_BAD:
            if token in low:
                ctx.store.add_finding(
                    target=base, module="secheaders",
                    name=f"Weak CSP: {token}", severity="low",
                    evidence=f"CSP on {base} contains '{token}' — {desc}",
                )
                n += 1
        # Wildcard source in script-src/default-src.
        if re.search(r"(script-src|default-src)[^;]*\*", low):
            ctx.store.add_finding(
                target=base, module="secheaders",
                name="Weak CSP: wildcard source", severity="low",
                evidence=f"CSP on {base} uses '*' in script-src/default-src",
            )
            n += 1
        for directive in ("object-src", "base-uri"):
            if directive not in low:
                ctx.store.add_finding(
                    target=base, module="secheaders",
                    name=f"CSP missing {directive}", severity="info",
                    evidence=f"CSP on {base} does not set {directive}",
                )
                n += 1
        return n

    def _analyze_cookies(self, ctx: Context, base: str, resp) -> int:
        # Collect all Set-Cookie header values.
        cookies = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]
        single = resp.header("set-cookie")
        if single and single not in cookies:
            cookies.append(single)
        n = 0
        for cookie in cookies:
            name = cookie.split("=", 1)[0].strip()
            low = cookie.lower()
            missing = [flag for flag, tok in
                       (("HttpOnly", "httponly"), ("Secure", "secure"), ("SameSite", "samesite"))
                       if tok not in low]
            if missing:
                sev = "low" if "HttpOnly" in missing or "Secure" in missing else "info"
                ctx.store.add_finding(
                    target=base, module="secheaders",
                    name=f"Cookie '{name}' missing {', '.join(missing)}", severity=sev,
                    evidence=f"Set-Cookie '{name}' on {base} lacks: {', '.join(missing)}",
                    cookie=name, missing=missing,
                )
                n += 1
        return n
