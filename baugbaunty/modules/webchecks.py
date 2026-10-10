"""Safe, non-exploit web vulnerability checks: CORS, open redirect, reflection.

Each check observes how the target responds to a crafted but harmless request.
Nothing here weaponises a finding:

  * CORS         — send a foreign Origin, see if it is trusted with credentials.
  * open redirect — set a redirect-like parameter to a benign canary URL and
                    see whether the server 3xx-redirects off-site to it.
  * reflection    — inject a unique marker with HTML metacharacters and see if
                    it comes back unencoded (an XSS *candidate*, not a proof).

Findings are leads to verify by hand, deliberately conservative to limit noise.
"""

from __future__ import annotations

import json
import random
import string
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .base import Context, Module

_CANARY_HOST = "canary-bbx.example"  # benign, non-routable test destination
_REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirecturl", "return", "returnurl", "returnto",
    "next", "url", "dest", "destination", "continue", "goto", "out", "target",
    "rurl", "u", "link", "forward", "callback",
}
# Parameters commonly backed by a server-side fetch (SSRF-prone).
_SSRF_PARAMS = {
    "url", "uri", "u", "link", "src", "source", "dest", "destination", "redirect",
    "redirect_uri", "callback", "webhook", "feed", "host", "port", "to", "out",
    "image", "imageurl", "img", "proxy", "path", "load", "fetch", "data", "resource",
    "domain", "site", "page", "continue", "open", "view", "window", "api", "endpoint",
}


def _marker() -> str:
    return "bbx" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


class WebChecksModule(Module):
    name = "webchecks"
    active = True

    def __init__(self, targets: list[str] | None = None) -> None:
        self.targets = targets

    def run(self, ctx: Context) -> dict:
        checks = set(ctx.config.get("modules.webchecks.checks", ["cors", "openredirect", "reflection"]))
        maxn = int(ctx.config.get("modules.webchecks.max_targets", 300))
        findings = 0

        if "cors" in checks:
            findings += self._cors(ctx, self._service_urls(ctx)[:maxn])
        if "hostheader" in checks:
            findings += self._host_header(ctx, self._service_urls(ctx)[:maxn])
        if {"openredirect", "reflection", "crlf", "ssrf"} & checks:
            pairs = self._param_targets(ctx)[:maxn]
            if "openredirect" in checks:
                findings += self._open_redirect(ctx, pairs)
            if "reflection" in checks:
                findings += self._reflection(ctx, pairs)
            if "crlf" in checks:
                findings += self._crlf(ctx, pairs)
            if "ssrf" in checks:
                canary = ctx.config.get("modules.webchecks.ssrf_canary", "")
                if canary:
                    findings += self._ssrf(ctx, pairs, canary)
                else:
                    ctx.log.info("[webchecks] ssrf check skipped (no ssrf_canary configured)")

        ctx.log.success(f"[webchecks] {findings} lead(s) flagged")
        return {"findings": findings}

    # --- target gathering -------------------------------------------------
    def _service_urls(self, ctx: Context) -> list[str]:
        if self.targets:
            return [t for t in self.targets if ctx.scope.is_allowed(t)]
        return [s["url"] for s in ctx.store.services() if ctx.scope.is_allowed(s["url"])]

    def _param_targets(self, ctx: Context) -> list[tuple[str, str]]:
        """Return (url, param) pairs to fuzz, from archived URLs + discovered params."""

        pairs: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        def add(url: str, param: str) -> None:
            base = url.split("#")[0]
            key = (base.split("?")[0], param)
            if key in seen or not ctx.scope.is_allowed(base):
                return
            seen.add(key)
            pairs.append((base, param))

        # URLs that already carry parameters (wayback/jsintel/seeds).
        for a in ctx.store.assets():
            if a["kind"] not in ("url", "endpoint"):
                continue
            q = parse_qs(urlparse(a["value"]).query)
            for p in q:
                add(a["value"], p)

        # Parameters discovered by the params module, applied to their service.
        for f in ctx.store.findings():
            if f.get("module") == "params":
                try:
                    data = json.loads(f.get("data") or "{}")
                except json.JSONDecodeError:
                    data = {}
                p = data.get("param")
                if p:
                    add(f.get("target", ""), p)
        return pairs

    # --- CORS -------------------------------------------------------------
    def _cors(self, ctx: Context, urls: list[str]) -> int:
        n = 0
        for url in urls:
            origin = f"https://{_marker()}.evil.example"
            resp = ctx.http.get(url, headers={"Origin": origin})
            if not resp.ok:
                continue
            acao = resp.header("access-control-allow-origin")
            acac = resp.header("access-control-allow-credentials").lower() == "true"
            if not acao:
                continue
            reflects = acao == origin
            wildcard = acao == "*"
            if reflects and acac:
                sev, desc = "high", "reflects arbitrary Origin AND allows credentials"
            elif reflects:
                sev, desc = "medium", "reflects arbitrary Origin"
            elif wildcard and acac:
                sev, desc = "medium", "wildcard ACAO with credentials"
            else:
                continue
            n += 1
            ctx.store.add_finding(
                target=url, module="webchecks",
                name=f"CORS misconfiguration ({desc})", severity=sev,
                evidence=f"Origin: {origin} -> ACAO: {acao}, ACAC: {acac}",
            )
            ctx.log.warn(f"[webchecks] CORS {sev}: {url}")
        return n

    # --- open redirect ----------------------------------------------------
    def _open_redirect(self, ctx: Context, pairs: list[tuple[str, str]]) -> int:
        n = 0
        for url, param in pairs:
            if param.lower() not in _REDIRECT_PARAMS:
                continue
            canary = f"https://{_CANARY_HOST}/bbx"
            test = _set_param(url, param, canary)
            resp = ctx.http.get(test, follow_redirects=False)
            loc = resp.header("location")
            if loc and (_CANARY_HOST in loc) and (
                loc.startswith("http") or loc.startswith("//")
            ):
                n += 1
                ctx.store.add_finding(
                    target=test, module="webchecks",
                    name=f"Open redirect via '{param}'", severity="medium",
                    evidence=f"Set {param}={canary} -> Location: {loc}",
                    param=param,
                )
                ctx.log.warn(f"[webchecks] open redirect: {test}")
        return n

    # --- reflection (XSS candidate) --------------------------------------
    def _reflection(self, ctx: Context, pairs: list[tuple[str, str]]) -> int:
        n = 0
        for url, param in pairs:
            marker = _marker()
            payload = f"{marker}\"'<>"
            test = _set_param(url, param, payload)
            resp = ctx.http.get(test)
            if not resp.ok:
                continue
            body = resp.text()
            if payload in body:
                # Metacharacters returned unencoded -> strong XSS candidate.
                n += 1
                ctx.store.add_finding(
                    target=test, module="webchecks",
                    name=f"Reflected input (XSS candidate) via '{param}'",
                    severity="low",
                    evidence=f"Marker with \"'<> reflected unencoded in response of {test}",
                    param=param, note="verify manually; not confirmed exploitable",
                )
                ctx.log.warn(f"[webchecks] reflection: {test}")
            elif marker in body:
                # Reflected but encoded/escaped — weaker signal, info only.
                ctx.store.add_finding(
                    target=test, module="webchecks",
                    name=f"Parameter value reflected via '{param}'",
                    severity="info",
                    evidence=f"Value reflected (metacharacters appear encoded) in {test}",
                    param=param,
                )
        return n


    # --- host header injection -------------------------------------------
    def _host_header(self, ctx: Context, urls: list[str]) -> int:
        n = 0
        evil = f"{_marker()}.evil.example"
        for url in urls:
            resp = ctx.http.get(
                url,
                headers={"Host": evil, "X-Forwarded-Host": evil},
                follow_redirects=False,
            )
            if not resp.ok:
                continue
            loc = resp.header("location")
            body = resp.text(limit=100_000)
            if (loc and evil in loc) or (evil in body):
                where = "Location header" if (loc and evil in loc) else "response body"
                n += 1
                ctx.store.add_finding(
                    target=url, module="webchecks",
                    name="Host header injection (reflected)", severity="medium",
                    evidence=f"Injected Host/X-Forwarded-Host '{evil}' reflected in {where}",
                )
                ctx.log.warn(f"[webchecks] host-header injection: {url}")
        return n

    # --- CRLF / response splitting ---------------------------------------
    def _crlf(self, ctx: Context, pairs: list[tuple[str, str]]) -> int:
        n = 0
        for url, param in pairs:
            marker = _marker()
            # The CR/LF are URL-encoded on the wire; a vulnerable server decodes
            # them and emits our header.
            payload = f"x\r\n{marker}: bbxcrlf"
            test = _set_param(url, param, payload)
            resp = ctx.http.get(test, follow_redirects=False)
            if resp.ok and resp.header(marker) == "bbxcrlf":
                n += 1
                ctx.store.add_finding(
                    target=test, module="webchecks",
                    name=f"CRLF / header injection via '{param}'", severity="medium",
                    evidence=f"Injected header '{marker}' appeared in the response of {test}",
                    param=param,
                )
                ctx.log.warn(f"[webchecks] CRLF injection: {test}")
        return n

    # --- SSRF (out-of-band canary) ---------------------------------------
    def _ssrf(self, ctx: Context, pairs: list[tuple[str, str]], canary: str) -> int:
        n = 0
        for url, param in pairs:
            if param.lower() not in _SSRF_PARAMS:
                continue
            marker = _marker()
            # Unique subdomain per probe so canary logs identify the exact param.
            probe = f"http://{marker}.{canary}/"
            test = _set_param(url, param, probe)
            resp = ctx.http.get(test)
            reflected = resp.ok and (marker in resp.text(limit=50_000) or canary in resp.text(limit=50_000))
            n += 1
            ctx.store.add_finding(
                target=test, module="webchecks",
                name=f"SSRF probe sent via '{param}'",
                severity="info",
                evidence=(
                    f"Sent {param}={probe}. Check your canary ({canary}) logs for "
                    f"'{marker}' — a hit confirms server-side request forgery."
                    + (" Canary value was also reflected in the response." if reflected else "")
                ),
                param=param, canary_marker=marker,
            )
        if n:
            ctx.log.info(f"[webchecks] sent {n} SSRF canary probe(s) -> check {canary} logs")
        return n


def _set_param(url: str, param: str, value: str) -> str:
    parts = urlparse(url)
    q = parse_qs(parts.query)
    q[param] = [value]
    new_q = urlencode({k: v[-1] for k, v in q.items()})
    return urlunparse(parts._replace(query=new_q))
