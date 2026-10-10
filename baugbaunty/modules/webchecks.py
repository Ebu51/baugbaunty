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
        if {"openredirect", "reflection"} & checks:
            pairs = self._param_targets(ctx)[:maxn]
            if "openredirect" in checks:
                findings += self._open_redirect(ctx, pairs)
            if "reflection" in checks:
                findings += self._reflection(ctx, pairs)

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


def _set_param(url: str, param: str, value: str) -> str:
    parts = urlparse(url)
    q = parse_qs(parts.query)
    q[param] = [value]
    new_q = urlencode({k: v[-1] for k, v in q.items()})
    return urlunparse(parts._replace(query=new_q))
