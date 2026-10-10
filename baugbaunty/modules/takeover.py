"""Subdomain takeover detection.

A subdomain whose CNAME points at a de-provisioned third-party service (an
unclaimed S3 bucket, a deleted Heroku app, a dangling GitHub Pages site, ...)
can often be *claimed by an attacker*, who then controls content on your
target's subdomain. These are high-impact, frequently-accepted bug bounty
findings and are low-risk to test (we only read the normally-served response).

Detection combines two weak signals into a strong one:
  1. the subdomain's CNAME matches a known third-party provider, and
  2. the HTTP response contains that provider's "unclaimed / not found"
     fingerprint string.

The curated fingerprint set below is a representative subset modelled on the
community ``can-i-take-over-xyz`` project. Point ``modules.takeover.extra``
at your own JSON list to extend it.
"""

from __future__ import annotations

import json
from pathlib import Path

from .base import Context, Module
from ..core.scope import Verdict

# Each entry: service name -> {cname: [substrings], fingerprint: [body markers],
#                              vulnerable: bool}
_FINGERPRINTS: dict[str, dict] = {
    "AWS/S3": {
        "cname": ["s3.amazonaws.com", "s3-website", "s3.", ".amazonaws.com"],
        "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"],
        "vulnerable": True,
    },
    "GitHub Pages": {
        "cname": ["github.io", "github.map.fastly.net"],
        "fingerprint": ["There isn't a GitHub Pages site here", "404 - File not found"],
        "vulnerable": True,
    },
    "Heroku": {
        "cname": ["herokuapp.com", "herokudns.com"],
        "fingerprint": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
        "vulnerable": True,
    },
    "Fastly": {
        "cname": ["fastly.net"],
        "fingerprint": ["Fastly error: unknown domain"],
        "vulnerable": True,
    },
    "Shopify": {
        "cname": ["myshopify.com"],
        "fingerprint": ["Sorry, this shop is currently unavailable",
                        "Only one step left!"],
        "vulnerable": True,
    },
    "Tumblr": {
        "cname": ["domains.tumblr.com"],
        "fingerprint": ["Whatever you were looking for doesn't currently exist at this address"],
        "vulnerable": True,
    },
    "Zendesk": {
        "cname": ["zendesk.com"],
        "fingerprint": ["Help Center Closed", "this help center no longer exists"],
        "vulnerable": True,
    },
    "Unbounce": {
        "cname": ["unbouncepages.com"],
        "fingerprint": ["The requested URL was not found on this server"],
        "vulnerable": True,
    },
    "Surge.sh": {
        "cname": ["surge.sh"],
        "fingerprint": ["project not found"],
        "vulnerable": True,
    },
    "Pantheon": {
        "cname": ["pantheonsite.io"],
        "fingerprint": ["The gods are wise", "404 error unknown site"],
        "vulnerable": True,
    },
    "Ghost": {
        "cname": ["ghost.io"],
        "fingerprint": ["The thing you were looking for is no longer here"],
        "vulnerable": True,
    },
    "Azure": {
        "cname": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net",
                  "blob.core.windows.net", "azureedge.net"],
        "fingerprint": ["404 Web Site not found", "The resource you are looking for has been removed"],
        "vulnerable": True,
    },
    "Bitbucket": {
        "cname": ["bitbucket.io"],
        "fingerprint": ["Repository not found"],
        "vulnerable": True,
    },
    "Readthedocs": {
        "cname": ["readthedocs.io"],
        "fingerprint": ["unknown to Read the Docs"],
        "vulnerable": True,
    },
}


class TakeoverModule(Module):
    name = "takeover"
    active = True  # issues HTTP requests to target subdomains

    def __init__(self, hosts: list[str] | None = None) -> None:
        self.hosts = hosts

    def _load_fingerprints(self, ctx: Context) -> dict[str, dict]:
        fps = dict(_FINGERPRINTS)
        extra = ctx.config.get("modules.takeover.extra", "")
        if extra and Path(extra).exists():
            try:
                fps.update(json.loads(Path(extra).read_text(encoding="utf-8")))
                ctx.log.info(f"[takeover] merged extra fingerprints from {extra}")
            except (json.JSONDecodeError, OSError) as e:
                ctx.log.warn(f"[takeover] could not load {extra}: {e}")
        return fps

    def _targets(self, ctx: Context) -> list[dict]:
        if self.hosts:
            return [{"value": h, "data": "{}"} for h in self.hosts]
        return [
            a for a in ctx.store.assets()
            if a["kind"] in ("subdomain", "domain")
            and ctx.scope.check(a["value"]).verdict is Verdict.IN_SCOPE
        ]

    def run(self, ctx: Context) -> dict:
        targets = self._targets(ctx)
        if not targets:
            ctx.log.warn("[takeover] no in-scope hosts")
            return {"checked": 0, "vulnerable": 0}

        fps = self._load_fingerprints(ctx)
        ctx.log.info(f"[takeover] checking {len(targets)} hosts against {len(fps)} signatures")
        vuln = 0

        for asset in targets:
            host = asset["value"]
            cnames = _asset_cnames(asset)
            matched = self._check_host(ctx, host, cnames, fps)
            if matched:
                vuln += 1

        ctx.log.success(f"[takeover] done: {vuln} potential takeover(s)")
        return {"checked": len(targets), "vulnerable": vuln}

    def _check_host(self, ctx: Context, host: str, cnames: list[str], fps: dict) -> bool:
        # Fetch the normally-served response once (https then http).
        body = ""
        for scheme in ("https", "http"):
            resp = ctx.http.get(f"{scheme}://{host}")
            if resp.ok and resp.status:
                body = resp.text(limit=100_000)
                break
        cname_blob = " ".join(cnames).lower()

        for service, sig in fps.items():
            cname_hit = any(c.lower() in cname_blob for c in sig.get("cname", []))
            fp_hit = any(marker in body for marker in sig.get("fingerprint", []))
            # Strong signal: provider fingerprint in the body. CNAME raises confidence.
            if fp_hit:
                severity = "high" if sig.get("vulnerable", False) else "medium"
                confidence = "high" if cname_hit else "medium"
                ctx.store.add_finding(
                    target=host,
                    module="takeover",
                    name=f"Possible subdomain takeover ({service})",
                    severity=severity,
                    evidence=(
                        f"{host} serves the '{service}' unclaimed-resource "
                        f"fingerprint" + (f"; CNAME -> {cname_blob}" if cname_hit else "")
                    ),
                    service=service,
                    confidence=confidence,
                    cname=cnames,
                )
                ctx.log.warn(
                    f"[takeover] {host}: {service} fingerprint (confidence={confidence})"
                )
                return True
        return False


def _asset_cnames(asset: dict) -> list[str]:
    try:
        data = json.loads(asset.get("data") or "{}")
    except json.JSONDecodeError:
        return []
    cn = data.get("cname", [])
    return cn if isinstance(cn, list) else [cn]
