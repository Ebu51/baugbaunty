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
    "Acquia": {
        "cname": ["acquia-sites.com", "acquia.com"],
        "fingerprint": ["The site you are looking for could not be found",
                        "If you are an Acquia Cloud customer"],
        "vulnerable": True,
    },
    "Agile CRM": {
        "cname": ["agilecrm.com"],
        "fingerprint": ["Sorry, this page is no longer available"],
        "vulnerable": True,
    },
    "Aha": {
        "cname": ["ideas.aha.io"],
        "fingerprint": ["There is no portal here ... sending you back to Aha!"],
        "vulnerable": True,
    },
    "Anima": {
        "cname": ["animaapp.io"],
        "fingerprint": ["If this is your website and you've just created it"],
        "vulnerable": True,
    },
    "Big Cartel": {
        "cname": ["bigcartel.com"],
        "fingerprint": ["<h1>Oops! We couldn&#8217;t find that page.</h1>"],
        "vulnerable": True,
    },
    "Campaign Monitor": {
        "cname": ["createsend.com"],
        "fingerprint": ["Trying to access your account?", "Double check the URL"],
        "vulnerable": True,
    },
    "Cargo Collective": {
        "cname": ["cargocollective.com"],
        "fingerprint": ["404 &mdash; File not found"],
        "vulnerable": True,
    },
    "Desk": {
        "cname": ["desk.com"],
        "fingerprint": ["Please try again or try Desk.com free for 14 days"],
        "vulnerable": True,
    },
    "Gemfury": {
        "cname": ["furyns.com"],
        "fingerprint": ["404: This page could not be found"],
        "vulnerable": True,
    },
    "GetResponse": {
        "cname": ["gr8.com"],
        "fingerprint": ["With GetResponse Landing Pages, lead generation has never been easier"],
        "vulnerable": True,
    },
    "HatenaBlog": {
        "cname": ["hatenablog.com"],
        "fingerprint": ["404 Blog is not found"],
        "vulnerable": True,
    },
    "Help Juice": {
        "cname": ["helpjuice.com"],
        "fingerprint": ["We could not find what you're looking for"],
        "vulnerable": True,
    },
    "Help Scout": {
        "cname": ["helpscoutdocs.com"],
        "fingerprint": ["No settings were found for this company"],
        "vulnerable": True,
    },
    "Intercom": {
        "cname": ["custom.intercom.help"],
        "fingerprint": ["Uh oh. That page doesn't exist", "This page is reserved for artistic dogs"],
        "vulnerable": True,
    },
    "JetBrains": {
        "cname": ["myjetbrains.com"],
        "fingerprint": ["is not a registered InCloud YouTrack"],
        "vulnerable": True,
    },
    "LaunchRock": {
        "cname": ["launchrock.com"],
        "fingerprint": ["It looks like you may have taken a wrong turn somewhere"],
        "vulnerable": True,
    },
    "Mashery": {
        "cname": ["mashery.com"],
        "fingerprint": ["Unrecognized domain"],
        "vulnerable": True,
    },
    "Netlify": {
        "cname": ["netlify.app", "netlify.com"],
        "fingerprint": ["Not Found - Request ID"],
        "vulnerable": False,  # edge case; verify manually
    },
    "Ngrok": {
        "cname": ["ngrok.io"],
        "fingerprint": ["ngrok.io not found", "Tunnel *.ngrok.io not found"],
        "vulnerable": True,
    },
    "Proposify": {
        "cname": ["proposify.biz"],
        "fingerprint": ["If you need immediate assistance, please contact"],
        "vulnerable": True,
    },
    "Readme.io": {
        "cname": ["readme.io"],
        "fingerprint": ["Project doesnt exist... yet!"],
        "vulnerable": True,
    },
    "Strikingly": {
        "cname": ["s.strikinglydns.com", "strikingly.com"],
        "fingerprint": ["But if you're looking to build your own website"],
        "vulnerable": True,
    },
    "Teamwork": {
        "cname": ["teamwork.com"],
        "fingerprint": ["Oops - We didn't find your site"],
        "vulnerable": True,
    },
    "Tilda": {
        "cname": ["tilda.ws"],
        "fingerprint": ["Please renew your subscription"],
        "vulnerable": False,
    },
    "UserVoice": {
        "cname": ["uservoice.com"],
        "fingerprint": ["This UserVoice subdomain is currently available"],
        "vulnerable": True,
    },
    "Vend": {
        "cname": ["vendhq.com"],
        "fingerprint": ["Looks like you've traveled too far into cyberspace"],
        "vulnerable": True,
    },
    "Webflow": {
        "cname": ["proxy.webflow.com", "proxy-ssl.webflow.com"],
        "fingerprint": ["The page you are looking for doesn't exist or has been moved"],
        "vulnerable": False,  # generic text; confirm CNAME + manual
    },
    "Wishpond": {
        "cname": ["wishpond.com"],
        "fingerprint": ["https://www.wishpond.com/404?"],
        "vulnerable": True,
    },
    "Wufoo": {
        "cname": ["wufoo.com"],
        "fingerprint": ["Profile not found"],
        "vulnerable": True,
    },
    "Worksites": {
        "cname": ["worksites.net"],
        "fingerprint": ["Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist"],
        "vulnerable": True,
    },
    "Kinsta": {
        "cname": ["kinsta.cloud"],
        "fingerprint": ["No Site For Domain"],
        "vulnerable": True,
    },
    "Uptimerobot": {
        "cname": ["stats.uptimerobot.com"],
        "fingerprint": ["page not found", "This public status page"],
        "vulnerable": False,
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
