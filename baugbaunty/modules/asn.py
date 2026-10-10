"""ASN / organisation → IP range expansion (asnmap/Amass-intel-inspired).

Programs often own whole netblocks. Given an organisation name, this queries the
public BGPView API to find the ASNs registered to it and their announced IPv4
prefixes, so you can discover IP ranges that belong to the target.

Discovered CIDRs are reported as informational findings only — they are NOT
auto-added to scope (default-deny): confirm ownership and the program rules,
then add the ones you're allowed to test to ``scope.include`` yourself.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .base import Context, Module

_API = "https://api.bgpview.io"


class AsnModule(Module):
    name = "asn"
    active = False  # queries a third-party BGP dataset, not the target

    def __init__(self, keywords: list[str] | None = None) -> None:
        self.keywords = keywords

    def _keywords(self, ctx: Context) -> list[str]:
        kw = list(self.keywords or [])
        kw += list(ctx.config.get("modules.asn.org_keywords", []) or [])
        if not kw:
            # Derive a guess from the registrable label of each root domain.
            for r in ctx.config.get("scope.include", []):
                label = r.lstrip("*.").split(".")[0]
                if label:
                    kw.append(label)
        return sorted({k for k in kw if k})

    def run(self, ctx: Context) -> dict:
        keywords = self._keywords(ctx)
        if not keywords:
            ctx.log.warn("[asn] no org keywords (set modules.asn.org_keywords)")
            return {"asns": 0, "prefixes": 0}

        max_pref = int(ctx.config.get("modules.asn.max_prefixes", 200))
        asns_seen: set[int] = set()
        prefixes = 0

        for kw in keywords:
            data = self._get(ctx, f"{_API}/search?query_term={urllib.parse.quote(kw)}")
            if not data:
                continue
            for a in (data.get("data", {}) or {}).get("asns", []) or []:
                asn = a.get("asn")
                if not asn or asn in asns_seen:
                    continue
                asns_seen.add(asn)
                name = a.get("name") or a.get("description") or ""
                prefixes += self._asn_prefixes(ctx, asn, name, max_pref - prefixes)
                if prefixes >= max_pref:
                    break

        ctx.log.success(f"[asn] {len(asns_seen)} ASN(s), {prefixes} prefix(es) "
                        f"(review and add to scope manually)")
        return {"asns": len(asns_seen), "prefixes": prefixes}

    def _asn_prefixes(self, ctx: Context, asn: int, name: str, budget: int) -> int:
        if budget <= 0:
            return 0
        data = self._get(ctx, f"{_API}/asn/{asn}/prefixes")
        if not data:
            return 0
        n = 0
        for p in (data.get("data", {}) or {}).get("ipv4_prefixes", []) or []:
            cidr = p.get("prefix")
            if not cidr:
                continue
            ctx.store.add_asset(cidr, "cidr", source="asn", in_scope=ctx.scope.is_allowed(cidr))
            ctx.store.add_finding(
                target=cidr, module="asn",
                name=f"IP range via AS{asn} ({name})", severity="info",
                evidence=f"{cidr} announced by AS{asn} ({name}); confirm ownership "
                         f"and program scope before testing",
                asn=asn, org=name,
            )
            n += 1
            if n >= budget:
                break
        return n

    def _get(self, ctx: Context, url: str) -> dict | None:
        ctx.limiter.acquire("api.bgpview.io")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ctx.http.user_agent})
            with urllib.request.urlopen(req, timeout=20, context=ssl.create_default_context()) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except (urllib.error.URLError, ssl.SSLError, OSError, json.JSONDecodeError) as e:
            ctx.log.warn(f"[asn] query failed: {e}")
            return None
