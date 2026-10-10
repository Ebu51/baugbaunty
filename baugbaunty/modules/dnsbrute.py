"""Active DNS brute-force and permutation (puredns/gotator-inspired).

Passive sources miss subdomains that were never in a certificate or a public
dataset. This module resolves candidate names built from a wordlist and from
permutations of already-known subdomains, filtering out wildcard-DNS noise, to
surface hosts the passive phase could not.

It only performs DNS resolution (no web traffic to the target), so it is
classified passive; still, it is bounded by a candidate cap and rate-limited.
"""

from __future__ import annotations

import random
import socket
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import Context, Module
from ..core.scope import Verdict

# A small, high-signal built-in list; point modules.dnsbrute.wordlist at a
# bigger one (e.g. SecLists DNS) for real engagements.
_BUILTIN = [
    "www", "mail", "ftp", "dev", "staging", "stage", "test", "qa", "uat",
    "api", "api-dev", "apidev", "admin", "portal", "dashboard", "app", "apps",
    "beta", "demo", "secure", "vpn", "remote", "git", "gitlab", "jenkins",
    "ci", "cd", "jira", "confluence", "wiki", "docs", "support", "help",
    "status", "monitor", "grafana", "kibana", "prometheus", "metrics", "db",
    "database", "mysql", "postgres", "redis", "cache", "cdn", "static",
    "assets", "media", "img", "images", "upload", "uploads", "files", "ftp2",
    "smtp", "imap", "pop", "ns1", "ns2", "dns", "mx", "autodiscover", "owa",
    "exchange", "internal", "intranet", "corp", "office", "vpn2", "gateway",
    "proxy", "auth", "sso", "login", "account", "accounts", "billing", "pay",
    "payment", "payments", "shop", "store", "cart", "checkout", "blog", "news",
    "m", "mobile", "old", "new", "legacy", "backup", "backups", "s3", "cloud",
]
_PERMUTE_WORDS = ["dev", "staging", "test", "prod", "admin", "internal", "api",
                  "old", "new", "beta", "backup", "qa", "uat", "demo"]


def _resolve_ips(host: str) -> set[str]:
    ips: set[str] = set()
    try:
        _, _, addrs = socket.gethostbyname_ex(host)
        ips.update(addrs)
    except (socket.gaierror, socket.herror, OSError, UnicodeError):
        pass
    return ips


class DnsBruteModule(Module):
    name = "dnsbrute"
    active = False  # DNS resolution only, no web traffic to the target

    def __init__(self, domains: list[str] | None = None) -> None:
        self.domains = domains

    def _words(self, ctx: Context) -> list[str]:
        import pathlib

        wl = ctx.config.get("modules.dnsbrute.wordlist", "")
        if wl and pathlib.Path(wl).exists():
            words = [l.strip() for l in pathlib.Path(wl).read_text(
                encoding="utf-8", errors="ignore").splitlines()
                if l.strip() and not l.startswith("#")]
            return words
        return list(_BUILTIN)

    def _wildcard_ips(self, ctx: Context, domain: str) -> set[str]:
        seen: list[set[str]] = []
        for _ in range(3):
            label = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
            ips = _resolve_ips(f"{label}.{domain}")
            if ips:
                seen.append(ips)
        return set.intersection(*seen) if len(seen) > 1 else (seen[0] if seen else set())

    def run(self, ctx: Context) -> dict:
        domains = self.domains or [r.lstrip("*.") for r in ctx.config.get("scope.include", [])]
        words = self._words(ctx)
        max_cand = int(ctx.config.get("modules.dnsbrute.max_candidates", 5000))
        do_permute = bool(ctx.config.get("modules.dnsbrute.permutations", True))
        workers = min(int(ctx.config.get("limits.concurrency", 20)), 50)

        # Build candidate set.
        candidates: set[str] = set()
        for domain in domains:
            domain = domain.lstrip("*.")
            for w in words:
                candidates.add(f"{w}.{domain}")
            if do_permute:
                candidates |= self._permutations(ctx, domain)

        candidates = set(list(candidates)[:max_cand])
        # Per-apex wildcard IPs, to drop catch-all answers.
        wildcard: dict[str, set[str]] = {}
        for domain in domains:
            wildcard[domain.lstrip("*.")] = self._wildcard_ips(ctx, domain.lstrip("*."))

        ctx.log.info(f"[dnsbrute] resolving {len(candidates)} candidate(s)")
        found = 0
        in_scope = 0

        def work(host: str) -> tuple[str, set[str]]:
            ctx.limiter.acquire(host)
            return host, _resolve_ips(host)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(work, h) for h in candidates]
            for fut in as_completed(futs):
                host, ips = fut.result()
                if not ips:
                    continue
                apex = next((d for d in wildcard if host.endswith(d)), "")
                if wildcard.get(apex) and ips.issubset(wildcard[apex]):
                    continue  # wildcard catch-all, not a real host
                found += 1
                allowed = ctx.scope.check(host).verdict is Verdict.IN_SCOPE
                ctx.store.add_asset(host, "subdomain", source="dnsbrute", in_scope=allowed)
                ctx.store.update_asset_data(host, "subdomain", resolved=True, ips=sorted(ips))
                if allowed:
                    in_scope += 1

        ctx.log.success(f"[dnsbrute] {found} resolved ({in_scope} in scope)")
        return {"candidates": len(candidates), "found": found, "in_scope": in_scope}

    def _permutations(self, ctx: Context, domain: str) -> set[str]:
        known = [a["value"] for a in ctx.store.assets()
                 if a["kind"] == "subdomain" and a["value"].endswith(domain)]
        out: set[str] = set()
        for sub in known:
            label = sub[: -len(domain)].rstrip(".")
            if not label or "." in label:
                continue
            for w in _PERMUTE_WORDS:
                out.add(f"{w}-{label}.{domain}")
                out.add(f"{label}-{w}.{domain}")
                out.add(f"{w}.{label}.{domain}")
        return out
