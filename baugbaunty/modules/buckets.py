"""Cloud storage bucket enumeration (S3 / GCS / Azure Blob).

Generates candidate bucket/container names from the program's domains and
keywords and checks whether they exist and — more importantly — whether they
are publicly listable. Open buckets owned by a target are a classic, high-impact
bounty finding.

These requests go to the cloud providers (third-party endpoints), not the
target's own servers, so they are passive with respect to the target and are
rate-limited but not subject to the target scope gate. Only names derived from
the in-scope program are generated.
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request

from .base import Context, Module

_SUFFIXES = [
    "", "-dev", "-staging", "-stage", "-prod", "-production", "-test", "-qa",
    "-backup", "-backups", "-bak", "-assets", "-static", "-media", "-images",
    "-img", "-uploads", "-upload", "-data", "-files", "-public", "-private",
    "-internal", "-bucket", "-s3", "-cdn", "-logs", "-log", "-archive",
    "-user-content", "-userdata", "-storage", "-store", "-web", "-www",
]
_PREFIXES = ["", "dev-", "staging-", "prod-", "backup-", "assets-", "static-"]

_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


def _valid(name: str) -> bool:
    return bool(_BUCKET_RE.match(name)) and ".." not in name


class BucketsModule(Module):
    name = "buckets"
    active = False  # queries cloud providers, not the target

    def __init__(self, keywords: list[str] | None = None) -> None:
        self.keywords = keywords

    def _seeds(self, ctx: Context) -> list[str]:
        roots = {r.lstrip("*.") for r in ctx.config.get("scope.include", [])}
        seeds: set[str] = set(self.keywords or [])
        seeds |= set(ctx.config.get("modules.buckets.keywords", []) or [])
        for root in roots:
            label = root.split(".")[0]  # registrable-ish name
            if label:
                seeds.add(label)
                seeds.add(root.replace(".", "-"))
        return sorted(s.lower() for s in seeds if s)

    def _candidates(self, ctx: Context) -> list[str]:
        seeds = self._seeds(ctx)
        cands: list[str] = []
        seen: set[str] = set()
        for seed in seeds:
            for pre in _PREFIXES:
                for suf in _SUFFIXES:
                    name = f"{pre}{seed}{suf}"
                    if _valid(name) and name not in seen:
                        seen.add(name)
                        cands.append(name)
        maxn = int(ctx.config.get("modules.buckets.max_candidates", 200))
        return cands[:maxn]

    def run(self, ctx: Context) -> dict:
        cands = self._candidates(ctx)
        if not cands:
            ctx.log.warn("[buckets] no seed keywords (set scope.include or modules.buckets.keywords)")
            return {"checked": 0, "found": 0, "open": 0}

        providers = ctx.config.get("modules.buckets.providers", ["s3", "gcs", "azure"])
        ctx.log.info(f"[buckets] testing {len(cands)} name(s) across {providers}")
        found = 0
        open_count = 0
        for name in cands:
            if "s3" in providers:
                r = self._check(ctx, name, "S3", f"https://{name}.s3.amazonaws.com/")
                found += r[0]; open_count += r[1]
            if "gcs" in providers:
                r = self._check(ctx, name, "GCS", f"https://storage.googleapis.com/{name}/")
                found += r[0]; open_count += r[1]
            if "azure" in providers:
                r = self._check(ctx, name, "Azure", f"https://{name}.blob.core.windows.net/?comp=list&restype=container")
                found += r[0]; open_count += r[1]

        ctx.log.success(f"[buckets] {found} existing, {open_count} publicly listable")
        return {"checked": len(cands), "found": found, "open": open_count}

    def _check(self, ctx: Context, name: str, provider: str, url: str) -> tuple[int, int]:
        ctx.limiter.acquire(provider.lower())
        status, body = self._fetch(ctx, url)
        if status == 0:
            return (0, 0)
        listable = status == 200 and ("ListBucketResult" in body or "<EnumerationResults" in body
                                      or "<Contents>" in body or "<Blob>" in body)
        exists = status in (200, 403) or (provider == "Azure" and status in (200, 403, 409))
        if not exists:
            return (0, 0)

        ctx.store.add_asset(url, "bucket", source="buckets", in_scope=True)
        if listable:
            ctx.store.add_finding(
                target=url, module="buckets",
                name=f"Publicly listable {provider} bucket: {name}", severity="high",
                evidence=f"{url} returned a public object listing (HTTP {status})",
                provider=provider, bucket=name,
            )
            ctx.log.warn(f"[buckets] OPEN {provider} bucket: {name}")
            return (1, 1)
        ctx.store.add_finding(
            target=url, module="buckets",
            name=f"Existing {provider} bucket (access controlled): {name}", severity="info",
            evidence=f"{url} exists but is not public (HTTP {status})",
            provider=provider, bucket=name,
        )
        return (1, 0)

    def _fetch(self, ctx: Context, url: str) -> tuple[int, str]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ctx.http.user_agent})
            with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as resp:
                return resp.status, resp.read(200_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            try:
                body = e.read(200_000).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return e.code, body
        except (urllib.error.URLError, ssl.SSLError, OSError, ValueError):
            return 0, ""
