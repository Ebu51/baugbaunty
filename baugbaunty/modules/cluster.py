"""Cluster live services by response similarity (aquatone/gowitness-inspired).

At scale you get hundreds of live services, many of them identical (parked
domains, the same app on many hosts, default installs). Grouping them by a
response signature — status, title, rounded size and detected tech — lets you
skip the duplicates and focus on the distinct ones. Pure analysis of data
already collected; it sends no traffic.
"""

from __future__ import annotations

import json
from collections import defaultdict

from .base import Context, Module


def _sig(svc: dict) -> tuple:
    tech = svc.get("tech")
    if isinstance(tech, str):
        try:
            tech = json.loads(tech)
        except json.JSONDecodeError:
            tech = []
    clen = svc.get("content_length") or 0
    try:
        bucket = int(clen) // 512
    except (TypeError, ValueError):
        bucket = 0
    return (svc.get("status"), (svc.get("title") or "").strip()[:80],
            bucket, tuple(sorted(tech or [])))


class ClusterModule(Module):
    name = "cluster"
    active = False  # analysis only

    def run(self, ctx: Context) -> dict:
        services = [s for s in ctx.store.services() if ctx.scope.is_allowed(s["url"])]
        if not services:
            ctx.log.warn("[cluster] no services; run probe first")
            return {"services": 0, "clusters": 0}

        groups: dict[tuple, list[str]] = defaultdict(list)
        for s in services:
            groups[_sig(s)].append(s["url"])

        dupes = 0
        for sig, urls in groups.items():
            if len(urls) < 2:
                continue
            dupes += 1
            status, title, bucket, tech = sig
            ctx.store.add_finding(
                target=urls[0], module="cluster",
                name=f"{len(urls)} near-identical services (HTTP {status})",
                severity="info",
                evidence=(
                    f"{len(urls)} services share a signature "
                    f"(status={status}, title='{title}', ~{bucket*512}B, tech={list(tech)}): "
                    f"{', '.join(urls[:8])}" + (" ..." if len(urls) > 8 else "")
                ),
                members=urls, count=len(urls),
            )

        distinct = len(groups)
        ctx.log.success(
            f"[cluster] {len(services)} services -> {distinct} distinct group(s), "
            f"{dupes} with duplicates"
        )
        return {"services": len(services), "clusters": distinct, "duplicate_groups": dupes}
