"""Template-based vulnerability scanning via nuclei (optional, active).

nuclei runs community/curated templates against in-scope live services. We
pass only in-scope URLs, cap the request rate, and store each result as a
finding mapped to a severity. This module is a no-op if nuclei is not
installed — there is no built-in equivalent, by design: template scanning is
best left to the maintained nuclei template corpus.
"""

from __future__ import annotations

from .base import Context, Module
from ..integrations import external

_SEV_MAP = {
    "info": "info", "low": "low", "medium": "medium",
    "high": "high", "critical": "critical", "unknown": "info",
}


class NucleiModule(Module):
    name = "nuclei"
    active = True

    def __init__(self, targets: list[str] | None = None) -> None:
        self.targets = targets

    def run(self, ctx: Context) -> dict:
        if not external.have("nuclei"):
            ctx.log.warn("[nuclei] not installed — skipping (install nuclei to enable)")
            return {"skipped": True, "findings": 0}

        urls = self.targets or [
            s["url"] for s in ctx.store.services() if ctx.scope.is_allowed(s["url"])
        ]
        urls = [u for u in urls if ctx.scope.is_allowed(u)]
        if not urls:
            ctx.log.warn("[nuclei] no in-scope services; run probe first")
            return {"findings": 0}

        severities = ctx.config.get(
            "modules.nuclei.severity", ["low", "medium", "high", "critical"]
        )
        rate = int(ctx.config.get("modules.nuclei.rate_limit", 150))
        ctx.log.info(f"[nuclei] scanning {len(urls)} services (severity={severities})")

        count = 0
        for row in external.nuclei(urls, severities, rate_limit=rate):
            info = row.get("info", {})
            target = row.get("matched-at") or row.get("host") or row.get("url", "")
            if target and not ctx.scope.is_allowed(target):
                continue
            name = info.get("name") or row.get("template-id", "nuclei finding")
            severity = _SEV_MAP.get(str(info.get("severity", "info")).lower(), "info")
            ctx.store.add_finding(
                target=target or "unknown",
                module="nuclei",
                name=name,
                severity=severity,
                evidence=row.get("matched-at", ""),
                template=row.get("template-id", ""),
                reference=info.get("reference", []),
            )
            count += 1

        ctx.log.success(f"[nuclei] {count} findings")
        return {"findings": count}
