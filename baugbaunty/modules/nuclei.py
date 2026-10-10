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
        templates = ctx.config.get("modules.nuclei.templates", "")
        tags = ctx.config.get("modules.nuclei.tags", []) or []
        exclude = ctx.config.get("modules.nuclei.exclude_severity", []) or []
        extra = ctx.config.get("modules.nuclei.extra_args", []) or []

        if ctx.config.get("modules.nuclei.update", False):
            ctx.log.info("[nuclei] updating templates...")
            res = external.nuclei_update_templates()
            ctx.log.debug(f"[nuclei] update ok={res.ok}")

        ctx.log.info(
            f"[nuclei] scanning {len(urls)} services "
            f"(severity={severities}{', tags=' + ','.join(tags) if tags else ''}"
            f"{', custom templates' if templates else ''})"
        )

        count = 0
        by_sev: dict[str, int] = {}
        for row in external.nuclei(
            urls, severities, rate_limit=rate, templates=templates,
            tags=tags, exclude_severities=exclude, extra_args=extra,
        ):
            info = row.get("info", {})
            target = row.get("matched-at") or row.get("host") or row.get("url", "")
            if target and not ctx.scope.is_allowed(target):
                continue
            name = info.get("name") or row.get("template-id", "nuclei finding")
            severity = _SEV_MAP.get(str(info.get("severity", "info")).lower(), "info")
            classification = info.get("classification", {}) or {}
            ctx.store.add_finding(
                target=target or "unknown",
                module="nuclei",
                name=name,
                severity=severity,
                evidence=row.get("matched-at", ""),
                template=row.get("template-id", ""),
                reference=info.get("reference", []),
                tags=info.get("tags", []),
                cve=classification.get("cve-id", []),
                cwe=classification.get("cwe-id", []),
                cvss=classification.get("cvss-score"),
                matcher=row.get("matcher-name", ""),
                extracted=row.get("extracted-results", []),
            )
            by_sev[severity] = by_sev.get(severity, 0) + 1
            count += 1

        summary = ", ".join(f"{k}:{v}" for k, v in sorted(by_sev.items())) or "none"
        ctx.log.success(f"[nuclei] {count} findings ({summary})")
        return {"findings": count, "by_severity": by_sev}
