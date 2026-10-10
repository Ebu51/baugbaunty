"""Render engagement results to JSON, Markdown and a self-contained HTML page."""

from __future__ import annotations

import html
import json
import time
from pathlib import Path

from ..core.config import Config
from ..core.store import Store

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {
    "critical": "#b00020", "high": "#d9534f", "medium": "#f0ad4e",
    "low": "#5bc0de", "info": "#777",
}


def _summary(store: Store) -> dict:
    findings = store.findings()
    by_sev = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        by_sev[f.get("severity", "info")] = by_sev.get(f.get("severity", "info"), 0) + 1
    return {
        "counts": store.counts(),
        "by_severity": by_sev,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def generate_reports(store: Store, config: Config, out_dir: str | Path) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    formats = config.get("output.formats", ["json", "markdown"])
    program = config.get("program.name", "engagement")
    written: list[Path] = []

    data = {
        "program": config.get("program", {}),
        "scope": config.get("scope", {}),
        "summary": _summary(store),
        "assets": store.assets(),
        "services": store.services(),
        "findings": store.findings(),
    }

    if "json" in formats:
        p = out / f"{program}-report.json"
        p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        written.append(p)

    if "markdown" in formats:
        p = out / f"{program}-report.md"
        p.write_text(_render_markdown(data), encoding="utf-8")
        written.append(p)

    if "html" in formats:
        p = out / f"{program}-report.html"
        p.write_text(_render_html(data), encoding="utf-8")
        written.append(p)

    return written


def _render_markdown(data: dict) -> str:
    s = data["summary"]
    lines = [
        f"# Bug Bounty Report — {data['program'].get('name', 'engagement')}",
        "",
        f"_Generated: {s['generated_at']}_",
        "",
        "> For authorized testing only. Handle all data per the program's "
        "disclosure policy.",
        "",
        "## Summary",
        "",
        f"- Assets: **{s['counts']['assets']}** "
        f"({s['counts']['in_scope_assets']} in scope)",
        f"- Live services: **{s['counts']['services']}**",
        f"- Findings: **{s['counts']['findings']}**",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in _SEV_ORDER:
        lines.append(f"| {sev.capitalize()} | {s['by_severity'].get(sev, 0)} |")
    lines += ["", "## Findings", ""]

    findings = data["findings"]
    if not findings:
        lines.append("_No findings recorded._")
    for f in findings:
        lines += [
            f"### [{f.get('severity', 'info').upper()}] {f.get('name')}",
            "",
            f"- **Target:** `{f.get('target')}`",
            f"- **Module:** {f.get('module')}",
            f"- **Evidence:** {f.get('evidence', '') or '—'}",
            "",
        ]

    lines += ["## Live services", "", "| URL | Status | Server | Tech |", "|---|---|---|---|"]
    for svc in data["services"]:
        tech = svc.get("tech", "[]")
        try:
            tech = ", ".join(json.loads(tech)) if isinstance(tech, str) else ", ".join(tech)
        except Exception:
            tech = ""
        lines.append(
            f"| {svc.get('url')} | {svc.get('status', '')} | "
            f"{svc.get('server', '') or ''} | {tech} |"
        )

    return "\n".join(lines) + "\n"


def _render_html(data: dict) -> str:
    s = data["summary"]
    sev_cards = "".join(
        f'<div class="card" style="border-top:4px solid {_SEV_COLOR[sev]}">'
        f'<div class="n">{s["by_severity"].get(sev, 0)}</div>'
        f'<div class="l">{sev}</div></div>'
        for sev in _SEV_ORDER
    )
    rows = ""
    for f in data["findings"]:
        sev = f.get("severity", "info")
        rows += (
            f'<tr><td><span class="badge" style="background:{_SEV_COLOR.get(sev,"#777")}">'
            f"{html.escape(sev)}</span></td>"
            f"<td>{html.escape(str(f.get('name','')))}</td>"
            f"<td><code>{html.escape(str(f.get('target','')))}</code></td>"
            f"<td>{html.escape(str(f.get('module','')))}</td>"
            f"<td>{html.escape(str(f.get('evidence','') or ''))}</td></tr>"
        )
    prog = html.escape(str(data["program"].get("name", "engagement")))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bug Bounty Report — {prog}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; margin: 0; padding: 2rem;
         background: #0f1115; color: #e6e6e6; }}
  h1 {{ margin: 0 0 .25rem; }}
  .muted {{ color: #9aa; }}
  .cards {{ display: flex; gap: .75rem; flex-wrap: wrap; margin: 1.5rem 0; }}
  .card {{ background: #1a1d24; border-radius: 8px; padding: 1rem 1.5rem;
          min-width: 90px; text-align: center; }}
  .card .n {{ font-size: 1.8rem; font-weight: 700; }}
  .card .l {{ text-transform: capitalize; color: #9aa; font-size: .85rem; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
  th, td {{ text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #262a33;
           vertical-align: top; font-size: .9rem; }}
  th {{ color: #9aa; font-weight: 600; }}
  code {{ background: #11141a; padding: .1rem .3rem; border-radius: 4px; }}
  .badge {{ color: #fff; padding: .1rem .5rem; border-radius: 999px; font-size: .75rem;
           text-transform: uppercase; }}
  .note {{ background: #1a1d24; border-left: 4px solid #f0ad4e; padding: .75rem 1rem;
          border-radius: 4px; margin: 1rem 0; }}
</style></head><body>
<h1>Bug Bounty Report — {prog}</h1>
<div class="muted">Generated {html.escape(s['generated_at'])}</div>
<div class="note">For authorized testing only. Handle all findings according to
the program's responsible-disclosure policy.</div>
<div class="cards">
  <div class="card"><div class="n">{s['counts']['assets']}</div><div class="l">assets</div></div>
  <div class="card"><div class="n">{s['counts']['services']}</div><div class="l">services</div></div>
  <div class="card"><div class="n">{s['counts']['findings']}</div><div class="l">findings</div></div>
  {sev_cards}
</div>
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Name</th><th>Target</th><th>Module</th><th>Evidence</th></tr></thead>
<tbody>{rows or '<tr><td colspan="5" class="muted">No findings recorded.</td></tr>'}</tbody></table>
</body></html>
"""
