"""Correlate detected software versions with known CVEs.

This phase sends NO traffic — it analyses the version banners already collected
by ``probe`` (and tech labels carrying a version) and matches them against a
curated, offline ruleset of well-known, version-specific vulnerabilities. It is
deliberately conservative: a match is a *lead* that the disclosed version is
known-vulnerable, to be confirmed against the live service, not a proof of
exploitability.

Extend the ruleset with ``modules.cvecheck.extra`` (a JSON file). For live CVE
enrichment, feed the same services to ``nuclei``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .base import Context, Module

_VER_TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9+_\-]*?)[/ ]v?(\d+(?:\.\d+){1,3})")


def _ver(s: str) -> tuple[int, ...]:
    out = []
    for part in s.split("."):
        num = re.match(r"\d+", part)
        out.append(int(num.group()) if num else 0)
    return tuple(out)


def _between(v: tuple[int, ...], lo: tuple[int, ...], hi: tuple[int, ...]) -> bool:
    return lo <= v <= hi


# (product substring, predicate(version_tuple)->bool, CVE, severity, description)
_RULES: list[tuple[str, object, str, str, str]] = [
    ("apache", lambda v: v == _ver("2.4.49"), "CVE-2021-41773", "critical",
     "Apache httpd 2.4.49 path traversal / RCE"),
    ("apache", lambda v: v == _ver("2.4.50"), "CVE-2021-42013", "critical",
     "Apache httpd 2.4.50 path traversal / RCE (incomplete fix)"),
    ("apache", lambda v: v < _ver("2.4.53") and v >= _ver("2.4.0"), "CVE-2022-22720", "high",
     "Apache httpd < 2.4.53 HTTP request smuggling"),
    ("nginx", lambda v: _between(v, _ver("0.6.18"), _ver("1.20.0")), "CVE-2021-23017", "high",
     "nginx resolver off-by-one heap write (<= 1.20.0)"),
    ("nginx", lambda v: _between(v, _ver("1.3.9"), _ver("1.4.0")), "CVE-2013-2028", "critical",
     "nginx 1.3.9-1.4.0 chunked stack buffer overflow"),
    ("openssh", lambda v: v < _ver("9.3.2") and v >= _ver("9.0"), "CVE-2023-38408", "high",
     "OpenSSH ssh-agent PKCS#11 RCE (< 9.3p2)"),
    ("php", lambda v: v < _ver("8.1"), "EOL", "low",
     "PHP version is end-of-life / unsupported"),
    ("jquery", lambda v: v < _ver("3.5.0"), "CVE-2020-11022", "medium",
     "jQuery < 3.5.0 cross-site scripting"),
    ("bootstrap", lambda v: v < _ver("3.4.1"), "CVE-2019-8331", "medium",
     "Bootstrap < 3.4.1 XSS in tooltip/popover"),
    ("tomcat", lambda v: _between(v, _ver("9.0.0"), _ver("9.0.30")), "CVE-2020-1938", "high",
     "Apache Tomcat AJP Ghostcat file read/inclusion"),
    ("iis", lambda v: v <= _ver("7.5"), "LEGACY", "low",
     "Legacy IIS version disclosed (<= 7.5)"),
]


class CveCheckModule(Module):
    name = "cvecheck"
    active = False  # analysis of already-collected data; no new traffic

    def _load_extra(self, ctx: Context) -> list[tuple]:
        extra = ctx.config.get("modules.cvecheck.extra", "")
        rules: list[tuple] = []
        if extra and Path(extra).exists():
            try:
                for r in json.loads(Path(extra).read_text(encoding="utf-8")):
                    # {"product","max_exclusive"|"equals","cve","severity","desc"}
                    prod = r["product"].lower()
                    if "equals" in r:
                        pred = (lambda vv: (lambda v: v == vv))(_ver(r["equals"]))
                    else:
                        pred = (lambda vv: (lambda v: v < vv))(_ver(r.get("max_exclusive", "0")))
                    rules.append((prod, pred, r.get("cve", ""), r.get("severity", "info"), r.get("desc", "")))
            except (json.JSONDecodeError, KeyError, OSError) as e:
                ctx.log.warn(f"[cvecheck] could not load extra rules: {e}")
        return rules

    def run(self, ctx: Context) -> dict:
        services = ctx.store.services()
        if not services:
            ctx.log.warn("[cvecheck] no services; run probe first")
            return {"services": 0, "matches": 0}

        rules = _RULES + self._load_extra(ctx)
        ctx.log.info(f"[cvecheck] correlating {len(services)} service(s) against {len(rules)} rules")
        matches = 0

        for svc in services:
            url = svc["url"]
            if not ctx.scope.is_allowed(url):
                continue
            products = self._products(svc)
            for name, version, raw in products:
                # Version disclosure is itself a (low-noise) info finding.
                ctx.store.add_finding(
                    target=url, module="cvecheck",
                    name=f"Software version disclosed: {raw}",
                    severity="info",
                    evidence=f"{url} reveals {raw}",
                )
                for prod, pred, cve, sev, desc in rules:
                    if prod in name and _safe(pred, version):
                        matches += 1
                        ctx.store.add_finding(
                            target=url, module="cvecheck",
                            name=f"{desc} [{cve}]",
                            severity=sev,
                            evidence=f"{url} runs {raw}; matches {cve} ({desc})",
                            cve=cve, product=name, version=raw,
                        )
                        ctx.log.warn(f"[cvecheck] {url}: {cve} ({raw})")

        ctx.log.success(f"[cvecheck] {matches} CVE lead(s)")
        return {"services": len(services), "matches": matches}

    def _products(self, svc: dict) -> list[tuple[str, tuple[int, ...], str]]:
        blobs = [svc.get("server") or ""]
        tech = svc.get("tech")
        if isinstance(tech, str):
            try:
                tech = json.loads(tech)
            except json.JSONDecodeError:
                tech = []
        blobs.extend(tech or [])
        out: list[tuple[str, tuple[int, ...], str]] = []
        seen: set[str] = set()
        for blob in blobs:
            for m in _VER_TOKEN.finditer(str(blob)):
                name, ver = m.group(1).lower(), m.group(2)
                raw = f"{m.group(1)}/{ver}"
                if raw in seen:
                    continue
                seen.add(raw)
                out.append((name, _ver(ver), raw))
        return out


def _safe(pred, version: tuple[int, ...]) -> bool:
    try:
        return bool(pred(version))
    except Exception:
        return False
