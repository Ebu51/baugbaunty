"""Import program scope from HackerOne / Bugcrowd exports into a config.

Getting scope right by hand is error-prone, and a mistake here means touching
assets you aren't allowed to. This importer parses the scope files those
platforms produce (or their APIs return) and emits a ready-to-use config with
``scope.include`` / ``scope.exclude`` populated and everything out-of-scope
correctly excluded.

Supported inputs (auto-detected, but ``platform`` can force one):
  * HackerOne structured_scopes JSON (API or export)
  * Bugcrowd scope JSON (several shapes)
  * a plain text list: one asset per line, a leading ``!`` marks out-of-scope.

Only web-style assets (hosts, wildcards, URLs) are imported; asset types the
toolkit can't act on (source-repo, mobile binaries, hardware) are skipped and
reported, so you never get a false sense of coverage.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Asset types we can actually scan over HTTP/DNS.
_WEB_TYPES = {"url", "wildcard", "website", "api", "ip_address", "cidr", "domain"}


@dataclass
class ImportResult:
    name: str = "imported-program"
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # (identifier:type) we ignored

    def dedupe(self) -> "ImportResult":
        self.include = sorted(dict.fromkeys(self.include))
        self.exclude = sorted(dict.fromkeys(self.exclude))
        return self


def _normalize_asset(identifier: str) -> str | None:
    """Reduce a scope identifier to a host/wildcard/CIDR rule, or None to skip."""

    identifier = (identifier or "").strip()
    if not identifier:
        return None
    if identifier.startswith("*."):
        return identifier.lower()
    if "://" in identifier:
        host = urlparse(identifier).hostname
        return host.lower() if host else None
    # Keep CIDRs and bare hosts as-is; drop obvious non-hosts (paths, spaces).
    token = identifier.split("/")[0] if "/" not in identifier or _is_cidr(identifier) else identifier
    if " " in token or "@" in token:
        return None
    return identifier.lower() if _is_cidr(identifier) else token.lower()


def _is_cidr(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_network(value, strict=False)
        return "/" in value
    except ValueError:
        return False


def parse_hackerone(data: dict | list) -> ImportResult:
    res = ImportResult()
    rows = data.get("data", data) if isinstance(data, dict) else data
    for row in rows or []:
        attrs = row.get("attributes", row) if isinstance(row, dict) else {}
        ident = attrs.get("asset_identifier") or attrs.get("asset") or ""
        atype = str(attrs.get("asset_type", "")).lower()
        eligible = attrs.get("eligible_for_submission", True)
        norm = _normalize_asset(ident)
        if norm is None or (atype and atype not in _WEB_TYPES):
            if ident:
                res.skipped.append(f"{ident}:{atype or 'unknown'}")
            continue
        (res.include if eligible else res.exclude).append(norm)
    return res.dedupe()


def parse_bugcrowd(data: dict | list) -> ImportResult:
    res = ImportResult()

    def harvest(items, bucket: list[str]) -> None:
        for it in items or []:
            if isinstance(it, str):
                ident, atype = it, ""
            else:
                ident = it.get("target") or it.get("name") or it.get("uri") or ""
                atype = str(it.get("type") or it.get("category") or "").lower()
            norm = _normalize_asset(ident)
            if norm is None or (atype and atype not in _WEB_TYPES and atype not in ("", "other")):
                if ident:
                    res.skipped.append(f"{ident}:{atype or 'unknown'}")
                continue
            bucket.append(norm)

    if isinstance(data, dict):
        targets = data.get("targets", data)
        harvest(targets.get("in_scope") if isinstance(targets, dict) else None, res.include)
        harvest(targets.get("out_of_scope") if isinstance(targets, dict) else None, res.exclude)
        # Flat {"in_scope":[...], "out_of_scope":[...]} at top level.
        if not res.include:
            harvest(data.get("in_scope"), res.include)
            harvest(data.get("out_of_scope"), res.exclude)
    elif isinstance(data, list):
        harvest(data, res.include)
    return res.dedupe()


def parse_list(text: str) -> ImportResult:
    res = ImportResult()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        exclude = line.startswith("!")
        norm = _normalize_asset(line[1:] if exclude else line)
        if norm is None:
            continue
        (res.exclude if exclude else res.include).append(norm)
    return res.dedupe()


def import_scope(text: str, platform: str = "auto") -> ImportResult:
    platform = (platform or "auto").lower()
    data: object = None
    if platform in ("auto", "hackerone", "bugcrowd"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None

    if platform == "hackerone":
        return parse_hackerone(data or {})
    if platform == "bugcrowd":
        return parse_bugcrowd(data or {})
    if platform == "list" or data is None:
        return parse_list(text)

    # auto: sniff the JSON shape.
    if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
        return parse_hackerone(data)
    if isinstance(data, dict) and ("targets" in data or "in_scope" in data):
        return parse_bugcrowd(data)
    if isinstance(data, list):
        # Could be either; HackerOne rows have attributes/asset_identifier.
        if data and isinstance(data[0], dict) and (
            "asset_identifier" in data[0] or "attributes" in data[0]
        ):
            return parse_hackerone(data)
        return parse_bugcrowd(data)
    return parse_list(text)


def to_config_dict(result: ImportResult, name: str | None = None) -> dict:
    from ..core.config import DEFAULTS

    cfg = json.loads(json.dumps(DEFAULTS))
    cfg["program"]["name"] = name or result.name
    cfg["scope"]["include"] = result.include
    cfg["scope"]["exclude"] = result.exclude
    return cfg
