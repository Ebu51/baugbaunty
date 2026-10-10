"""Configuration loading and the runtime context shared across modules.

Config can be YAML (if PyYAML is installed) or JSON. A small, dependency-free
JSON path is always available so the toolkit runs out of the box.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

try:  # optional dependency
    import yaml  # type: ignore

    _HAVE_YAML = True
except Exception:  # pragma: no cover - env dependent
    _HAVE_YAML = False


DEFAULTS: dict[str, Any] = {
    "program": {
        "name": "unnamed-program",
        "platform": "",  # hackerone | bugcrowd | intigriti | private
        "authorized": False,  # must be flipped to True to run active modules
    },
    "scope": {
        "include": [],  # e.g. ["*.example.com", "api.example.com"]
        "exclude": [],  # e.g. ["blog.example.com", "*.staging.example.com"]
    },
    "limits": {
        "global_rps": 10.0,
        "per_host_rps": 5.0,
        "concurrency": 20,
        "timeout": 10.0,
        "max_retries": 2,
    },
    "http": {
        # A transparent, honest UA so target teams can identify your traffic.
        "user_agent": "baugbaunty/0.1 (authorized-security-testing)",
        "verify_tls": True,
        "follow_redirects": True,
        "extra_headers": {},
        "proxy": "",  # e.g. http://127.0.0.1:8080 to route through Burp/mitmproxy
    },
    # Credentials for authenticated scanning (test as a logged-in user).
    "auth": {
        "bearer": "",   # -> Authorization: Bearer <token>
        "cookie": "",   # -> Cookie: <value>
        "headers": {},  # arbitrary extra headers (e.g. {"X-Api-Key": "..."})
    },
    "modules": {
        "subdomains": {
            "sources": ["crtsh", "hackertarget", "rapiddns", "anubis", "otx"],
            "use_external": True,
        },
        "dns": {
            "use_external": True,
            "detect_wildcard": True,
            "filter_wildcard": True,
            "wildcard_test_count": 3,
        },
        "dnsbrute": {"wordlist": "", "max_candidates": 5000, "permutations": True},
        "asn": {"org_keywords": [], "max_prefixes": 200},
        "secheaders": {},
        "cluster": {},
        "takeover": {"extra": ""},  # path to a JSON file of extra fingerprints
        "wayback": {"sources": ["wayback", "otx"], "max_urls": 5000},
        "jsintel": {"max_files": 200, "scan_secrets": True},
        "seeds": {"favicon": True},  # robots/sitemap/favicon seeding
        "waf": {},
        "graphql": {},
        "ratecal": {"max_requests": 15, "concurrency": 10, "auto_tune": False},
        "openapi": {},
        "crawl": {"max_pages": 200, "max_depth": 3, "headless": False},
        "urltriage": {},
        "buckets": {"keywords": [], "providers": ["s3", "gcs", "azure"], "max_candidates": 200},
        "vhost": {"wordlist": "", "max_hosts": 300},
        "params": {"wordlist": "", "chunk_size": 25, "max_params": 500},
        "webchecks": {
            "checks": ["cors", "openredirect", "reflection", "crlf", "hostheader", "ssrf"],
            "max_targets": 300,
            "ssrf_canary": "",  # your OOB collaborator/interactsh domain; blank disables SSRF
        },
        "cvecheck": {"extra": "", "online": False},  # online = OSV enrichment
        "githubdork": {"token": "", "terms": [], "max_results": 20},
        "screenshot": {},
        "content": {
            "wordlist": "",
            "extensions": ["", "/"],
            "permute_ext": [],  # e.g. [".php", ".bak", ".json", ".old", ".zip"]
            "recurse": False,
            "max_depth": 1,
            "status_allow": [200, 204, 301, 302, 307, 401, 403, 405],
        },
        "ports": {"top_ports": 100, "use_external": True},
        "nuclei": {
            "severity": ["low", "medium", "high", "critical"],
            "rate_limit": 150,
            "templates": "",          # path to a custom template dir
            "tags": [],               # e.g. ["cve", "exposure"]
            "exclude_severity": [],
            "update": False,          # run -update-templates before scanning
            "extra_args": [],
        },
    },
    "notifications": {
        "enabled": False,
        "slack_webhook": "",
        "discord_webhook": "",
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "generic_webhook": "",
        "min_severity": "medium",  # only alert on findings at/above this severity
    },
    "output": {
        "dir": "output",
        "formats": ["json", "markdown"],
    },
}


@dataclass
class Config:
    data: dict[str, Any] = field(default_factory=lambda: _deep_copy(DEFAULTS))
    source_path: Path | None = None

    # --- convenience accessors -------------------------------------------
    def get(self, path: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in path.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node

    def set(self, path: str, value: Any) -> None:
        parts = path.split(".")
        node = self.data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value

    @property
    def authorized(self) -> bool:
        return bool(self.get("program.authorized", False))

    def to_json(self) -> str:
        return json.dumps(self.data, indent=2, sort_keys=False)

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None) -> "Config":
        cfg = cls()
        if path is None:
            return cfg
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"config not found: {p}")
        raw = p.read_text(encoding="utf-8")
        loaded = _parse_config_text(raw, p)
        cfg.data = _deep_merge(_deep_copy(DEFAULTS), loaded)
        cfg.source_path = p
        return cfg


def _parse_config_text(raw: str, path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        if not _HAVE_YAML:
            raise RuntimeError(
                f"{path} is YAML but PyYAML is not installed. "
                "Install it (pip install pyyaml) or use a .json config."
            )
        return yaml.safe_load(raw) or {}
    if suffix == ".json":
        return json.loads(raw) if raw.strip() else {}
    # Unknown suffix: try YAML first (superset of JSON), then JSON.
    if _HAVE_YAML:
        return yaml.safe_load(raw) or {}
    return json.loads(raw) if raw.strip() else {}


def _deep_copy(d: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(d))


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = _deep_merge(base[key], value)
        else:
            base[key] = value
    return base
