"""Scope enforcement — the single most important safety control in the toolkit.

A bug bounty engagement is only legal within the program's declared scope.
Every outbound action MUST be checked against this engine. The design rules:

* Out-of-scope rules ALWAYS win over in-scope rules (deny beats allow).
* If an asset matches nothing in scope, it is treated as OUT of scope
  (default-deny). You must explicitly opt an asset in.
* Wildcards (``*.example.com``), exact hosts, IP addresses and CIDR ranges
  are all supported.

The engine never performs network calls; it is pure, deterministic and unit
tested, so the rest of the toolkit can trust its verdicts.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable
from urllib.parse import urlparse


class Verdict(Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    NOT_LISTED = "not_listed"  # matched nothing -> treated as out of scope


@dataclass(frozen=True)
class ScopeDecision:
    """Result of a scope check, with the matched rule for auditability."""

    asset: str
    verdict: Verdict
    matched_rule: str | None = None
    reason: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.IN_SCOPE


def _normalize_host(value: str) -> str:
    """Return the bare hostname/ip from a raw host, URL or host:port string."""

    value = value.strip().lower()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or ""
    else:
        # Strip a trailing port if present (but keep IPv6 brackets intact).
        if value.startswith("["):
            # IPv6 literal, optionally bracketed with a port: [::1]:8080
            end = value.find("]")
            if end != -1:
                value = value[1:end]
        elif value.count(":") == 1:
            host, _, port = value.partition(":")
            if port.isdigit():
                value = host
    return value.rstrip(".")


@dataclass
class _Rule:
    raw: str
    kind: str  # "wildcard" | "host" | "cidr" | "ip" | "regex"
    pattern: object

    def matches(self, host: str) -> bool:
        if self.kind == "host":
            return host == self.pattern
        if self.kind == "wildcard":
            # *.example.com matches sub.example.com AND example.com itself.
            base = self.pattern  # type: ignore[assignment]
            return host == base or host.endswith("." + base)
        if self.kind == "regex":
            return bool(self.pattern.search(host))  # type: ignore[union-attr]
        if self.kind in ("ip", "cidr"):
            try:
                addr = ipaddress.ip_address(host)
            except ValueError:
                return False
            if self.kind == "ip":
                return addr == self.pattern
            return addr in self.pattern  # type: ignore[operator]
        return False


def _compile_rule(raw: str) -> _Rule:
    raw = raw.strip().lower()
    if raw.startswith("re:"):
        return _Rule(raw, "regex", re.compile(raw[3:]))
    if "/" in raw and _looks_like_cidr(raw):
        return _Rule(raw, "cidr", ipaddress.ip_network(raw, strict=False))
    try:
        return _Rule(raw, "ip", ipaddress.ip_address(raw))
    except ValueError:
        pass
    if raw.startswith("*."):
        return _Rule(raw, "wildcard", raw[2:])
    return _Rule(raw, "host", _normalize_host(raw))


def _looks_like_cidr(raw: str) -> bool:
    try:
        ipaddress.ip_network(raw, strict=False)
        return True
    except ValueError:
        return False


@dataclass
class Scope:
    """Holds compiled in-scope and out-of-scope rules and renders verdicts."""

    include: list[_Rule] = field(default_factory=list)
    exclude: list[_Rule] = field(default_factory=list)

    @classmethod
    def from_lists(
        cls, include: Iterable[str] | None, exclude: Iterable[str] | None = None
    ) -> "Scope":
        inc = [_compile_rule(r) for r in (include or []) if r and r.strip()]
        exc = [_compile_rule(r) for r in (exclude or []) if r and r.strip()]
        return cls(include=inc, exclude=exc)

    def check(self, asset: str) -> ScopeDecision:
        host = _normalize_host(asset)
        if not host:
            return ScopeDecision(asset, Verdict.NOT_LISTED, None, "empty asset")

        # Deny beats allow: evaluate exclusions first.
        for rule in self.exclude:
            if rule.matches(host):
                return ScopeDecision(
                    asset,
                    Verdict.OUT_OF_SCOPE,
                    rule.raw,
                    f"matched out-of-scope rule '{rule.raw}'",
                )

        for rule in self.include:
            if rule.matches(host):
                return ScopeDecision(
                    asset,
                    Verdict.IN_SCOPE,
                    rule.raw,
                    f"matched in-scope rule '{rule.raw}'",
                )

        return ScopeDecision(
            asset,
            Verdict.NOT_LISTED,
            None,
            "asset is not listed in scope (default-deny)",
        )

    def is_allowed(self, asset: str) -> bool:
        return self.check(asset).allowed

    def filter_allowed(self, assets: Iterable[str]) -> list[str]:
        """Return only the assets that are explicitly in scope."""

        return [a for a in assets if self.is_allowed(a)]

    def __bool__(self) -> bool:
        return bool(self.include)


class ScopeViolation(RuntimeError):
    """Raised when an out-of-scope action is attempted."""


def enforce(scope: Scope, asset: str) -> ScopeDecision:
    """Return the decision if allowed, otherwise raise ScopeViolation."""

    decision = scope.check(asset)
    if not decision.allowed:
        raise ScopeViolation(
            f"Refusing to touch '{asset}': {decision.reason}. "
            "Add it to the program scope only if you are authorized."
        )
    return decision
