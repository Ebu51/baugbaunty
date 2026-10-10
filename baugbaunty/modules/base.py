"""Shared runtime context and the Module protocol."""

from __future__ import annotations

from dataclasses import dataclass

from ..core.config import Config
from ..core.http import HttpClient
from ..core.logging import Logger, get_logger
from ..core.ratelimit import ConcurrencyGuard, HostHealth, RateLimiter
from ..core.scope import Scope
from ..core.store import Store


@dataclass
class Context:
    """Everything a module needs, assembled once per run."""

    config: Config
    scope: Scope
    limiter: RateLimiter
    http: HttpClient
    store: Store
    log: Logger
    concurrency: ConcurrencyGuard
    health: HostHealth

    @classmethod
    def build(cls, config: Config, store: Store, log: Logger | None = None) -> "Context":
        scope = Scope.from_lists(
            config.get("scope.include", []),
            config.get("scope.exclude", []),
        )
        limiter = RateLimiter(
            global_rps=float(config.get("limits.global_rps", 10)),
            per_host_rps=float(config.get("limits.per_host_rps", 5)),
        )
        http = HttpClient(
            scope=scope,
            limiter=limiter,
            user_agent=config.get("http.user_agent", "baugbaunty/0.1"),
            timeout=float(config.get("limits.timeout", 10)),
            verify_tls=bool(config.get("http.verify_tls", True)),
            follow_redirects=bool(config.get("http.follow_redirects", True)),
            max_retries=int(config.get("limits.max_retries", 2)),
            extra_headers=config.get("http.extra_headers", {}) or {},
            proxy=config.get("http.proxy", "") or "",
        )
        return cls(
            config=config,
            scope=scope,
            limiter=limiter,
            http=http,
            store=store,
            log=log or get_logger(),
            concurrency=ConcurrencyGuard(int(config.get("limits.concurrency", 20))),
            health=HostHealth(),
        )


class Module:
    """Base class for pipeline modules.

    ``active`` modules send traffic to the target and therefore require the
    engagement to be explicitly authorized in config. ``passive`` modules only
    touch third-party data sources (e.g. certificate transparency).
    """

    name: str = "module"
    active: bool = True

    def run(self, ctx: Context) -> dict:  # pragma: no cover - interface
        raise NotImplementedError
