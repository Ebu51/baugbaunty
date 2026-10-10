"""A polite, scope-aware HTTP client built on the standard library.

Key properties:
* Every request is checked against the active :class:`Scope` before a packet
  is sent. An out-of-scope URL raises instead of connecting.
* Every request passes through the shared :class:`RateLimiter`.
* Sensible timeouts, bounded retries with backoff, honest User-Agent.

Using the stdlib (``urllib``) keeps the core dependency-free; modules that want
richer behaviour can still shell out to specialised external tools.
"""

from __future__ import annotations

import gzip
import http.client
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import urlparse

from .ratelimit import RateLimiter
from .scope import Scope, ScopeViolation


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes = b""
    elapsed: float = 0.0
    final_url: str = ""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and 0 < self.status < 600

    def text(self, limit: int | None = None) -> str:
        data = self.body if limit is None else self.body[:limit]
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # type: ignore[override]
        return None


@dataclass
class HttpClient:
    scope: Scope
    limiter: RateLimiter
    user_agent: str = "baugbaunty/0.1 (authorized-security-testing)"
    timeout: float = 10.0
    verify_tls: bool = True
    follow_redirects: bool = True
    max_retries: int = 2
    extra_headers: Mapping[str, str] = field(default_factory=dict)
    max_body: int = 2_000_000  # cap downloaded bytes per response (2 MB)
    proxy: str = ""  # e.g. http://127.0.0.1:8080 to route through Burp/mitmproxy

    def _opener(self, follow: bool | None = None) -> urllib.request.OpenerDirector:
        if follow is None:
            follow = self.follow_redirects
        handlers: list[urllib.request.BaseHandler] = []
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
        if self.proxy:
            handlers.append(
                urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy})
            )
        if not follow:
            handlers.append(_NoRedirect())
        return urllib.request.build_opener(*handlers)

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str] | None = None,
        data: bytes | None = None,
        follow_redirects: bool | None = None,
    ) -> Response:
        host = urlparse(url).hostname or ""
        # Hard scope gate: never send a packet to an out-of-scope host.
        decision = self.scope.check(url)
        if not decision.allowed:
            raise ScopeViolation(
                f"Blocked {method} {url}: {decision.reason}"
            )

        self.limiter.acquire(host)

        req_headers = {"User-Agent": self.user_agent, "Accept-Encoding": "gzip"}
        req_headers.update({k: v for k, v in self.extra_headers.items()})
        if headers:
            req_headers.update(headers)

        opener = self._opener(follow_redirects)
        last_err: str | None = None
        for attempt in range(self.max_retries + 1):
            start = time.monotonic()
            req = urllib.request.Request(
                url, data=data, headers=req_headers, method=method.upper()
            )
            try:
                with opener.open(req, timeout=self.timeout) as resp:
                    raw = resp.read(self.max_body)
                    body = _maybe_gunzip(raw, resp.headers.get("Content-Encoding", ""))
                    return Response(
                        url=url,
                        status=resp.status,
                        headers=_lower_headers(resp.headers.items()),
                        body=body,
                        elapsed=time.monotonic() - start,
                        final_url=resp.geturl(),
                    )
            except urllib.error.HTTPError as e:
                # An HTTP error is still a valid response (401/403/500 etc.).
                raw = b""
                try:
                    raw = e.read(self.max_body)
                except Exception:
                    pass
                return Response(
                    url=url,
                    status=e.code,
                    headers=_lower_headers(e.headers.items() if e.headers else []),
                    body=_maybe_gunzip(raw, (e.headers or {}).get("Content-Encoding", "")),
                    elapsed=time.monotonic() - start,
                    final_url=url,
                )
            except (urllib.error.URLError, ssl.SSLError, OSError, ValueError,
                    http.client.HTTPException) as e:
                last_err = str(getattr(e, "reason", e))
                if attempt < self.max_retries:
                    time.sleep(0.5 * (2**attempt))
                    continue
        return Response(url=url, status=0, headers={}, error=last_err or "request failed")

    def get(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
        follow_redirects: bool | None = None,
    ) -> Response:
        return self.request("GET", url, headers=headers, follow_redirects=follow_redirects)

    def head(self, url: str, headers: Mapping[str, str] | None = None) -> Response:
        return self.request("HEAD", url, headers=headers)


def _lower_headers(items) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in items:
        out[str(k).lower()] = str(v)
    return out


def _maybe_gunzip(data: bytes, encoding: str) -> bytes:
    if "gzip" in (encoding or "").lower():
        try:
            return gzip.decompress(data)
        except Exception:
            return data
    return data
