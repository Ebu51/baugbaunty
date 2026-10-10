"""OpenAPI / Swagger specification discovery and endpoint extraction.

If a service exposes its API spec, it hands you the entire API surface: every
path, method and parameter. This module looks for the spec at common locations,
parses it (OpenAPI 3 or Swagger 2), and seeds the discovered operations as
endpoint assets (and their parameters as params findings) so later phases can
test them. An exposed spec is itself recorded as an informational finding.

It only reads the spec; it does not call the documented operations.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin, urlparse

from .base import Context, Module

_SPEC_PATHS = [
    "swagger.json", "openapi.json", "v2/api-docs", "v3/api-docs",
    "api-docs", "api/swagger.json", "api/openapi.json", "swagger/v1/swagger.json",
    "api/v1/swagger.json", "openapi.yaml", "swagger.yaml", "api/docs",
    ".well-known/openapi.json",
]


class OpenApiModule(Module):
    name = "openapi"
    active = True

    def __init__(self, services: list[str] | None = None) -> None:
        self.services = services

    def _bases(self, ctx: Context) -> list[str]:
        if self.services:
            return [s for s in self.services if ctx.scope.is_allowed(s)]
        return [s["url"] for s in ctx.store.services() if ctx.scope.is_allowed(s["url"])]

    def run(self, ctx: Context) -> dict:
        bases = self._bases(ctx)
        if not bases:
            ctx.log.warn("[openapi] no in-scope services; run probe first")
            return {"specs": 0, "endpoints": 0}

        specs = 0
        endpoints = 0
        for base in bases:
            base = base.rstrip("/")
            for path in _SPEC_PATHS:
                url = f"{base}/{path}"
                if not ctx.scope.is_allowed(url):
                    continue
                spec = self._fetch_spec(ctx, url)
                if spec is None:
                    continue
                specs += 1
                ctx.store.add_finding(
                    target=url, module="openapi",
                    name="API specification exposed", severity="info",
                    evidence=f"OpenAPI/Swagger spec served at {url}",
                )
                endpoints += self._extract(ctx, base, url, spec)
                break  # one spec per service is enough

        ctx.log.success(f"[openapi] {specs} spec(s), {endpoints} operation(s) extracted")
        return {"specs": specs, "endpoints": endpoints}

    def _fetch_spec(self, ctx: Context, url: str) -> dict | None:
        resp = ctx.http.get(url)
        if not resp.ok or resp.status != 200:
            return None
        text = resp.text(limit=3_000_000)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        # Must look like an OpenAPI/Swagger document.
        if "paths" in data and ("openapi" in data or "swagger" in data):
            return data
        return None

    def _base_from_spec(self, spec: dict, spec_url: str) -> str:
        # OpenAPI 3: servers[].url ; Swagger 2: host + basePath.
        servers = spec.get("servers")
        if isinstance(servers, list) and servers:
            u = servers[0].get("url", "")
            if u.startswith("http"):
                return u.rstrip("/")
            if u:  # relative server url
                return urljoin(spec_url, u).rstrip("/")
        host = spec.get("host")
        if host:
            scheme = (spec.get("schemes") or ["https"])[0]
            base_path = spec.get("basePath", "") or ""
            return f"{scheme}://{host}{base_path}".rstrip("/")
        # Fall back to the spec's own origin.
        p = urlparse(spec_url)
        return f"{p.scheme}://{p.netloc}"

    def _extract(self, ctx: Context, service_base: str, spec_url: str, spec: dict) -> int:
        api_base = self._base_from_spec(spec, spec_url)
        paths = spec.get("paths", {}) or {}
        count = 0
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            url = api_base + path if path.startswith("/") else f"{api_base}/{path}"
            if not ctx.scope.is_allowed(url):
                continue
            ctx.store.add_asset(url, "endpoint", source="openapi", in_scope=True)
            count += 1
            for method, op in item.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete", "head"):
                    continue
                if isinstance(op, dict):
                    for p in op.get("parameters", []) or []:
                        pname = p.get("name") if isinstance(p, dict) else None
                        if pname:
                            ctx.store.add_finding(
                                target=url, module="openapi",
                                name=f"API parameter from spec: {pname} ({method.upper()})",
                                severity="info",
                                evidence=f"{method.upper()} {url} parameter '{pname}' "
                                         f"(in={p.get('in','?')})",
                                param=pname, http_method=method.upper(),
                            )
        return count
