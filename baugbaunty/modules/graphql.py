"""GraphQL endpoint discovery and introspection.

GraphQL APIs are a rich modern attack surface. This module finds GraphQL
endpoints on in-scope live services and checks whether **introspection** is
enabled — a very common misconfiguration that hands an attacker the full schema
(every query, mutation and type), dramatically easing further testing.

It issues a single, read-only introspection query per candidate path. It does
not call any mutation or attempt to exploit the schema; a discovered schema is
information for you to review and test by hand.
"""

from __future__ import annotations

import json

from .base import Context, Module

# Common locations GraphQL is mounted at.
_CANDIDATES = [
    "graphql", "api/graphql", "v1/graphql", "v2/graphql", "query", "api",
    "gql", "graphql/console", "graphiql", "playground", "api/gql", "console",
]

# Minimal introspection query — enough to prove introspection is on and to
# enumerate the top-level schema without pulling the entire (large) type graph.
_INTROSPECTION = json.dumps({
    "query": "query{__schema{queryType{name} mutationType{name} "
             "types{name kind}}}"
}).encode()

# A trivial probe to recognise a GraphQL endpoint even when introspection is off.
_PROBE = json.dumps({"query": "{__typename}"}).encode()


class GraphqlModule(Module):
    name = "graphql"
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
            ctx.log.warn("[graphql] no in-scope services; run probe first")
            return {"endpoints": 0, "introspection": 0}

        endpoints = 0
        introspective = 0
        for base in bases:
            base = base.rstrip("/")
            for path in _CANDIDATES:
                url = f"{base}/{path.lstrip('/')}"
                if not ctx.scope.is_allowed(url):
                    continue
                kind = self._check(ctx, url)
                if kind == "introspection":
                    endpoints += 1
                    introspective += 1
                    break  # found the endpoint for this base; stop probing paths
                if kind == "endpoint":
                    endpoints += 1
                    break

        ctx.log.success(
            f"[graphql] {endpoints} endpoint(s), {introspective} with introspection"
        )
        return {"endpoints": endpoints, "introspection": introspective}

    def _post(self, ctx: Context, url: str, body: bytes):
        return ctx.http.request(
            "POST", url, headers={"Content-Type": "application/json"}, data=body
        )

    def _check(self, ctx: Context, url: str) -> str | None:
        # First, a cheap probe to see if this even looks like GraphQL.
        resp = self._post(ctx, url, _PROBE)
        if not resp.ok or resp.status in (0, 404):
            return None
        text = resp.text(limit=50_000)
        looks_graphql = ("__typename" in text or '"data"' in text
                         or '"errors"' in text and "graphql" in text.lower())
        if not looks_graphql:
            return None

        ctx.store.add_asset(url, "endpoint", source="graphql", in_scope=True)

        # Now attempt full introspection.
        intro = self._post(ctx, url, _INTROSPECTION)
        if intro.ok and "__schema" in intro.text(limit=200_000):
            try:
                data = json.loads(intro.text(limit=1_000_000)).get("data", {})
                schema = data.get("__schema", {}) or {}
            except json.JSONDecodeError:
                schema = {}
            types = schema.get("types", []) or []
            query_t = (schema.get("queryType") or {}).get("name")
            mut_t = (schema.get("mutationType") or {}).get("name")
            ctx.store.add_finding(
                target=url, module="graphql",
                name="GraphQL introspection enabled", severity="medium",
                evidence=(
                    f"Introspection at {url} exposed the schema: {len(types)} types, "
                    f"queryType={query_t}, mutationType={mut_t}"
                ),
                types=len(types), query_type=query_t, mutation_type=mut_t,
            )
            ctx.log.warn(f"[graphql] introspection enabled: {url} ({len(types)} types)")
            return "introspection"

        # Endpoint exists but introspection appears disabled.
        ctx.store.add_finding(
            target=url, module="graphql",
            name="GraphQL endpoint found (introspection disabled)", severity="info",
            evidence=f"GraphQL endpoint at {url}; introspection query was rejected",
        )
        ctx.log.info(f"[graphql] endpoint (introspection off): {url}")
        return "endpoint"
