"""Rate-limit calibration.

Sends a small, bounded burst to a live service to learn where the target starts
rejecting requests (HTTP 429/503 or a Retry-After). Knowing this lets you stay
polite *and* efficient on later phases. The burst is deliberately small and
stops at the first sign of limiting — this measures the limit, it does not try
to exhaust it.
"""

from __future__ import annotations

import time

from .base import Context, Module

_LIMIT_STATUSES = {429, 503}


class RateCalModule(Module):
    name = "ratecal"
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
            ctx.log.warn("[ratecal] no in-scope services; run probe first")
            return {"checked": 0, "limited": 0}

        max_req = int(ctx.config.get("modules.ratecal.max_requests", 15))
        limited = 0
        for base in bases:
            if self._measure(ctx, base.rstrip("/"), max_req):
                limited += 1
        ctx.log.success(f"[ratecal] {limited}/{len(bases)} service(s) showed rate limiting")
        return {"checked": len(bases), "limited": limited}

    def _measure(self, ctx: Context, base: str, max_req: int) -> bool:
        # NOTE: these requests still pass through the shared limiter, so this
        # observes the TARGET's limit without us being the ones flooding.
        start = time.monotonic()
        sent = 0
        for i in range(max_req):
            resp = ctx.http.get(base + "/")
            sent += 1
            if resp.status in _LIMIT_STATUSES:
                elapsed = max(time.monotonic() - start, 1e-6)
                rate = sent / elapsed
                retry_after = resp.header("retry-after")
                tuned = ""
                # Optionally slow the whole pipeline to stay under the observed limit.
                if ctx.config.get("modules.ratecal.auto_tune", False):
                    safe = max(rate * 0.5, 0.5)
                    ctx.limiter.set_per_host_rate(safe)
                    tuned = f"; auto-tuned per-host rate to {safe:.1f} req/s"
                    ctx.log.info(f"[ratecal] auto-tuned per-host rate to {safe:.1f} req/s")
                ctx.store.add_finding(
                    target=base, module="ratecal",
                    name=f"Rate limiting observed after {sent} requests", severity="info",
                    evidence=(
                        f"HTTP {resp.status} after {sent} requests (~{rate:.1f} req/s)"
                        + (f"; Retry-After: {retry_after}" if retry_after else "") + tuned
                    ),
                    requests=sent, status=resp.status, retry_after=retry_after,
                )
                ctx.log.info(f"[ratecal] {base}: limited after {sent} req (~{rate:.1f}/s)")
                return True
            if not resp.ok:
                break
        ctx.log.debug(f"[ratecal] {base}: no limiting within {sent} requests")
        return False
