"""End-to-end integration tests against a real local HTTP server.

These exercise the full stack — the real HTTP client, scope gate, rate limiter
and the active modules — instead of mocking. They catch regressions that
unit tests miss (e.g. a malformed request line that only fails on the wire).

Zero external dependencies: the fixture is a stdlib threaded HTTP server.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from baugbaunty.core.config import Config
from baugbaunty.core.store import Store
from baugbaunty.modules.base import Context
from baugbaunty.modules.content import ContentModule
from baugbaunty.modules.graphql import GraphqlModule
from baugbaunty.modules.params import ParamsModule
from baugbaunty.modules.probe import ProbeModule
from baugbaunty.modules.waf import WafModule
from baugbaunty.modules.webchecks import WebChecksModule


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, code, body, headers=None):
        self.send_response(code)
        # Simulate a Cloudflare WAF + nginx, no security headers.
        self.send_header("Server", "nginx")
        self.send_header("CF-RAY", "deadbeef-AMS")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        p, q = u.path, parse_qs(u.query, keep_blank_values=True)
        origin = self.headers.get("Origin")
        host = self.headers.get("Host", "")

        if p == "/admin":
            return self._send(301, b"", {"Location": "/admin/"})
        if p == "/.env":
            return self._send(200, b"SECRET=bbx")
        if p == "/":
            extra = {}
            body = b"<html><head><title>IntApp</title></head><body>home"
            if "q" in q:
                val = q["q"][0]
                if "\r\n" in val:  # CRLF sink
                    for line in val.split("\r\n")[1:]:
                        if ":" in line:
                            k, v = line.split(":", 1)
                            extra[k.strip()] = v.strip()
                body += b" " + val.encode("utf-8", "replace")  # reflection
            if "debug" in q:
                body += b" DEBUGDEBUGDEBUGDEBUGDEBUG"
            if "evil" in host:
                body += b" host=" + host.encode()
            body += b"</body></html>"
            if origin:  # permissive CORS
                extra["Access-Control-Allow-Origin"] = origin
                extra["Access-Control-Allow-Credentials"] = "true"
            return self._send(200, body, extra)
        return self._send(404, b"nf")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            query = json.loads(raw).get("query", "")
        except Exception:
            query = ""
        if urlparse(self.path).path == "/graphql":
            if "__schema" in query:
                body = json.dumps({"data": {"__schema": {
                    "queryType": {"name": "Query"}, "mutationType": None,
                    "types": [{"name": "User", "kind": "OBJECT"},
                              {"name": "Query", "kind": "OBJECT"}],
                }}}).encode()
            elif "__typename" in query:
                body = json.dumps({"data": {"__typename": "Query"}}).encode()
            else:
                body = json.dumps({"errors": [{"message": "no"}]}).encode()
            return self._send(200, body, {"Content-Type": "application/json"})
        return self._send(404, b"nf")


@pytest.fixture()
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"127.0.0.1:{port}"
    httpd.shutdown()


def _ctx(tmp_path, host):
    cfg = Config()
    cfg.set("program.name", "int")
    cfg.set("program.authorized", True)
    cfg.set("scope.include", [host])
    cfg.set("limits.global_rps", 500)
    cfg.set("limits.per_host_rps", 500)
    cfg.set("limits.timeout", 5)
    store = Store.open(tmp_path / "int.sqlite")
    return Context.build(cfg, store), store


def test_probe_detects_live_and_headers(server, tmp_path):
    ctx, store = _ctx(tmp_path, server)
    try:
        res = ProbeModule(hosts=[server]).run(ctx)
        assert res["live"] == 1
        services = store.services()
        assert any(s["url"] == f"http://{server}" for s in services)
        # missing-security-header findings recorded
        assert any(f["module"] == "probe" for f in store.findings())
    finally:
        store.close()


def test_content_finds_sensitive_and_redirect(server, tmp_path):
    ctx, store = _ctx(tmp_path, server)
    try:
        ProbeModule(hosts=[server]).run(ctx)
        ContentModule(services=[f"http://{server}"]).run(ctx)
        names = [f["name"] for f in store.findings() if f["module"] == "content"]
        assert any("/.env" in n for n in names)       # sensitive file (200)
        assert any("/admin" in n for n in names)       # redirect discovered
    finally:
        store.close()


def test_webchecks_cors_crlf_reflection(server, tmp_path):
    ctx, store = _ctx(tmp_path, server)
    try:
        ProbeModule(hosts=[server]).run(ctx)
        ParamsModule(targets=[f"http://{server}"]).run(ctx)
        WebChecksModule().run(ctx)
        wc = [f for f in store.findings() if f["module"] == "webchecks"]
        names = " ".join(f["name"] for f in wc)
        assert "CORS misconfiguration" in names
        assert "CRLF" in names or "Reflected" in names
    finally:
        store.close()


def test_graphql_introspection(server, tmp_path):
    ctx, store = _ctx(tmp_path, server)
    try:
        res = GraphqlModule(services=[f"http://{server}"]).run(ctx)
        assert res["introspection"] == 1
        assert any("introspection enabled" in f["name"] for f in store.findings())
    finally:
        store.close()


def test_waf_detects_cloudflare(server, tmp_path):
    ctx, store = _ctx(tmp_path, server)
    try:
        res = WafModule(services=[f"http://{server}"]).run(ctx)
        assert res["detected"] == 1
        assert any("Cloudflare" in f["name"] for f in store.findings() if f["module"] == "waf")
    finally:
        store.close()


def test_out_of_scope_host_is_blocked(server, tmp_path):
    """The scope gate must refuse a host that isn't in scope, even live."""
    ctx, store = _ctx(tmp_path, server)
    try:
        from baugbaunty.core.scope import ScopeViolation
        with pytest.raises(ScopeViolation):
            ctx.http.get("http://127.0.0.2:9/")  # not in scope
    finally:
        store.close()
