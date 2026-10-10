from types import SimpleNamespace

from baugbaunty.core.config import Config
from baugbaunty.core.store import Store
from baugbaunty.modules.base import Context
from baugbaunty.modules.buckets import BucketsModule, _valid
from baugbaunty.modules.openapi import OpenApiModule
from baugbaunty.report.pdf import render_pdf


def _cfg_ctx(tmp_path, overrides):
    cfg = Config()
    for k, v in overrides.items():
        cfg.set(k, v)
    store = Store.open(tmp_path / "a.sqlite")
    return Context.build(cfg, store), store


# --- authenticated scanning ---------------------------------------------
def test_auth_bearer_and_cookie_merge(tmp_path):
    ctx, store = _cfg_ctx(tmp_path, {
        "auth.bearer": "ABC", "auth.cookie": "sid=1",
        "auth.headers": {"X-Api-Key": "k"},
    })
    try:
        h = ctx.http.extra_headers
        assert h["Authorization"] == "Bearer ABC"
        assert h["Cookie"] == "sid=1"
        assert h["X-Api-Key"] == "k"
    finally:
        store.close()


# --- openapi -------------------------------------------------------------
def test_openapi_base_from_servers():
    m = OpenApiModule()
    spec = {"openapi": "3.0.0", "servers": [{"url": "https://api.x.com/v1"}], "paths": {}}
    assert m._base_from_spec(spec, "https://x.com/openapi.json") == "https://api.x.com/v1"


def test_openapi_base_from_swagger2_host():
    m = OpenApiModule()
    spec = {"swagger": "2.0", "host": "api.x.com", "basePath": "/v2",
            "schemes": ["https"], "paths": {}}
    assert m._base_from_spec(spec, "https://x.com/swagger.json") == "https://api.x.com/v2"


def test_openapi_base_relative_server():
    m = OpenApiModule()
    spec = {"openapi": "3.0.0", "servers": [{"url": "/api"}], "paths": {}}
    assert m._base_from_spec(spec, "https://x.com/openapi.json") == "https://x.com/api"


# --- buckets -------------------------------------------------------------
def test_bucket_name_validation():
    assert _valid("acme-backups")
    assert _valid("a1b2")
    assert not _valid("Acme_Bucket")      # uppercase/underscore invalid
    assert not _valid("a")                 # too short
    assert not _valid("bad..name")         # consecutive dots


def test_bucket_candidate_generation(tmp_path):
    ctx, store = _cfg_ctx(tmp_path, {"scope.include": ["*.acme.com"],
                                     "modules.buckets.max_candidates": 50})
    try:
        cands = BucketsModule()._candidates(ctx)
        assert "acme" in cands
        assert any(c.startswith("acme-") for c in cands)
        assert len(cands) <= 50
        assert all(_valid(c) for c in cands)
    finally:
        store.close()


# --- pdf -----------------------------------------------------------------
def test_pdf_is_valid(tmp_path):
    p = render_pdf("T", [f"line {i}" for i in range(200)], tmp_path / "r.pdf")
    data = p.read_bytes()
    assert data.startswith(b"%PDF-1.4")
    assert b"%%EOF" in data[-16:]
    assert b"/Type /Catalog" in data
    assert data.count(b"/Type /Page ") >= 2  # multi-page


def test_pdf_escapes_special_chars(tmp_path):
    p = render_pdf("T", ["a (paren) and \\ backslash"], tmp_path / "e.pdf")
    data = p.read_bytes()
    assert b"\\(paren\\)" in data
    assert b"\\\\ backslash" in data
