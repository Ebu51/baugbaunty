from types import SimpleNamespace

from baugbaunty.core.config import Config
from baugbaunty.core.ratelimit import RateLimiter
from baugbaunty.core.store import Store
from baugbaunty.modules.base import Context
from baugbaunty.modules.asn import AsnModule
from baugbaunty.modules.cluster import ClusterModule, _sig
from baugbaunty.modules.dnsbrute import DnsBruteModule, _BUILTIN


def _ctx(tmp_path, overrides=None):
    cfg = Config()
    for k, v in (overrides or {}).items():
        cfg.set(k, v)
    cfg.set("program.authorized", True)
    store = Store.open(tmp_path / "f.sqlite")
    return Context.build(cfg, store), store


# --- ratelimit auto-tune -------------------------------------------------
def test_ratelimiter_set_per_host_rate():
    rl = RateLimiter(global_rps=100, per_host_rps=50)
    rl.acquire("x.com")                 # create a host bucket
    rl.set_per_host_rate(2.0)           # retune
    assert rl._per_host_rps == 2.0
    assert rl._hosts == {}              # buckets reset
    rl.acquire("x.com")                 # still works with new rate


# --- cluster -------------------------------------------------------------
def test_cluster_signature_groups_identical():
    a = {"status": 200, "title": "Home", "content_length": 1000, "tech": "[]"}
    b = {"status": 200, "title": "Home", "content_length": 1020, "tech": "[]"}  # same 512 bucket
    c = {"status": 404, "title": "NF", "content_length": 50, "tech": "[]"}
    assert _sig(a) == _sig(b)
    assert _sig(a) != _sig(c)


def test_cluster_module_flags_duplicates(tmp_path):
    ctx, store = _ctx(tmp_path, {"scope.include": ["*.x.com"]})
    try:
        for i in range(3):
            store.add_service(f"https://h{i}.x.com", host=f"h{i}.x.com", status=200,
                              title="Same", server="nginx", tech=[], content_length=500)
        store.add_service("https://diff.x.com", host="diff.x.com", status=200,
                          title="Different", server="nginx", tech=[], content_length=9000)
        res = ClusterModule().run(ctx)
        assert res["duplicate_groups"] == 1
        assert any(f["module"] == "cluster" for f in store.findings())
    finally:
        store.close()


# --- dnsbrute ------------------------------------------------------------
def test_dnsbrute_builtin_wordlist():
    m = DnsBruteModule()
    cfg = Config()
    assert set(m._words(SimpleNamespace(config=cfg))) == set(_BUILTIN)
    assert "dev" in _BUILTIN and "api" in _BUILTIN


def test_dnsbrute_permutations(tmp_path):
    ctx, store = _ctx(tmp_path, {"scope.include": ["*.x.com"]})
    try:
        store.add_asset("app.x.com", "subdomain", "passive", in_scope=True)
        perms = DnsBruteModule()._permutations(ctx, "x.com")
        assert "dev-app.x.com" in perms
        assert "app-dev.x.com" in perms
        assert "dev.app.x.com" in perms
    finally:
        store.close()


# --- asn -----------------------------------------------------------------
def test_asn_keyword_derivation(tmp_path):
    ctx, store = _ctx(tmp_path, {"scope.include": ["*.acme.com", "api.foo.io"]})
    try:
        kw = AsnModule()._keywords(ctx)
        assert "acme" in kw and "api" in kw
    finally:
        store.close()
