import time

from baugbaunty.core.config import Config
from baugbaunty.core.ratelimit import RateLimiter, TokenBucket
from baugbaunty.core.store import Store


def test_token_bucket_limits_rate():
    tb = TokenBucket(rate=20, capacity=1)
    start = time.monotonic()
    for _ in range(5):
        tb.acquire()
    elapsed = time.monotonic() - start
    # 5 tokens at 20/s with capacity 1 -> at least ~0.2s of waiting.
    assert elapsed >= 0.15


def test_rate_limiter_runs():
    rl = RateLimiter(global_rps=100, per_host_rps=50)
    for _ in range(10):
        rl.acquire("example.com")  # should not raise


def test_config_defaults_and_override(tmp_path):
    cfg = Config()
    assert cfg.get("limits.global_rps") == 10.0
    assert cfg.authorized is False

    p = tmp_path / "c.json"
    p.write_text('{"program": {"authorized": true}, "limits": {"global_rps": 3}}')
    loaded = Config.load(p)
    assert loaded.authorized is True
    assert loaded.get("limits.global_rps") == 3
    # untouched defaults still present
    assert loaded.get("limits.concurrency") == 20


def test_config_dotted_set():
    cfg = Config()
    cfg.set("program.name", "abc")
    assert cfg.get("program.name") == "abc"


def test_store_roundtrip(tmp_path):
    store = Store.open(tmp_path / "e.sqlite")
    store.add_asset("a.example.com", "subdomain", "passive", in_scope=True)
    store.add_asset("a.example.com", "subdomain", "passive", in_scope=True)  # dedup
    store.add_service("https://a.example.com", host="a.example.com", status=200,
                      title="Home", server="nginx", tech=["nginx"], content_length=10)
    store.add_finding("https://a.example.com", "probe", "Missing HSTS",
                      severity="low", evidence="no header")
    counts = store.counts()
    assert counts["assets"] == 1
    assert counts["services"] == 1
    assert counts["findings"] == 1
    findings = store.findings()
    assert findings[0]["severity"] == "low"
    store.close()
