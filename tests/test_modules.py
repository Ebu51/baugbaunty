import time

from baugbaunty.core.notify import Notifier
from baugbaunty.core.store import Store
from baugbaunty.modules.jsintel import _SECRET_PATTERNS, _redact
from baugbaunty.modules.wayback import WaybackModule
from baugbaunty.modules.takeover import _FINGERPRINTS


def test_store_meta_and_new_since(tmp_path):
    store = Store.open(tmp_path / "m.sqlite")
    assert store.get_meta("last_run_ts") is None
    checkpoint = time.time()
    time.sleep(0.01)
    store.add_asset("new.example.com", "subdomain", "passive", in_scope=True)
    store.add_finding("https://new.example.com", "probe", "X", "high", "e")
    diff = store.new_since(checkpoint)
    assert len(diff["assets"]) == 1
    assert len(diff["findings"]) == 1
    # nothing new strictly after now
    assert store.new_since(time.time() + 1)["assets"] == []
    store.set_meta("last_run_ts", "123.4")
    assert store.get_meta("last_run_ts") == "123.4"
    store.close()


def test_update_asset_data_merges(tmp_path):
    store = Store.open(tmp_path / "d.sqlite")
    store.add_asset("a.example.com", "subdomain", "passive", in_scope=True)
    store.update_asset_data("a.example.com", "subdomain", resolved=True, ips=["1.2.3.4"])
    store.update_asset_data("a.example.com", "subdomain", cname=["x.github.io"])
    import json
    row = [a for a in store.assets() if a["value"] == "a.example.com"][0]
    data = json.loads(row["data"])
    assert data["resolved"] is True
    assert data["ips"] == ["1.2.3.4"]
    assert data["cname"] == ["x.github.io"]  # earlier keys preserved
    store.close()


def test_notifier_severity_filter():
    n = Notifier(enabled=True, min_severity="medium")
    assert n.severity_passes("high")
    assert n.severity_passes("medium")
    assert not n.severity_passes("low")
    assert not n.severity_passes("info")


def test_notifier_disabled_is_noop():
    n = Notifier(enabled=False)
    # Should not raise even with no channels configured.
    n.send("t", "b")
    n.send_diff("prog", {"assets": [{"value": "x", "kind": "url"}]})


def test_jsintel_detects_aws_key():
    text = 'var k = "AKIAIOSFODNN7EXAMPLE"; const j="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEFghiJKL";'
    hits = {label for label, _, pat in _SECRET_PATTERNS if pat.search(text)}
    assert "AWS Access Key ID" in hits
    assert "JWT" in hits


def test_jsintel_generic_assignment():
    text = "apiKey: 'abcdef1234567890abcdef'"
    hits = {label for label, _, pat in _SECRET_PATTERNS if pat.search(text)}
    assert "Generic API Key assignment" in hits


def test_redact_hides_value():
    r = _redact("AKIAIOSFODNN7EXAMPLE")
    assert "IOSFODNN" not in r
    assert r.startswith("AKIA")


def test_wayback_interesting_detection():
    assert WaybackModule._is_interesting("https://x.example.com/old/data.sql")
    assert WaybackModule._is_interesting("https://x.example.com/search?q=1&id=2")
    assert not WaybackModule._is_interesting("https://x.example.com/home")


def test_takeover_fingerprints_present():
    assert "GitHub Pages" in _FINGERPRINTS
    assert _FINGERPRINTS["AWS/S3"]["vulnerable"] is True
