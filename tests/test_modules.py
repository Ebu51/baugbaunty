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


def test_webchecks_set_param_add_and_replace():
    from baugbaunty.modules.webchecks import _set_param

    # add a new param
    out = _set_param("https://x.example.com/a", "next", "https://c/")
    assert "next=https%3A%2F%2Fc%2F" in out
    # replace an existing param, keep others
    out2 = _set_param("https://x.example.com/a?id=1&next=old", "next", "NEW")
    assert "next=NEW" in out2 and "id=1" in out2 and "old" not in out2


def test_webchecks_redirect_param_list():
    from baugbaunty.modules.webchecks import _REDIRECT_PARAMS

    assert "next" in _REDIRECT_PARAMS
    assert "redirect_uri" in _REDIRECT_PARAMS


def test_seeds_robots_and_loc_regex():
    from baugbaunty.modules.seeds import _ROBOTS_PATH_RE, _ROBOTS_SITEMAP_RE, _LOC_RE

    robots = "User-agent: *\nDisallow: /admin\nAllow: /public\nSitemap: http://x/sm.xml"
    assert "/admin" in _ROBOTS_PATH_RE.findall(robots)
    assert "/public" in _ROBOTS_PATH_RE.findall(robots)
    assert _ROBOTS_SITEMAP_RE.findall(robots) == ["http://x/sm.xml"]
    assert _LOC_RE.findall("<url><loc>http://x/p</loc></url>") == ["http://x/p"]


def test_httpclient_has_proxy_and_redirect_support():
    import inspect
    from baugbaunty.core.http import HttpClient

    assert "proxy" in {f.name for f in __import__("dataclasses").fields(HttpClient)}
    assert "follow_redirects" in inspect.signature(HttpClient.get).parameters
