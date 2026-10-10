from baugbaunty.core.scope import Scope, Verdict, enforce, ScopeViolation
import pytest


def make():
    return Scope.from_lists(
        include=["*.example.com", "api.test.io", "10.0.0.0/24", "203.0.113.5"],
        exclude=["*.staging.example.com", "secret.example.com"],
    )


def test_wildcard_matches_sub_and_apex():
    s = make()
    assert s.is_allowed("www.example.com")
    assert s.is_allowed("deep.sub.example.com")
    assert s.is_allowed("example.com")


def test_exclude_beats_include():
    s = make()
    assert not s.is_allowed("secret.example.com")
    assert not s.is_allowed("app.staging.example.com")
    assert s.check("secret.example.com").verdict is Verdict.OUT_OF_SCOPE


def test_default_deny_for_unlisted():
    s = make()
    d = s.check("notmine.org")
    assert d.verdict is Verdict.NOT_LISTED
    assert not d.allowed


def test_exact_host():
    s = make()
    assert s.is_allowed("api.test.io")
    assert not s.is_allowed("web.test.io")


def test_cidr_and_ip():
    s = make()
    assert s.is_allowed("10.0.0.17")
    assert not s.is_allowed("10.0.1.17")
    assert s.is_allowed("203.0.113.5")
    assert not s.is_allowed("203.0.113.6")


def test_url_and_port_normalization():
    s = make()
    assert s.is_allowed("https://www.example.com/path?q=1")
    assert s.is_allowed("www.example.com:8443")


def test_enforce_raises_out_of_scope():
    s = make()
    with pytest.raises(ScopeViolation):
        enforce(s, "evil.org")
    # in-scope returns a decision
    assert enforce(s, "api.test.io").allowed


def test_empty_asset_is_denied():
    s = make()
    assert not s.is_allowed("")
