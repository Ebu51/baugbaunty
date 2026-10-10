from baugbaunty.integrations import programs
from baugbaunty.modules.cvecheck import _RULES, _ver, _between, CveCheckModule


# --- program import ------------------------------------------------------
def test_import_hackerone_structured():
    data = {
        "data": [
            {"attributes": {"asset_type": "WILDCARD", "asset_identifier": "*.acme.com",
                            "eligible_for_submission": True}},
            {"attributes": {"asset_type": "URL", "asset_identifier": "https://api.acme.com/v1",
                            "eligible_for_submission": True}},
            {"attributes": {"asset_type": "URL", "asset_identifier": "staging.acme.com",
                            "eligible_for_submission": False}},
            {"attributes": {"asset_type": "SOURCE_CODE", "asset_identifier": "github.com/a/b",
                            "eligible_for_submission": True}},
        ]
    }
    res = programs.parse_hackerone(data)
    assert "*.acme.com" in res.include
    assert "api.acme.com" in res.include  # URL reduced to host
    assert "staging.acme.com" in res.exclude
    assert any("github.com/a/b" in s for s in res.skipped)  # non-web skipped


def test_import_bugcrowd_shapes():
    data = {"targets": {
        "in_scope": [{"target": "*.foo.com", "type": "website"},
                     {"target": "api.foo.com", "type": "api"}],
        "out_of_scope": [{"target": "legacy.foo.com", "type": "website"}],
    }}
    res = programs.parse_bugcrowd(data)
    assert "*.foo.com" in res.include and "api.foo.com" in res.include
    assert "legacy.foo.com" in res.exclude


def test_import_plain_list_with_exclusions():
    text = "*.bar.com\napi.bar.com\n!internal.bar.com\n# comment\n"
    res = programs.parse_list(text)
    assert "*.bar.com" in res.include
    assert "internal.bar.com" in res.exclude


def test_import_auto_detect():
    h1 = {"data": [{"attributes": {"asset_identifier": "*.x.com", "asset_type": "WILDCARD",
                                   "eligible_for_submission": True}}]}
    assert "*.x.com" in programs.import_scope(__import__("json").dumps(h1)).include
    # plain text falls back to list parsing
    assert "a.com" in programs.import_scope("a.com\n").include


def test_to_config_dict_has_defaults():
    res = programs.ImportResult(name="p", include=["*.x.com"], exclude=["y.x.com"])
    cfg = programs.to_config_dict(res)
    assert cfg["scope"]["include"] == ["*.x.com"]
    assert cfg["program"]["authorized"] is False  # inherited default
    assert "limits" in cfg


# --- cve correlation -----------------------------------------------------
def test_ver_and_between():
    assert _ver("2.4.49") == (2, 4, 49)
    assert _between(_ver("1.18.0"), _ver("0.6.18"), _ver("1.20.0"))
    assert not _between(_ver("1.21.0"), _ver("0.6.18"), _ver("1.20.0"))


def test_cvecheck_products_and_rule_match():
    m = CveCheckModule()
    svc = {"server": "Apache/2.4.49 (Unix) PHP/7.4.1", "tech": "[]"}
    products = m._products(svc)
    names = {n for n, _, _ in products}
    assert "apache" in names and "php" in names
    # the Apache 2.4.49 RCE rule should fire
    apache_v = next(v for n, v, _ in products if n == "apache")
    fired = [cve for prod, pred, cve, sev, desc in _RULES
             if prod == "apache" and pred(apache_v)]
    assert "CVE-2021-41773" in fired
