import json

from baugbaunty.core.http import Response
from baugbaunty.modules.graphql import _CANDIDATES, _INTROSPECTION, GraphqlModule
from baugbaunty.modules.waf import _SIGNATURES, WafModule


def _resp(headers=None, body=b"", status=200):
    return Response(url="http://x", status=status, headers=headers or {}, body=body)


def test_waf_matches_cloudflare_header():
    m = WafModule()
    r = _resp(headers={"server": "cloudflare", "cf-ray": "abc123"})
    assert "Cloudflare" in m._match(r)


def test_waf_matches_incapsula_cookie():
    m = WafModule()
    r = _resp(headers={"set-cookie": "incap_ses_123=abc; visid_incap_1=x"})
    assert "Imperva/Incapsula" in m._match(r)


def test_waf_no_false_positive_on_plain_response():
    m = WafModule()
    r = _resp(headers={"server": "nginx", "content-type": "text/html"})
    assert m._match(r) == set()


def test_waf_signature_set_present():
    for waf in ("Cloudflare", "Akamai", "AWS WAF / CloudFront", "ModSecurity"):
        assert waf in _SIGNATURES


def test_graphql_candidates_and_query():
    assert "graphql" in _CANDIDATES
    # the introspection query is valid JSON asking for __schema
    payload = json.loads(_INTROSPECTION.decode())
    assert "__schema" in payload["query"]


def test_graphql_module_name():
    assert GraphqlModule.name == "graphql"
    assert GraphqlModule.active is True
