from baugbaunty.modules.crawl import _HREF_RE, _FORM_RE, _INPUT_RE, _ACTION_RE
from baugbaunty.modules.subdomains import SubdomainModule
from baugbaunty.modules.urltriage import UrlTriageModule, _PATTERNS


# --- crawl regexes -------------------------------------------------------
def test_crawl_href_extraction():
    html = '<a href="/a?id=1">x</a> <a href="https://x.com/b">y</a> <a href="#frag">z</a>'
    hrefs = _HREF_RE.findall(html)
    assert "/a?id=1" in hrefs
    assert "https://x.com/b" in hrefs
    assert "#frag" not in hrefs  # fragment-only excluded


def test_crawl_form_and_inputs():
    html = '<form method="POST" action="/login"><input name="user"><input name="pass"></form>'
    body = _FORM_RE.search(html).group(1)
    assert _INPUT_RE.findall(body) == ["user", "pass"]
    assert _ACTION_RE.search('action="/login"').group(1) == "/login"


# --- urltriage -----------------------------------------------------------
def test_urltriage_classify_categories():
    c = UrlTriageModule._classify
    assert "xss" in c("http://x/search?q=1")
    assert "lfi" in c("http://x/get?file=/etc/passwd")
    assert "redirect" in c("http://x/go?next=http://evil")
    assert "sqli" in c("http://x/p?id=1")
    assert c("http://x/no-params") == set()


def test_urltriage_pattern_sets_nonempty():
    for cat in ("redirect", "ssrf", "sqli", "xss", "lfi", "idor", "cmdi"):
        assert cat in _PATTERNS and _PATTERNS[cat]


# --- subdomains harvest --------------------------------------------------
def test_subdomains_harvest_filters_to_domain():
    m = SubdomainModule(["example.com"])
    text = "a.example.com\nb.example.com\nother.org\nfoo@example.com mail"
    got = m._harvest(text, "example.com")
    assert "a.example.com" in got
    assert "b.example.com" in got
    assert "other.org" not in got


def test_subdomains_sources_configurable():
    # the module exposes the new passive sources as methods
    m = SubdomainModule(["x.com"])
    for src in ("_crtsh", "_hackertarget", "_rapiddns", "_anubis", "_otx"):
        assert hasattr(m, src)
