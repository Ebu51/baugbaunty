from baugbaunty.core.config import Config
from baugbaunty.core.store import Store
from baugbaunty.report.submission import build_submission, classify, generate_submissions


def test_classify_by_module_and_name():
    assert classify({"module": "takeover", "name": "Possible subdomain takeover (S3)"}) == "subdomain_takeover"
    assert classify({"module": "webchecks", "name": "CORS misconfiguration (...)"}) == "cors"
    assert classify({"module": "webchecks", "name": "Open redirect via 'next'"}) == "open_redirect"
    assert classify({"module": "webchecks", "name": "Reflected input (XSS candidate) via 'q'"}) == "xss"
    assert classify({"module": "webchecks", "name": "CRLF / header injection via 'q'"}) == "crlf"
    assert classify({"module": "webchecks", "name": "Host header injection (reflected)"}) == "host_header"
    assert classify({"module": "webchecks", "name": "SSRF probe sent via 'url'"}) == "ssrf"
    assert classify({"module": "jsintel", "name": "Possible AWS Access Key ID in JavaScript"}) == "secret_disclosure"
    assert classify({"module": "content", "name": "Sensitive path exposed: /.env (200)"}) == "sensitive_file"
    assert classify({"module": "cvecheck", "name": "Apache httpd 2.4.49 [CVE-2021-41773]"}) == "vulnerable_component"
    assert classify({"module": "probe", "name": "Missing HSTS header"}) == "security_headers"


def test_build_submission_sections():
    f = {"module": "webchecks", "name": "CORS misconfiguration (x)", "severity": "high",
         "target": "https://x.example.com", "evidence": "Origin reflected"}
    md = build_submission(f, platform="hackerone")
    for section in ("## CORS Misconfiguration", "**Severity:** High",
                    "### Steps to Reproduce", "### Impact", "### Remediation",
                    "### References", "https://x.example.com"):
        assert section in md


def test_build_submission_bugcrowd_priority():
    f = {"module": "takeover", "name": "takeover", "severity": "high", "target": "a.x.com"}
    md = build_submission(f, platform="bugcrowd")
    assert "VRT priority ~P2" in md


def test_generate_submissions_threshold(tmp_path):
    store = Store.open(tmp_path / "s.sqlite")
    store.add_finding("https://a.x.com", "webchecks", "CORS misconfiguration (x)", "high", "e")
    store.add_finding("https://a.x.com", "probe", "Missing HSTS header", "info", "e")
    cfg = Config()
    cfg.set("program.name", "t")
    path = generate_submissions(store, cfg, tmp_path, min_severity="medium", platform="hackerone")
    text = path.read_text()
    assert "CORS Misconfiguration" in text      # high -> included
    assert "Missing Security Headers" not in text  # info -> below threshold
    store.close()


def test_generate_submissions_json(tmp_path):
    store = Store.open(tmp_path / "s2.sqlite")
    store.add_finding("https://a.x.com", "takeover", "Possible subdomain takeover (S3)", "high", "e")
    cfg = Config()
    cfg.set("program.name", "t2")
    path = generate_submissions(store, cfg, tmp_path, min_severity="medium", fmt="json")
    import json
    data = json.loads(path.read_text())
    assert data[0]["vuln_class"] == "subdomain_takeover"
    assert "submission_markdown" in data[0]
    store.close()
