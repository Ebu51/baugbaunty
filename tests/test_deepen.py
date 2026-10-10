from types import SimpleNamespace

from baugbaunty.core.config import Config
from baugbaunty.modules.content import ContentModule
from baugbaunty.modules.takeover import _FINGERPRINTS
from baugbaunty.modules.cvecheck import _osv_severity
from baugbaunty.modules.webchecks import _SSRF_PARAMS, _REDIRECT_PARAMS


def _ctx(cfg_overrides: dict) -> SimpleNamespace:
    cfg = Config()
    for k, v in cfg_overrides.items():
        cfg.set(k, v)
    return SimpleNamespace(config=cfg)


def test_content_extension_permutation():
    m = ContentModule()
    ctx = _ctx({"modules.content.permute_ext": [".php", ".bak"]})
    out = m._expand(ctx, ["admin", "index.html"])
    assert "admin" in out
    assert "admin.php" in out and "admin.bak" in out
    # words that already have a file extension are not permuted
    assert "index.html.php" not in out


def test_content_no_permutation_by_default():
    m = ContentModule()
    ctx = _ctx({})
    assert m._expand(ctx, ["admin", "login"]) == ["admin", "login"]


def test_content_dir_like():
    assert ContentModule._dir_like("admin", 301)
    assert ContentModule._dir_like("api", 200)
    assert not ContentModule._dir_like("app.js", 200)  # has extension
    assert not ContentModule._dir_like("admin", 404)


def test_takeover_set_expanded():
    assert len(_FINGERPRINTS) >= 40
    for svc in ("Netlify", "Webflow", "UserVoice", "Gemfury", "Intercom"):
        assert svc in _FINGERPRINTS
        assert "fingerprint" in _FINGERPRINTS[svc]


def test_ssrf_and_redirect_param_sets():
    assert "callback" in _SSRF_PARAMS
    assert "webhook" in _SSRF_PARAMS
    assert "next" in _REDIRECT_PARAMS


def test_osv_severity_mapping():
    assert _osv_severity({"database_specific": {"severity": "CRITICAL"}}) == "critical"
    assert _osv_severity({"database_specific": {"severity": "MODERATE"}}) == "medium"
    assert _osv_severity({}) == "medium"  # default when unknown
