"""PoC validator tests — scope guard and vuln-type routing (no network)."""

from types import SimpleNamespace
from app.engines.poc_validator import PocValidator


def _finding(**kw):
    base = dict(cwe_id=None, title="", parameter=None, url="http://t/x", method="GET")
    base.update(kw)
    return SimpleNamespace(**base)


def test_scope_parsing_from_string():
    v = PocValidator(scope="juice.local, example.com")
    assert v.scope == ["juice.local", "example.com"]


def test_scope_matches_host_and_subdomain():
    v = PocValidator(scope="example.com")
    assert v._in_scope("http://example.com/a") is True
    assert v._in_scope("https://api.example.com/a") is True
    assert v._in_scope("http://evil.com/a") is False


def test_empty_scope_is_unrestricted():
    assert PocValidator(scope="")._in_scope("http://anything.test/x") is True


def test_select_type_routing():
    sel = PocValidator._select_type
    assert sel(_finding(cwe_id="CWE-89", title="SQL Injection")) == "sqli_check"
    assert sel(_finding(cwe_id="CWE-79", title="Reflected XSS")) == "xss_check"
    assert sel(_finding(cwe_id="CWE-601", title="Open Redirect")) == "open_redirect_check"
    assert sel(_finding(cwe_id="CWE-22", title="Path Traversal")) == "lfi_check"
    assert sel(_finding(cwe_id="CWE-942", title="CORS misconfig")) == "cors_check"


def test_post_fetch_uses_form_body(monkeypatch):
    """A POST finding should send the payload as form data, not a query string."""
    v = PocValidator(scope="")
    captured = {}

    def fake_post(url, data=None, timeout=None):
        captured["url"] = url
        captured["data"] = data
        return SimpleNamespace(text="ok", status_code=200,
                               elapsed=SimpleNamespace(total_seconds=lambda: 0.1))

    monkeypatch.setattr(v.session, "post", fake_post)
    f = _finding(parameter="q", method="POST", url="http://t/login?old=1")
    resp, probe, method = v._fetch(f, "payload")
    assert method == "POST"
    assert captured["data"] == {"q": "payload"}
    assert "?" not in captured["url"]   # query stripped for POST target
