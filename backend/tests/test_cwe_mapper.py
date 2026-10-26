"""CWE keyword-mapper tests.

Most assertions run against the pure static `_keyword_match`, so they need no
database or app context. The two regression cases (substring acronyms and the
cookie catch-all) are called out explicitly.
"""

import pytest

from app.models.normalized_finding import NormalizedFinding
from app.engines.cwe_mapper import CweMapper, KEYWORD_CWE_MAP, CWE_DESCRIPTIONS

match = CweMapper._keyword_match


@pytest.mark.parametrize("title,expected", [
    ("SQL Injection", "CWE-89"),
    ("Cross Site Scripting (Reflected)", "CWE-79"),
    ("DOM-based Cross-Site Scripting", "CWE-79"),
    ("Remote Code Execution via upload", "CWE-94"),
    ("Server-Side Template Injection", "CWE-1336"),
    ("Server Side Request Forgery", "CWE-918"),
    ("Insecure Direct Object Reference (IDOR)", "CWE-639"),
    ("Prototype Pollution", "CWE-1321"),
    ("Content Security Policy (CSP) Header Not Set", "CWE-693"),
    ("X-Content-Type-Options Header Missing", "CWE-693"),
    ("Missing Anti-clickjacking Header", "CWE-1021"),
    ("Session ID in URL Rewrite", "CWE-598"),
    ("Directory Browsing", "CWE-548"),
    ("Application Error Disclosure", "CWE-209"),
    ("Information Disclosure - Suspicious Comments", "CWE-615"),
    ("SSL Certificate Expired", "CWE-295"),
    ("Weak SSL/TLS Ciphers Supported", "CWE-326"),
    ("Cross-Domain Misconfiguration", "CWE-942"),
    ("HTTP TRACE Method Enabled", "CWE-693"),
    ("Private IP Disclosure", "CWE-200"),
])
def test_keyword_mappings(title, expected):
    assert match(title) == expected


def test_regression_source_code_is_not_rce():
    # "souRCE" must not trigger the \brce\b -> CWE-94 rule.
    assert match("Source Code Disclosure") == "CWE-540"


def test_regression_cookie_variants_are_distinct():
    # A bare "cookie" no longer collapses everything to HttpOnly (CWE-1004).
    assert match("Cookie Without Secure Flag") == "CWE-614"
    assert match("Cookie without SameSite Attribute") == "CWE-1275"
    assert match("Cookie No HttpOnly Flag") == "CWE-1004"


def test_specific_beats_general_ordering():
    # Both a specific and the general disclosure rule could match; specific wins.
    assert match("Backup File Disclosure") == "CWE-530"
    assert match("Debug Mode Enabled") == "CWE-489"


def test_no_match_returns_none():
    assert match("Completely unrelated marketing text") is None


def test_every_mapped_cwe_has_a_description():
    mapped = {cwe for _, cwe in KEYWORD_CWE_MAP}
    assert mapped <= set(CWE_DESCRIPTIONS)


def test_existing_cwe_is_preserved(app):
    f = NormalizedFinding(group_hash="c1", title="SQL Injection", cwe_id="CWE-999")
    assert CweMapper().map_finding(f) == "CWE-999"  # scanner CWE not overwritten


def test_maps_finding_without_cwe(app):
    f = NormalizedFinding(group_hash="c2", title="Reflected XSS on search", cwe_id=None)
    assert CweMapper().map_finding(f) == "CWE-79"
    assert f.cwe_id == "CWE-79"
