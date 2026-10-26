"""Regression test: report text escaping.

PoC evidence/payloads and scanner descriptions can contain '<script>...' style
markup. ReportLab Paragraph parses XML-ish markup, so unescaped '<' raised
"parse ended with N unclosed tags" and crashed report generation. _esc fixes it.
"""

from app.engines.report_generator import _esc
from reportlab.platypus import Paragraph
from reportlab.lib.styles import getSampleStyleSheet


def test_esc_escapes_angle_brackets_and_amp():
    assert _esc("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert _esc("a & b") == "a &amp; b"
    assert _esc(None) == ""


def test_escaped_payload_builds_a_paragraph():
    # The raw payload would raise in ReportLab; the escaped one must not.
    style = getSampleStyleSheet()["BodyText"]
    payload = "Payload: \"><img src=x onerror=alert(1)> <script>/*x*/</script>"
    Paragraph(_esc(payload), style)   # should not raise
