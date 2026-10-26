"""html_to_text: scanner descriptions/solutions (e.g. ZAP's) arrive as HTML and
must not surface raw <p> tags in the UI or the PDF report."""

import pytest

from app.utils.helpers import html_to_text


def test_strips_single_paragraph():
    assert html_to_text("<p>SQL injection may be possible.</p>") == \
        "SQL injection may be possible."


def test_separates_paragraphs_with_newline():
    out = html_to_text("<p>One.</p><p>Two.</p>")
    assert out == "One.\nTwo."


def test_decodes_entities_without_reintroducing_tags():
    # Entities decode to literal text (safe: rendered as text / XML-escaped later).
    assert html_to_text("<p>Encode &lt;b&gt; &amp; escape.</p>") == "Encode <b> & escape."


def test_plain_text_unchanged():
    assert html_to_text("Plain text, no markup") == "Plain text, no markup"


@pytest.mark.parametrize("empty", ["", None, "<p></p>"])
def test_empty_returns_none(empty):
    assert html_to_text(empty) is None
