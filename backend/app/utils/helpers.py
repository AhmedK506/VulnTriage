import html as _html
import re


_HTML_BLOCK_RE = re.compile(r"(?i)</(p|div|li|ul|ol|tr|h[1-6])\s*>|<br\s*/?>")
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def html_to_text(value, max_len: int = 10000) -> str | None:
    """Convert HTML markup to readable plain text.

    Scanner descriptions/solutions (notably ZAP's) arrive as HTML, which would
    otherwise show raw <p>…</p> tags in the UI and the PDF report. Block-level
    closing tags become newlines so paragraphs/list items stay separated, all
    remaining tags are removed, and HTML entities are decoded. Returns None for
    empty input.
    """
    if not value:
        return None
    s = _HTML_BLOCK_RE.sub("\n", str(value))
    s = _HTML_TAG_RE.sub("", s)
    s = _html.unescape(s)
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n[ \t]*", "\n", s)
    s = re.sub(r"\n{3,}", "\n\n", s).strip()
    return s[:max_len] or None


def allowed_file(filename: str, allowed_extensions: set) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def get_scanner_type(filename: str) -> str | None:
    """Best-effort scanner detection from filename."""
    name = filename.lower()
    if "zap" in name or name.endswith(".xml"):
        return "zap"
    if "nuclei" in name or name.endswith((".json", ".jsonl")):
        return "nuclei"
    if name.endswith(".nessus") or "nessus" in name:
        return "nessus"
    return None


def normalize_severity(raw: str) -> str:
    """Map scanner-specific severity labels to unified scale."""
    if not raw:
        return "Unknown"
    r = raw.strip().lower()
    if r in ("critical", "4"):
        return "Critical"
    if r in ("high", "3"):
        return "High"
    if r in ("medium", "moderate", "2"):
        return "Medium"
    if r in ("low", "1"):
        return "Low"
    if r in ("info", "informational", "0", "none"):
        return "Informational"
    return "Unknown"


def cvss_score_to_severity(score: float) -> str:
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Informational"


def extract_cwe_id(raw: str) -> str | None:
    """Extract CWE-NNN from a raw string.

    Returns None for CWE-0, which scanners (e.g. ZAP) emit as a placeholder
    meaning "no weakness assigned" — treating it as a real CWE would block the
    keyword mapper / NVD back-fill and wrongly credit the cwe_mapping factor.
    Non-numeric markers such as NVD-CWE-noinfo / NVD-CWE-Other already return
    None (no CWE-<digits> match).
    """
    if not raw:
        return None
    m = re.search(r"CWE-(\d+)", raw, re.IGNORECASE)
    if not m or int(m.group(1)) == 0:
        return None
    return f"CWE-{m.group(1)}"


def extract_cve_id(raw: str) -> str | None:
    """Extract CVE-YYYY-NNNNN from a raw string."""
    if not raw:
        return None
    m = re.search(r"CVE-\d{4}-\d{4,7}", raw, re.IGNORECASE)
    return m.group(0).upper() if m else None


def sanitize_text(value: str | None, max_len: int = 10000) -> str | None:
    if not value:
        return None
    return str(value).strip()[:max_len]
