"""
Phase 9 – PDF Report Generator (ReportLab Platypus)

Generates a structured A4 PDF vulnerability triage report containing:
  • Cover page with severity quick-stats
  • Executive summary (classification + severity breakdowns)
  • Detailed findings by severity (full card for Critical/High, summary table for rest)
  • ML prediction analysis
  • CWE-based recommendations
"""

import os
from collections import Counter
from datetime import datetime

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    HRFlowable,
    KeepTogether,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from sqlalchemy import func
from xml.sax.saxutils import escape as _xml_escape

from app import db
from app.models.normalized_finding import NormalizedFinding
from app.models.report import Report


# Tester-friendly display labels for classifications (internal values unchanged).
CLASSIFICATION_LABELS = {
    "Confirmed": "Vulnerability Confirmed",
    "Needs Manual Verification": "Needs Manual Verification",
    "Not Confirmed": "Vulnerability Not Confirmed",
    "Informational": "Informational",
}


def _clabel(classification) -> str:
    return CLASSIFICATION_LABELS.get(classification, classification or "Unclassified")


def _esc(text) -> str:
    """Escape text for ReportLab Paragraph mini-markup.

    Finding descriptions and especially PoC evidence/payloads contain attack
    strings like '<script>...' — unescaped '<' breaks ReportLab's XML-ish parser
    ('unclosed tags'). Apply to any scanner/PoC-derived text placed in a Paragraph
    (slice BEFORE escaping so entities like '&lt;' aren't cut in half)."""
    return _xml_escape(str(text or ""))

# ── Constants ──────────────────────────────────────────────────────────────

_NAVY  = colors.HexColor("#1e3a5f")
_SLATE = colors.HexColor("#64748b")
_LGREY = colors.HexColor("#e2e8f0")
_FAINT = colors.HexColor("#f8fafc")

_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
_SEV_HEX   = {
    "Critical":      "#dc2626",
    "High":          "#ea580c",
    "Medium":        "#d97706",
    "Low":           "#16a34a",
    "Informational": "#2563eb",
}
_SEV_BG = {
    "Critical":      "#fef2f2",
    "High":          "#fff7ed",
    "Medium":        "#fffbeb",
    "Low":           "#f0fdf4",
    "Informational": "#eff6ff",
}

# CWE → (short name, advice) for the recommendations section
_CWE_ADVICE = {
    "CWE-79":  ("Cross-Site Scripting (XSS)",
                "Encode all user-supplied output. Apply Content-Security-Policy headers. "
                "Use framework-level auto-escaping and avoid innerHTML."),
    "CWE-89":  ("SQL Injection",
                "Use parameterised queries exclusively. Apply least-privilege DB accounts. "
                "Enable WAF SQL injection rules. Audit ORM usage for raw query construction."),
    "CWE-22":  ("Path Traversal",
                "Validate and sanitise all file-path inputs. Use allowlists for permitted "
                "directories. Avoid passing user input directly to filesystem APIs."),
    "CWE-200": ("Information Disclosure",
                "Suppress verbose error messages in production. Remove debug output. "
                "Review HTTP response headers for server version leakage."),
    "CWE-287": ("Improper Authentication",
                "Enforce MFA. Implement account-lockout policies. Use timing-safe credential "
                "comparison. Validate session tokens server-side on every request."),
    "CWE-863": ("Incorrect Authorization",
                "Adopt a deny-by-default access model. Add server-side access checks on "
                "every privileged endpoint. Audit all privilege-escalation code paths."),
    "CWE-611": ("XXE Injection",
                "Disable external entity processing in all XML parsers. Use defusedxml. "
                "Validate XML schema against a strict allowlist."),
    "CWE-918": ("Server-Side Request Forgery (SSRF)",
                "Allowlist permitted internal destinations. Block requests to link-local and "
                "private ranges. Do not pass user-controlled URLs to backend HTTP clients."),
    "CWE-20":  ("Improper Input Validation",
                "Apply input validation at every trust boundary. Reject unexpected data types, "
                "lengths, and character sets. Fail closed on invalid input."),
    "CWE-798": ("Hardcoded Credentials",
                "Store secrets in environment variables or a secrets manager. "
                "Rotate all discovered credentials immediately. Run secret-scanning in CI."),
    "CWE-352": ("Cross-Site Request Forgery (CSRF)",
                "Use synchronised anti-CSRF tokens on all state-changing requests. "
                "Validate the Origin/Referer header. Apply SameSite=Strict on session cookies."),
    "CWE-434": ("Unrestricted File Upload",
                "Validate file type by content (magic bytes), not extension. "
                "Store uploads outside the web root. Scan uploads with an AV engine."),
}


class ReportGenerator:
    """Builds PDF reports for the VulnTriage triage pipeline."""

    _REPORTS_DIR = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "..", "reports_output")
    )

    def __init__(self):
        os.makedirs(self._REPORTS_DIR, exist_ok=True)

    # ── Public API ─────────────────────────────────────────────────────────

    def generate(self, report_id: int, ai_summary: bool = False) -> str:
        """
        Build the PDF for the given Report record.
        Updates report.status and report.file_path; returns the absolute file path.
        When ai_summary is True (and a Gemini API key is configured) an optional
        AI-generated analysis section is included.
        """
        report = db.session.get(Report, report_id)
        if report is None:
            raise ValueError(f"Report {report_id} not found")

        report.status = "generating"
        db.session.commit()

        try:
            from app.models.user import User
            user     = db.session.get(User, report.user_id)
            analyst  = user.username if user else "Analyst"
            findings = self._load_findings(report.user_id, report.upload_ids or [])

            ai_analysis = None
            if ai_summary:
                from app.engines.ai_summary import AiSummaryEngine
                ai_analysis = AiSummaryEngine().summarise(findings)

            fname = f"report_{report_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.pdf"
            fpath = os.path.abspath(os.path.join(self._REPORTS_DIR, fname))
            self._build_pdf(fpath, report, findings, analyst, ai_analysis)

            report.total_findings      = len(findings)
            report.confirmed_count     = sum(1 for f in findings if f.classification == "Confirmed")
            report.needs_review_count  = sum(1 for f in findings if f.classification == "Needs Manual Verification")
            report.not_confirmed_count = sum(1 for f in findings if f.classification == "Not Confirmed")
            report.critical_count      = sum(1 for f in findings if f.severity == "Critical")
            report.high_count          = sum(1 for f in findings if f.severity == "High")
            report.medium_count        = sum(1 for f in findings if f.severity == "Medium")
            report.low_count           = sum(1 for f in findings if f.severity == "Low")
            report.file_path           = fpath
            report.status              = "completed"
            report.generated_at        = datetime.utcnow()
            db.session.commit()
            return fpath

        except Exception:
            report.status = "failed"
            db.session.commit()
            raise

    # ── Data loading ───────────────────────────────────────────────────────

    def _load_findings(self, user_id: int, upload_ids: list) -> list:
        from app.models.vulnerability import Vulnerability
        from app.models.scanner_upload import ScannerUpload
        from sqlalchemy import select

        # Base query — all findings owned by this user
        base = (
            select(NormalizedFinding)
            .join(Vulnerability,  NormalizedFinding.vulnerability_id == Vulnerability.id)
            .join(ScannerUpload,  Vulnerability.upload_id == ScannerUpload.id)
            .where(ScannerUpload.user_id == user_id)
            .order_by(func.coalesce(NormalizedFinding.cvss_score, 0.0).desc())
        )

        # Try scoped query first
        if upload_ids:
            scoped = base.where(ScannerUpload.id.in_([int(i) for i in upload_ids]))
            results = list(db.session.execute(scoped).scalars().all())
            if results:
                return results
            # Deduplication merged re-uploaded findings into earlier upload records.
            # Fall through to return ALL user findings instead.

        return list(db.session.execute(base).scalars().all())

    # ── PDF construction ───────────────────────────────────────────────────

    def _build_pdf(self, fpath: str, report: Report, findings: list, analyst: str,
                   ai_analysis: dict | None = None):
        doc = SimpleDocTemplate(
            fpath,
            pagesize=(210 * mm, 297 * mm),   # A4
            rightMargin=20 * mm, leftMargin=20 * mm,
            topMargin=22 * mm,   bottomMargin=25 * mm,
            title=report.title,
            author=analyst,
        )
        s     = self._make_styles()
        story = []
        story += self._cover(report, analyst, findings, s)
        story.append(PageBreak())
        story += self._exec_summary(findings, s)
        if ai_analysis:
            story.append(PageBreak())
            story += self._ai_section(ai_analysis, s)
        story.append(PageBreak())
        story += self._findings_section(findings, s)
        story.append(PageBreak())
        story += self._ml_section(findings, s)
        story.append(PageBreak())
        story += self._poc_section(findings, s)
        story.append(PageBreak())
        story += self._recommendations(findings, s)
        doc.build(story, onFirstPage=self._deco, onLaterPages=self._deco)

    # ── Style factory ──────────────────────────────────────────────────────

    @staticmethod
    def _make_styles() -> dict:
        base = getSampleStyleSheet()

        def ps(name, parent="Normal", **kw):
            return ParagraphStyle(name, parent=base[parent], **kw)

        return {
            "h1":    ps("vt_h1",    "Heading1", fontSize=15, textColor=_NAVY,  spaceAfter=4,  spaceBefore=10),
            "h2":    ps("vt_h2",    "Heading2", fontSize=11, textColor=_NAVY,  spaceAfter=4,  spaceBefore=6),
            "body":  ps("vt_body",  "Normal",   fontSize=9,  leading=14),
            "small": ps("vt_small", "Normal",   fontSize=8,  textColor=_SLATE, leading=12),
            "bold":  ps("vt_bold",  "Normal",   fontSize=9,  fontName="Helvetica-Bold"),
            "ctr":   ps("vt_ctr",   "Normal",   fontSize=9,  alignment=TA_CENTER),
        }

    # ── Header / footer ────────────────────────────────────────────────────

    @staticmethod
    def _deco(canvas, doc):
        canvas.saveState()
        w, h = doc.pagesize

        canvas.setStrokeColor(_NAVY)
        canvas.setLineWidth(1.5)
        canvas.line(20 * mm, h - 14 * mm, w - 20 * mm, h - 14 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(_SLATE)
        canvas.drawString(20 * mm, h - 11 * mm,
                          "VulnTriage — AI-Assisted Vulnerability Triage Report")
        canvas.drawRightString(w - 20 * mm, h - 11 * mm,
                               datetime.utcnow().strftime("%d %b %Y"))

        canvas.setStrokeColor(_LGREY)
        canvas.setLineWidth(0.5)
        canvas.line(20 * mm, 18 * mm, w - 20 * mm, 18 * mm)
        canvas.setFillColor(_SLATE)
        canvas.drawCentredString(w / 2, 12 * mm, f"Page {doc.page}")
        canvas.drawString(20 * mm, 12 * mm, "CONFIDENTIAL — Internal Use Only")
        canvas.restoreState()

    # ── Section: cover page ────────────────────────────────────────────────

    def _cover(self, report, analyst, findings, s) -> list:
        story = [Spacer(1, 22 * mm)]

        # Title banner
        banner = Table(
            [[Paragraph("VulnTriage",
                        ParagraphStyle("bh", fontSize=28, leading=32,
                                       fontName="Helvetica-Bold",
                                       textColor=colors.white, alignment=TA_CENTER))]],
            colWidths=[170 * mm],
        )
        banner.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), _NAVY),
            ("TOPPADDING",    (0, 0), (-1, -1), 16),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
        ]))
        story.append(banner)
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(
            "AI-Assisted Vulnerability Triage Report",
            ParagraphStyle("sub", fontSize=10, textColor=_SLATE, alignment=TA_CENTER),
        ))
        story.append(Spacer(1, 8 * mm))

        # Report metadata
        meta = Table([
            [Paragraph("<b>Report Title:</b>",   s["bold"]), Paragraph(report.title,              s["body"])],
            [Paragraph("<b>Generated:</b>",      s["bold"]), Paragraph(datetime.utcnow().strftime("%d %B %Y, %H:%M UTC"), s["body"])],
            [Paragraph("<b>Analyst:</b>",        s["bold"]), Paragraph(analyst,                   s["body"])],
            [Paragraph("<b>Total Findings:</b>", s["bold"]), Paragraph(str(len(findings)),        s["body"])],
        ], colWidths=[45 * mm, 125 * mm])
        meta.setStyle(TableStyle([
            ("GRID",          (0, 0), (-1, -1), 0.25, _LGREY),
            ("BACKGROUND",    (0, 0), (0, -1),  _FAINT),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(meta)
        story.append(Spacer(1, 12 * mm))

        # Severity quick-stats (4 coloured boxes)
        sev = Counter(f.severity for f in findings)
        sev_keys = ["Critical", "High", "Medium", "Low"]
        sev_hex  = ["#dc2626",  "#ea580c", "#d97706", "#16a34a"]
        sev_bg   = ["#fef2f2",  "#fff7ed", "#fffbeb", "#f0fdf4"]

        label_row = [
            Paragraph(k, ParagraphStyle(f"sl{i}", fontSize=8, fontName="Helvetica-Bold",
                                        alignment=TA_CENTER, textColor=colors.HexColor(sev_hex[i])))
            for i, k in enumerate(sev_keys)
        ]
        count_row = [
            Paragraph(str(sev.get(k, 0)),
                      ParagraphStyle(f"sc{i}", fontSize=30, leading=34,
                                     fontName="Helvetica-Bold",
                                     alignment=TA_CENTER, textColor=colors.HexColor(sev_hex[i])))
            for i, k in enumerate(sev_keys)
        ]
        st = Table([label_row, count_row], colWidths=[42.5 * mm] * 4)
        style_cmds = [
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("GRID",          (0, 0), (-1, -1), 1, colors.white),
        ]
        for i, bg in enumerate(sev_bg):
            style_cmds.append(("BACKGROUND", (i, 0), (i, -1), colors.HexColor(bg)))
        st.setStyle(TableStyle(style_cmds))
        story.append(st)
        return story

    # ── Section: executive summary ─────────────────────────────────────────

    def _exec_summary(self, findings, s) -> list:
        story = [
            Paragraph("Executive Summary", s["h1"]),
            HRFlowable(width="100%", thickness=1, color=_LGREY),
            Spacer(1, 4 * mm),
        ]

        total    = len(findings)
        conf     = sum(1 for f in findings if f.classification == "Confirmed")
        review   = sum(1 for f in findings if f.classification == "Needs Manual Verification")
        not_conf = sum(1 for f in findings if f.classification == "Not Confirmed")
        unclass  = total - conf - review - not_conf
        sev      = Counter(f.severity for f in findings)
        srcs     = sorted({src for f in findings for src in (f.scanner_sources or [])})

        intro = (
            f"This report presents the results of an automated vulnerability triage "
            f"conducted using VulnTriage. A total of <b>{total}</b> unique findings were "
            f"identified across <b>{len(srcs)}</b> scanner source(s) "
            f"(<b>{', '.join(srcs) or 'N/A'}</b>). The analysis combines multi-scanner "
            f"correlation, NVD enrichment, Random Forest ML priority prediction, and a "
            f"composite six-factor confidence scoring engine to produce final classifications."
        )
        story.append(Paragraph(intro, s["body"]))
        story.append(Spacer(1, 6 * mm))

        def pct(n): return f"{n / max(total, 1) * 100:.0f}%"

        def summary_table(rows_data, col_widths):
            hdr  = [Paragraph("<b>Category</b>", s["bold"]),
                    Paragraph("<b>Count</b>",    s["bold"]),
                    Paragraph("<b>%</b>",        s["bold"])]
            rows = [hdr] + rows_data
            t    = Table(rows, colWidths=col_widths)
            t.setStyle(TableStyle([
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
                ("FONTNAME",      (0, -1),(-1, -1), "Helvetica-Bold"),
                ("BACKGROUND",    (0, 0), (-1,  0), _NAVY),
                ("TEXTCOLOR",     (0, 0), (-1,  0), colors.white),
                ("BACKGROUND",    (0, -1),(-1, -1), colors.HexColor("#f1f5f9")),
                ("ROWBACKGROUNDS",(0, 1), (-1, -2), [colors.white, _FAINT]),
                ("GRID",          (0, 0), (-1, -1), 0.25, _LGREY),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("ALIGN",         (1, 0), (-1, -1), "RIGHT"),
            ]))
            return t

        # Classification table
        story.append(Paragraph("Classification Breakdown", s["h2"]))
        cls_rows = [
            ["Confirmed",                str(conf),     pct(conf)],
            ["Needs Manual Verification",str(review),   pct(review)],
            ["Not Confirmed",            str(not_conf), pct(not_conf)],
            ["Unclassified",             str(unclass),  pct(unclass)],
            [Paragraph("<b>Total</b>", s["bold"]), str(total), "100%"],
        ]
        story.append(summary_table(cls_rows, [90 * mm, 20 * mm, 20 * mm]))
        story.append(Spacer(1, 5 * mm))

        # Severity table
        story.append(Paragraph("Severity Breakdown", s["h2"]))
        sev_rows = [
            [Paragraph(f'<font color="{_SEV_HEX.get(sv, "#6b7280")}"><b>{sv}</b></font>', s["body"]),
             str(sev.get(sv, 0)), pct(sev.get(sv, 0))]
            for sv in _SEV_ORDER
        ]
        sev_rows.append([Paragraph("<b>Total</b>", s["bold"]), str(total), "100%"])
        story.append(summary_table(sev_rows, [90 * mm, 20 * mm, 20 * mm]))
        return story

    # ── Section: findings detail ───────────────────────────────────────────

    def _ai_section(self, ai: dict, s) -> list:
        """Render the optional Gemini-generated analysis."""
        story = [
            Paragraph("AI-Assisted Analysis", s["h1"]),
            HRFlowable(width="100%", thickness=1, color=_LGREY),
            Spacer(1, 3 * mm),
            Paragraph("<i>Generated by an AI model from the triaged findings. "
                      "Review before acting.</i>", s["small"]),
            Spacer(1, 4 * mm),
        ]

        if ai.get("executive_summary"):
            story.append(Paragraph("Overview", s["h2"]))
            story.append(Paragraph(_esc(ai["executive_summary"]), s["body"]))
            story.append(Spacer(1, 5 * mm))

        key = ai.get("key_findings") or []
        if key:
            story.append(Paragraph("Key Findings Explained", s["h2"]))
            for item in key:
                story.append(Paragraph(f"<b>{_esc(item.get('title', ''))}</b>", s["body"]))
                if item.get("risk"):
                    story.append(Paragraph(f"<b>Risk:</b> {_esc(item['risk'])}", s["small"]))
                if item.get("fix"):
                    story.append(Paragraph(f"<b>Fix:</b> {_esc(item['fix'])}", s["small"]))
                story.append(Spacer(1, 3 * mm))

        actions = ai.get("priority_actions") or []
        if actions:
            story.append(Spacer(1, 2 * mm))
            story.append(Paragraph("Prioritised Actions", s["h2"]))
            for i, a in enumerate(actions, 1):
                story.append(Paragraph(f"{i}. {_esc(a)}", s["body"]))
        return story

    def _findings_section(self, findings, s) -> list:
        story = [
            Paragraph("Findings Detail", s["h1"]),
            HRFlowable(width="100%", thickness=1, color=_LGREY),
            Spacer(1, 4 * mm),
        ]
        by_sev = {sv: [f for f in findings if f.severity == sv] for sv in _SEV_ORDER}

        for sv in _SEV_ORDER:
            grp = by_sev[sv]
            if not grp:
                continue

            hex_c = _SEV_HEX.get(sv, "#6b7280")
            bg_c  = _SEV_BG.get(sv, "#f9fafb")

            # Section sub-header
            hdr = Table(
                [[Paragraph(f'<font color="{hex_c}"><b>{sv}</b></font> Findings ({len(grp)})', s["body"])]],
                colWidths=[170 * mm],
            )
            hdr.setStyle(TableStyle([
                ("BACKGROUND",  (0, 0), (-1, -1), colors.HexColor(bg_c)),
                ("TOPPADDING",  (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING",(0,0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("LINEABOVE",   (0, 0), (-1,  0), 2, colors.HexColor(hex_c)),
            ]))
            story.append(KeepTogether([hdr, Spacer(1, 2 * mm)]))

            if sv in ("Critical", "High"):
                for f in grp:
                    story.append(self._detail_card(f, s, hex_c, bg_c))
                    story.append(Spacer(1, 3 * mm))
            else:
                story.append(self._summary_table(grp, s))
                story.append(Spacer(1, 4 * mm))

        return story

    def _detail_card(self, f, s, hex_c, bg_c) -> KeepTogether:
        """Full-detail block for a single Critical/High finding."""
        cs = f.confidence_score
        ml = f.ml_prediction

        # Title header
        title_t = Table(
            [[Paragraph(f"<b>{f.title}</b>", s["body"])]],
            colWidths=[170 * mm],
        )
        title_t.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), colors.HexColor(bg_c)),
            ("LEFTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",   (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
            ("LINEABOVE",    (0, 0), (-1,  0), 1, colors.HexColor(hex_c)),
        ]))

        url_str = (f.url[:120] + "…") if f.url and len(f.url) > 120 else (f.url or "—")
        scanner_str = f"{f.scanner_count} ({', '.join(f.scanner_sources or [])})"

        # Cells are Paragraphs (not raw strings) so long values — URLs, long
        # classification labels — wrap within their column instead of spilling
        # into the neighbouring cell.
        _lbl = ParagraphStyle("metalbl", parent=s["small"],
                              fontName="Helvetica-Bold", textColor=_NAVY)
        def _L(t): return Paragraph(str(t), _lbl)
        def _V(t): return Paragraph(_esc(str(t)), s["small"])

        meta = Table([
            [_L("CVE"),            _V(f.cve_id or "—"),  _L("CWE"),         _V(f.cwe_id or "—")],
            [_L("CVSS Score"),     _V(f"{f.cvss_score:.1f}" if f.cvss_score is not None else "—"),
             _L("Confidence"),     _V(f"{cs.score:.0f}/100" if cs else "—")],
            [_L("URL"),            _V(url_str),
             _L("ML Priority"),    _V(ml.predicted_priority if ml else "—")],
            [_L("Classification"), _V(_clabel(f.classification)),
             _L("Scanners"),       _V(scanner_str)],
        ], colWidths=[25 * mm, 57 * mm, 25 * mm, 63 * mm])
        meta.setStyle(TableStyle([
            ("GRID",          (0, 0), (-1, -1), 0.25, _LGREY),
            ("ROWBACKGROUNDS",(0, 0), (-1, -1), [colors.white, _FAINT]),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))

        parts = [title_t, meta]

        # Confidence rationale — explain *why* this classification was assigned.
        rationale = None
        if cs and isinstance(cs.factor_breakdown, dict):
            rationale = cs.factor_breakdown.get("rationale")
        if rationale:
            why_t = Table(
                [[Paragraph(f"<b>Why this classification:</b> {_esc(rationale)}", s["small"])]],
                colWidths=[170 * mm],
            )
            why_t.setStyle(TableStyle([
                ("LEFTPADDING",  (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING",   (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
                ("BACKGROUND",   (0, 0), (-1, -1), colors.HexColor("#eef4fb")),
                ("BOX",          (0, 0), (-1, -1), 0.25, _LGREY),
            ]))
            parts.append(why_t)

        if f.description:
            desc = (f.description[:550] + "…") if len(f.description) > 550 else f.description
            desc_t = Table(
                [[Paragraph(f"<b>Description:</b> {_esc(desc)}", s["small"])]],
                colWidths=[170 * mm],
            )
            desc_t.setStyle(TableStyle([
                ("LEFTPADDING",  (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING",   (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
                ("BACKGROUND",   (0, 0), (-1, -1), colors.white),
                ("BOX",          (0, 0), (-1, -1), 0.25, _LGREY),
            ]))
            parts.append(desc_t)

        if f.solution:
            sol = (f.solution[:350] + "…") if len(f.solution) > 350 else f.solution
            sol_t = Table(
                [[Paragraph(f"<b>Recommendation:</b> {_esc(sol)}", s["small"])]],
                colWidths=[170 * mm],
            )
            sol_t.setStyle(TableStyle([
                ("LEFTPADDING",  (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING",   (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
                ("BACKGROUND",   (0, 0), (-1, -1), _FAINT),
                ("BOX",          (0, 0), (-1, -1), 0.25, _LGREY),
            ]))
            parts.append(sol_t)

        outer = Table([[p] for p in parts], colWidths=[170 * mm])
        outer.setStyle(TableStyle([
            ("LEFTPADDING",  (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING",   (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
            ("BOX",          (0, 0), (-1, -1), 0.5, _LGREY),
        ]))
        return KeepTogether(outer)

    def _summary_table(self, findings, s) -> Table:
        header = [
            Paragraph("<b>#</b>",             s["bold"]),
            Paragraph("<b>Title</b>",         s["bold"]),
            Paragraph("<b>CVE / CWE</b>",     s["bold"]),
            Paragraph("<b>CVSS</b>",          s["bold"]),
            Paragraph("<b>Confidence</b>",    s["bold"]),
            Paragraph("<b>Classification</b>",s["bold"]),
            Paragraph("<b>ML Priority</b>",   s["bold"]),
        ]
        rows = [header]
        for i, f in enumerate(findings, 1):
            cs = f.confidence_score
            ml = f.ml_prediction
            title = (f.title[:70] + "…") if len(f.title) > 70 else f.title
            # Text columns are Paragraphs so they wrap; numeric columns stay
            # plain strings so the centre alignment below still applies.
            rows.append([
                str(i),
                Paragraph(_esc(title), s["small"]),
                Paragraph(_esc(f.cve_id or f.cwe_id or "—"), s["small"]),
                f"{f.cvss_score:.1f}" if f.cvss_score is not None else "—",
                f"{cs.score:.0f}" if cs else "—",
                Paragraph(_esc(_clabel(f.classification) if f.classification else "—"), s["small"]),
                Paragraph(_esc(ml.predicted_priority if ml else "—"), s["small"]),
            ])

        t = Table(rows, colWidths=[8*mm, 55*mm, 23*mm, 13*mm, 18*mm, 34*mm, 19*mm],
                  repeatRows=1)
        t.setStyle(TableStyle([
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
            ("BACKGROUND",    (0, 0), (-1,  0), _NAVY),
            ("TEXTCOLOR",     (0, 0), (-1,  0), colors.white),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, _FAINT]),
            ("GRID",          (0, 0), (-1, -1), 0.25, _LGREY),
            ("LEFTPADDING",   (0, 0), (-1, -1), 4),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("ALIGN",         (0, 0), (0, -1),  "CENTER"),
            ("ALIGN",         (3, 0), (4, -1),  "CENTER"),
        ]))
        return t

    # ── Section: ML analysis ───────────────────────────────────────────────

    def _ml_section(self, findings, s) -> list:
        story = [
            Paragraph("Machine Learning Analysis", s["h1"]),
            HRFlowable(width="100%", thickness=1, color=_LGREY),
            Spacer(1, 4 * mm),
        ]

        intro = (
            "The VulnTriage Random Forest classifier (200 estimators, pure NumPy implementation) "
            "was trained on NVD CVE translation records with CVSS v3 feature vectors. "
            "It predicts a priority label (Critical / High / Medium / Low) for each finding "
            "independently of the scanner-reported severity, using 10 normalised feature "
            "dimensions including CVSS base score, attack vector, attack complexity, "
            "privileges required, and impact metrics."
        )
        story.append(Paragraph(intro, s["body"]))
        story.append(Spacer(1, 6 * mm))

        ml_findings = [f for f in findings if f.ml_prediction]
        if ml_findings:
            story.append(Paragraph("ML Priority Distribution", s["h2"]))
            pc = Counter(f.ml_prediction.predicted_priority for f in ml_findings)
            total_ml = len(ml_findings)

            rows = [[Paragraph("<b>Priority</b>", s["bold"]),
                     Paragraph("<b>Count</b>",    s["bold"]),
                     Paragraph("<b>% of ML-predicted</b>", s["bold"])]]
            for p in ("Critical", "High", "Medium", "Low"):
                cnt = pc.get(p, 0)
                rows.append([
                    Paragraph(f'<font color="{_SEV_HEX.get(p, "#6b7280")}"><b>{p}</b></font>', s["body"]),
                    str(cnt),
                    f"{cnt / max(total_ml, 1) * 100:.1f}%",
                ])
            rows.append([Paragraph("<b>Total</b>", s["bold"]), str(total_ml), "100%"])

            t = Table(rows, colWidths=[50 * mm, 25 * mm, 60 * mm])
            t.setStyle(TableStyle([
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
                ("FONTNAME",      (0, -1),(-1, -1), "Helvetica-Bold"),
                ("BACKGROUND",    (0, 0), (-1,  0), _NAVY),
                ("TEXTCOLOR",     (0, 0), (-1,  0), colors.white),
                ("BACKGROUND",    (0, -1),(-1, -1), colors.HexColor("#f1f5f9")),
                ("ROWBACKGROUNDS",(0, 1), (-1, -2), [colors.white, _FAINT]),
                ("GRID",          (0, 0), (-1, -1), 0.5, _LGREY),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("ALIGN",         (1, 0), (-1, -1), "RIGHT"),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(t)
            story.append(Spacer(1, 6 * mm))

        # Confidence score bands
        cs_findings = [f for f in findings if f.confidence_score]
        if cs_findings:
            story.append(Paragraph("Confidence Score Distribution", s["h2"]))
            bands = {"High (>=70) → Confirmed": 0,
                     "Medium (40-69) → Needs Review": 0,
                     "Low (<40) → Not Confirmed": 0}
            for f in cs_findings:
                sc = f.confidence_score.score
                if sc >= 70:
                    bands["High (>=70) → Confirmed"] += 1
                elif sc >= 40:
                    bands["Medium (40-69) → Needs Review"] += 1
                else:
                    bands["Low (<40) → Not Confirmed"] += 1

            rows = [[Paragraph("<b>Confidence Band</b>", s["bold"]),
                     Paragraph("<b>Count</b>",           s["bold"]),
                     Paragraph("<b>Threshold Action</b>", s["bold"])]]
            for band, cnt in bands.items():
                label, _, outcome = band.partition(" → ")
                rows.append([label, str(cnt), outcome])

            t = Table(rows, colWidths=[65 * mm, 25 * mm, 50 * mm])
            t.setStyle(TableStyle([
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("FONTNAME",      (0, 0), (-1,  0), "Helvetica-Bold"),
                ("BACKGROUND",    (0, 0), (-1,  0), _NAVY),
                ("TEXTCOLOR",     (0, 0), (-1,  0), colors.white),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, _FAINT]),
                ("GRID",          (0, 0), (-1, -1), 0.5, _LGREY),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(t)

        return story

    # ── Section: PoC validation results ───────────────────────────────────────

    def _poc_section(self, findings, s) -> list:
        story = [
            Paragraph("Proof-of-Concept Validation Results", s["h1"]),
            HRFlowable(width="100%", thickness=1, color=_LGREY),
            Spacer(1, 4 * mm),
        ]

        # Collect all findings that had PoC run
        poc_findings = [(f, list(f.poc_validations.all())) for f in findings]
        poc_findings = [(f, v) for f, v in poc_findings if v]

        if not poc_findings:
            story.append(Paragraph(
                "No PoC validation checks were run for this report. "
                "Enable the PoC toggle on the Upload page and re-run the pipeline "
                "to perform live confirmation checks against the target.",
                s["body"],
            ))
            return story

        total_checks    = sum(len(v) for _, v in poc_findings)
        total_confirmed = sum(
            1 for _, vs in poc_findings for v in vs if v.result == "confirmed"
        )
        total_not       = sum(
            1 for _, vs in poc_findings for v in vs if v.result == "not_confirmed"
        )
        total_error     = sum(
            1 for _, vs in poc_findings for v in vs if v.result in ("error", "skipped")
        )

        intro = (
            f"PoC validation was performed on <b>{len(poc_findings)}</b> findings "
            f"({total_checks} total checks). "
            f"<b><font color='#16a34a'>{total_confirmed} confirmed</font></b>, "
            f"{total_not} not confirmed, "
            f"{total_error} skipped/error."
        )
        story.append(Paragraph(intro, s["body"]))
        story.append(Spacer(1, 5 * mm))

        # Summary table
        hdr = [
            Paragraph("<b>Finding</b>",          s["bold"]),
            Paragraph("<b>Check Type</b>",        s["bold"]),
            Paragraph("<b>Result</b>",            s["bold"]),
            Paragraph("<b>Evidence / Payload</b>",s["bold"]),
        ]
        rows = [hdr]

        for finding, validations in poc_findings:
            title_short = (finding.title[:45] + "…") if len(finding.title) > 45 else finding.title
            for i, v in enumerate(validations):
                # Result colour
                if v.result == "confirmed":
                    result_text = Paragraph('<font color="#16a34a"><b>CONFIRMED</b></font>', s["body"])
                elif v.result == "not_confirmed":
                    result_text = Paragraph('<font color="#6b7280">Not Confirmed</font>', s["body"])
                else:
                    result_text = Paragraph(f'<font color="#d97706">{v.result.title()}</font>', s["body"])

                evidence_text = ""
                if v.payload_used:
                    evidence_text += f"Payload: {v.payload_used[:60]}\n"
                if v.evidence:
                    evidence_text += v.evidence[:120]
                if v.error_message:
                    evidence_text += f"Error: {v.error_message[:80]}"

                rows.append([
                    Paragraph(_esc(title_short) if i == 0 else "", s["small"]),
                    Paragraph(_esc(v.validation_type) or "—", s["small"]),
                    result_text,
                    Paragraph(_esc(evidence_text[:150]) or "—", s["small"]),
                ])

        t = Table(rows, colWidths=[48*mm, 28*mm, 28*mm, 66*mm], repeatRows=1)
        t.setStyle(TableStyle([
            ("FONTSIZE",       (0, 0), (-1, -1), 8),
            ("FONTNAME",       (0, 0), (-1,  0), "Helvetica-Bold"),
            ("BACKGROUND",     (0, 0), (-1,  0), _NAVY),
            ("TEXTCOLOR",      (0, 0), (-1,  0), colors.white),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _FAINT]),
            ("GRID",           (0, 0), (-1, -1), 0.25, _LGREY),
            ("LEFTPADDING",    (0, 0), (-1, -1), 5),
            ("RIGHTPADDING",   (0, 0), (-1, -1), 5),
            ("TOPPADDING",     (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
            ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)
        story.append(Spacer(1, 5 * mm))

        # Note on confirmed findings
        if total_confirmed > 0:
            story.append(Paragraph(
                f"<b>Note:</b> {total_confirmed} finding(s) confirmed by PoC have been automatically "
                f"classified as <font color='#16a34a'><b>Confirmed</b></font> and their confidence "
                f"scores set to ≥75 regardless of other factor weights.",
                s["small"],
            ))

        return story

    # ── Section: recommendations ───────────────────────────────────────────

    def _recommendations(self, findings, s) -> list:
        story = [
            Paragraph("Recommendations", s["h1"]),
            HRFlowable(width="100%", thickness=1, color=_LGREY),
            Spacer(1, 4 * mm),
        ]

        found_cwes = Counter(f.cwe_id for f in findings if f.cwe_id)
        top_cwes   = [cwe for cwe, _ in found_cwes.most_common(10)]

        if top_cwes:
            story.append(Paragraph(
                "Recommendations are prioritised by the CWE categories most frequently "
                "observed in this scan.", s["body"],
            ))
            story.append(Spacer(1, 4 * mm))

            for cwe in top_cwes:
                cnt = found_cwes[cwe]
                label = f"({cnt} finding{'s' if cnt != 1 else ''})"
                if cwe in _CWE_ADVICE:
                    name, advice = _CWE_ADVICE[cwe]
                    block = [
                        Paragraph(f"<b>{cwe} — {name}</b> {label}", s["body"]),
                        Paragraph(advice, s["small"]),
                        Spacer(1, 3 * mm),
                    ]
                else:
                    block = [
                        Paragraph(f"<b>{cwe}</b> {label} — See MITRE CWE advisory for remediation guidance.", s["body"]),
                        Spacer(1, 3 * mm),
                    ]
                story.append(KeepTogether(block))
        else:
            story.append(Paragraph(
                "No CWE categories were mapped for the findings in this report.", s["body"],
            ))

        story.append(Spacer(1, 8 * mm))
        story.append(Paragraph("General Best Practices", s["h2"]))
        for point in [
            "Prioritise remediation of Critical and High severity findings within 24–48 hours.",
            "Review all 'Needs Manual Verification' findings before closing — these may contain true positives with limited scanner evidence.",
            "Re-scan after patching to confirm vulnerability resolution and avoid regression.",
            "Maintain a vulnerability disclosure policy and track Mean Time to Remediate (MTTR).",
            "Integrate SAST/DAST scanners into the CI/CD pipeline to detect regressions early.",
        ]:
            story.append(Paragraph(f"• {point}", s["body"]))

        story.append(Spacer(1, 10 * mm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=_LGREY))
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(
            "Generated by VulnTriage AI-Assisted Vulnerability Triage System. "
            "This document is CONFIDENTIAL and intended for the authorised analyst only.",
            s["small"],
        ))
        return story
