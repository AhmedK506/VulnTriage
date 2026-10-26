"""
VulnTriage CLI — AI-assisted vulnerability triage from the terminal.

Designed for penetration testers who live in the shell. Point it at a scanner
output file and it runs the full triage pipeline (parse → normalise → dedupe →
CWE map → NVD enrich → ML prioritise → confidence score → optional live PoC)
and writes a PDF report — no browser, no separate database service required.

Usage:
    python cli.py scan results.xml -s zap
    python cli.py scan results.xml -s zap --poc -o report.pdf
    python cli.py info

By default the CLI uses a single-file SQLite database (./vulntriage.db) so it
runs standalone. Point it at the shared Postgres instance with --db if desired:
    python cli.py scan results.xml --db postgresql://user:pass@host/db

NOTE: this module deliberately does NOT import the Flask app at import time.
The database URL must be set in the environment *before* app.config is
evaluated, so all `from app import ...` imports happen lazily inside commands.
"""

import os
import uuid as _uuid
import warnings

import click

# Keep the terminal output clean — the codebase uses datetime.utcnow() throughout,
# which Python 3.14 flags as deprecated. That's not actionable for a CLI user.
warnings.filterwarnings("ignore", category=DeprecationWarning)


# ── App bootstrap ────────────────────────────────────────────────────────────

def _default_sqlite_url() -> str:
    path = os.path.join(os.getcwd(), "vulntriage.db")
    # SQLAlchemy expects forward slashes even on Windows.
    return "sqlite:///" + path.replace("\\", "/")


def make_app(db_url: str | None = None):
    """Set the DB URL in the environment, then build the Flask app context."""
    if db_url:
        os.environ["DATABASE_URL"] = db_url
    else:
        os.environ.setdefault("DATABASE_URL", _default_sqlite_url())
    os.environ.setdefault("FLASK_ENV", "production")
    from app import create_app
    return create_app(os.environ["FLASK_ENV"])


# ── Terminal styling helpers ─────────────────────────────────────────────────

_SEV_COLOR = {
    "Critical": "red", "High": "bright_red", "Medium": "yellow",
    "Low": "green", "Informational": "blue",
}
_CLS_COLOR = {
    "Confirmed": "green",
    "Needs Manual Verification": "yellow",
    "Not Confirmed": "bright_black",
    "Informational": "blue",
}


def _c(text, color, bold=False):
    return click.style(str(text), fg=color, bold=bold)


# ── CLI group ────────────────────────────────────────────────────────────────

@click.group()
@click.version_option("1.0.0", prog_name="vulntriage")
def cli():
    """VulnTriage — AI-assisted vulnerability triage from the terminal."""


@cli.command()
@click.argument("scan_file", type=click.Path(exists=True, dir_okay=False))
@click.option("-s", "--scanner", type=click.Choice(["zap", "nuclei", "nessus"]),
              help="Scanner type (auto-detected from the filename if omitted).")
@click.option("--poc/--no-poc", "run_poc", default=False,
              help="Run live, non-destructive PoC validation against target URLs.")
@click.option("--scope", "poc_scope", default=None,
              help="Comma-separated authorised host(s) for active PoC probes. "
                   "When set, out-of-scope hosts are skipped. Strongly recommended.")
@click.option("--exploits", "search_exploits", is_flag=True, default=False,
              help="Look up public exploits for each finding via searchsploit (Exploit-DB).")
@click.option("--ai-summary", "ai_summary", is_flag=True, default=False,
              help="Add a Gemini-generated AI analysis section to the report (needs GEMINI_API_KEY).")
@click.option("-o", "--output", type=click.Path(dir_okay=False),
              help="Where to write the PDF report (default: leave it in reports_output/).")
@click.option("--db", "db_url",
              help="Database URL (default: ./vulntriage.db SQLite).")
@click.option("--top", default=10, show_default=True,
              help="How many findings to list in the terminal summary.")
@click.option("-q", "--quiet", is_flag=True, help="Suppress per-step progress output.")
def scan(scan_file, scanner, run_poc, poc_scope, search_exploits, ai_summary, output, db_url, top, quiet):
    """Run the full triage pipeline on a scanner output FILE and write a PDF report."""
    import shutil
    from datetime import datetime

    app = make_app(db_url)
    with app.app_context():
        from flask import current_app
        from app import db
        import app.models  # noqa: F401  (register all tables for create_all)
        from app.models.user import User
        from app.models.scanner_upload import ScannerUpload
        from app.models.normalized_finding import NormalizedFinding
        from app.models.vulnerability import Vulnerability
        from app.models.report import Report
        from app.parsers import parse_scanner_file
        from app.utils.helpers import get_scanner_type
        from app.engines.normalisation import NormalisationEngine
        from app.engines.deduplication import DeduplicationEngine
        from app.engines.cwe_mapper import CweMapper
        from app.engines.nvd_enrichment import NvdEnrichmentEngine
        from app.engines.cwe_cvss_enrichment import CweCvssEnrichmentEngine
        from app.engines.confidence_engine import ConfidenceEngine
        from app.engines.report_generator import ReportGenerator
        from app.ml.predictor import VulnerabilityPredictor

        db.create_all()

        stype = scanner or get_scanner_type(os.path.basename(scan_file))
        if not stype:
            raise click.ClickException(
                "Could not auto-detect the scanner type from the filename. "
                "Pass -s/--scanner (zap|nuclei|nessus)."
            )

        def step(msg):
            if not quiet:
                click.echo("  " + _c("›", "cyan") + " " + msg)

        click.echo(
            _c("VulnTriage", "cyan", bold=True)
            + f"  {os.path.basename(scan_file)}  →  scanner="
            + _c(stype, "magenta")
            + f"  poc={_c('on', 'green') if run_poc else _c('off', 'bright_black')}"
        )

        # Synthetic CLI user owns all CLI-created uploads/reports.
        user = User.query.filter_by(username="cli").first()
        if not user:
            user = User(username="cli", email="cli@vulntriage.local", role="analyst")
            user.set_password(_uuid.uuid4().hex)
            db.session.add(user)
            db.session.commit()

        # Copy the input into the managed upload folder (parsers read file_path).
        ext = scan_file.rsplit(".", 1)[-1].lower()
        unique = f"{_uuid.uuid4().hex}.{ext}"
        dest = os.path.join(current_app.config["UPLOAD_FOLDER"], unique)
        shutil.copyfile(scan_file, dest)

        upload = ScannerUpload(
            user_id=user.id,
            filename=unique,
            original_filename=os.path.basename(scan_file),
            scanner_type=stype,
            file_size=os.path.getsize(dest),
            file_path=dest,
            status="processing",
        )
        db.session.add(upload)
        db.session.commit()

        # ── Parse ────────────────────────────────────────────────────────────
        step("Parsing scanner output…")
        try:
            count = parse_scanner_file(upload, dest, stype)
            upload.status = "completed"
            upload.vulnerability_count = count
            upload.processed_at = datetime.utcnow()
            db.session.commit()
        except Exception as exc:
            upload.status = "failed"
            upload.error_message = str(exc)
            db.session.commit()
            raise click.ClickException(f"Parse failed: {exc}")
        step(f"Parsed {_c(count, 'white', bold=True)} raw findings")

        # ── Pipeline ─────────────────────────────────────────────────────────
        step("Normalising findings…")
        NormalisationEngine().normalise_upload(upload.id)

        step("Deduplicating…")
        DeduplicationEngine().merge_duplicates()

        step("Mapping CWEs…")
        CweMapper().map_all_unclassified()

        step("Enriching from NVD…")
        try:
            NvdEnrichmentEngine().enrich_all_pending()
        except Exception as exc:
            step(_c(f"NVD enrichment skipped ({exc})", "yellow"))

        step("Inferring CVSS vectors from CWE…")
        try:
            n_inf = CweCvssEnrichmentEngine().enrich_all_pending()
            if n_inf:
                step(_c(f"  inferred CVSS vectors for {n_inf} vector-less finding(s)", "cyan"))
        except Exception as exc:
            step(_c(f"CWE→CVSS enrichment skipped ({exc})", "yellow"))

        step("ML prioritising…")
        try:
            VulnerabilityPredictor().predict_all_unpredicted()
        except FileNotFoundError as exc:
            step(_c(f"ML model not found, skipping ({exc})", "yellow"))

        # ── Optional exploit lookup (Exploit-DB via searchsploit) ────────────
        if search_exploits:
            step("Searching Exploit-DB (searchsploit)…")
            from app.engines.exploit_search import ExploitSearchEngine, searchsploit_available
            if not searchsploit_available():
                step(_c("  searchsploit not installed — skipping", "yellow"))
            else:
                summary = ExploitSearchEngine().enrich_all()
                step(_c(f"  {summary['total_exploits']} exploit(s) across "
                        f"{summary['findings_with_exploits']} finding(s)", "cyan"))

        step("Confidence scoring…")
        ConfidenceEngine().score_all()

        # ── Optional live PoC validation ─────────────────────────────────────
        poc_count = 0
        if run_poc:
            scope_note = f" (scope: {poc_scope})" if poc_scope else _c(" (no scope set — unrestricted!)", "yellow")
            step(f"Running PoC validation (live HTTP){scope_note}…")
            from app.engines.poc_validator import PocValidator
            validator = PocValidator(scope=poc_scope)
            owned = db.session.query(ScannerUpload.id).filter_by(user_id=user.id).subquery()
            findings = (
                NormalizedFinding.query
                .join(NormalizedFinding.source_vulnerability)
                .filter(Vulnerability.upload_id.in_(owned))
                .filter(NormalizedFinding.url.isnot(None))
                .limit(25)
                .all()
            )
            for f in findings:
                try:
                    validator.validate_finding(f)
                    poc_count += 1
                except Exception:
                    pass
            db.session.commit()
            step(f"Ran {_c(poc_count, 'white', bold=True)} PoC checks")

        # ── PDF report ───────────────────────────────────────────────────────
        step("Generating PDF report…")
        rpt = Report(
            user_id=user.id,
            title=f"Triage Report — {upload.original_filename} — {datetime.utcnow():%d %b %Y}",
            report_type="pdf",
            status="pending",
            upload_ids=[upload.id],
        )
        db.session.add(rpt)
        db.session.commit()
        pdf_path = ReportGenerator().generate(rpt.id, ai_summary=ai_summary)

        if output:
            shutil.copyfile(pdf_path, output)
            pdf_path = os.path.abspath(output)

        _print_summary(rpt, user, top)
        click.echo()
        click.echo(_c("✓ PDF report:", "green", bold=True) + " " + pdf_path)


def _print_summary(rpt, user, top: int) -> None:
    from sqlalchemy import select, func
    from app import db
    from app.models.normalized_finding import NormalizedFinding
    from app.models.scanner_upload import ScannerUpload
    from app.models.vulnerability import Vulnerability

    click.echo()
    click.echo(_c("── Triage Summary ──────────────────────────────────────────", "cyan"))
    click.echo(f"  Total findings : {_c(rpt.total_findings, 'white', bold=True)}")
    click.echo(f"  Confirmed      : {_c(rpt.confirmed_count, 'green', bold=True)}")
    click.echo(f"  Needs review   : {_c(rpt.needs_review_count, 'yellow', bold=True)}")
    click.echo(f"  Not confirmed  : {_c(rpt.not_confirmed_count, 'bright_black')}")
    click.echo(
        "  Severity       : "
        + _c(f"Crit {rpt.critical_count}", "red") + "  "
        + _c(f"High {rpt.high_count}", "bright_red") + "  "
        + _c(f"Med {rpt.medium_count}", "yellow") + "  "
        + _c(f"Low {rpt.low_count}", "green")
    )

    stmt = (
        select(NormalizedFinding)
        .join(Vulnerability, NormalizedFinding.vulnerability_id == Vulnerability.id)
        .join(ScannerUpload, Vulnerability.upload_id == ScannerUpload.id)
        .where(ScannerUpload.user_id == user.id)
        .order_by(func.coalesce(NormalizedFinding.cvss_score, 0.0).desc())
        .limit(top)
    )
    rows = list(db.session.execute(stmt).scalars().all())
    if not rows:
        return

    _CLS_LABEL = {
        "Confirmed": "Vulnerability Confirmed",
        "Needs Manual Verification": "Needs Manual Verification",
        "Not Confirmed": "Vulnerability Not Confirmed",
        "Informational": "Informational",
    }
    click.echo()
    click.echo(_c(f"  Top {len(rows)} findings", "cyan"))
    click.echo("  " + _c(f"{'SEVERITY':<14} {'CVSS':>4}  {'CLASSIFICATION':<28} TITLE", "bright_black"))
    for f in rows:
        sev = f.severity or "—"
        cls = f.classification or "—"
        label = _CLS_LABEL.get(cls, cls)
        cvss = f"{f.cvss_score:.1f}" if f.cvss_score is not None else " — "
        title = (f.title or "")[:50]
        click.echo(
            "  "
            + _c(f"{sev:<14}", _SEV_COLOR.get(sev, "white")) + " "
            + f"{cvss:>4}  "
            + _c(f"{label:<28}", _CLS_COLOR.get(cls, "white")) + " "
            + title
        )


@cli.command()
@click.argument("target")
@click.option("-s", "--scanners", default="zap,nuclei",
              help="Comma-separated scanners to run: zap,nuclei (default: both). "
                   "Nessus is not auto-launched — export a .nessus report and upload it.")
@click.option("--authorise", "--authorize", "authorise", is_flag=True, default=False,
              help="REQUIRED acknowledgement that you are authorised to actively scan TARGET.")
@click.option("--exploits", "search_exploits", is_flag=True, default=False,
              help="Look up public exploits (searchsploit) after scanning.")
@click.option("--poc/--no-poc", "run_poc", default=False, help="Run PoC validation after scanning.")
@click.option("--scope", "poc_scope", default=None, help="Authorised host(s) for PoC probes.")
@click.option("-o", "--output", type=click.Path(dir_okay=False), help="Where to write the PDF report.")
@click.option("--db", "db_url", help="Database URL (default: ./vulntriage.db SQLite).")
@click.option("--top", default=10, show_default=True, help="Findings to list in the summary.")
def autoscan(target, scanners, authorise, search_exploits, run_poc, poc_scope, output, db_url, top):
    """Run scanners against TARGET, then triage the combined results.

    Example: vulntriage autoscan http://localhost:3000 -s zap,nuclei --authorise
    """
    scanner_list = [s.strip() for s in scanners.split(",") if s.strip()]
    app = make_app(db_url)
    with app.app_context():
        import uuid as _uuid
        import app.models  # noqa: F401  (register all tables for create_all)
        from app import db
        from app.models.user import User
        from app.models.report import Report
        from app.engines.auto_scan import AutoScanOrchestrator, AutoScanError

        db.create_all()

        if not authorise:
            click.echo(_c("Refusing to scan: pass --authorise to confirm you are "
                          "permitted to actively scan this target.", "red"))
            raise SystemExit(2)

        user = User.query.filter_by(username="cli").first()
        if not user:
            user = User(username="cli", email="cli@vulntriage.local", role="analyst")
            user.set_password(_uuid.uuid4().hex)
            db.session.add(user); db.session.commit()

        click.echo(_c(f"VulnTriage auto scan", "cyan", bold=True)
                   + f"  target={target}  scanners={','.join(scanner_list)}")
        try:
            res = AutoScanOrchestrator().run(
                target=target, scanners=scanner_list, user_id=user.id,
                authorise=True, search_exploits=search_exploits,
                run_poc=run_poc, poc_scope=poc_scope,
                progress=lambda m: click.echo("  " + _c("›", "cyan") + " " + m),
            )
        except AutoScanError as exc:
            click.echo(_c(f"Auto scan failed: {exc}", "red")); raise SystemExit(1)

        for name, info_ in res["scanners"].items():
            colour = "green" if info_["status"] == "ok" else "yellow"
            detail = info_.get("findings", info_.get("reason", ""))
            click.echo(f"  {name:8s}: " + _c(f"{info_['status']} ({detail})", colour))

        rpt = Report.query.get(res["report_id"]) if res.get("report_id") else None
        if rpt:
            _print_summary(rpt, user, top)
            pdf_path = rpt.file_path
            if output and pdf_path and os.path.exists(pdf_path):
                import shutil
                shutil.copyfile(pdf_path, output); pdf_path = os.path.abspath(output)
            click.echo()
            click.echo(_c("✓ PDF report:", "green", bold=True) + " " + (pdf_path or "(generation failed)"))
        else:
            click.echo(_c("Report generation failed — see findings in the DB.", "yellow"))


@cli.command()
@click.option("--db", "db_url", help="Database URL (default: ./vulntriage.db SQLite).")
@click.confirmation_option(prompt="Delete ALL CLI scan data (uploads, findings, reports)?")
def reset(db_url):
    """Clear all scan data created by the CLI, for a fresh session/target."""
    import os
    app = make_app(db_url)
    with app.app_context():
        import app.models  # noqa: F401
        from app import db
        from app.models.user import User
        from app.models.scanner_upload import ScannerUpload
        from app.models.report import Report
        db.create_all()
        user = User.query.filter_by(username="cli").first()
        if not user:
            click.echo("No CLI scan data to clear.")
            return
        uploads = ScannerUpload.query.filter_by(user_id=user.id).all()
        reports = Report.query.filter_by(user_id=user.id).all()
        for r in reports + uploads:
            if r.file_path and os.path.exists(r.file_path):
                try:
                    os.remove(r.file_path)
                except OSError:
                    pass
        nu, nr = len(uploads), len(reports)
        for r in reports:
            db.session.delete(r)
        for u in uploads:
            db.session.delete(u)
        db.session.commit()
        click.echo(_c(f"Cleared {nu} upload(s) and {nr} report(s).", "green"))


@cli.command()
@click.option("--db", "db_url", help="Database URL (default: ./vulntriage.db SQLite).")
def info(db_url):
    """Show the active database and ML model metadata."""
    app = make_app(db_url)
    with app.app_context():
        from app.ml.predictor import VulnerabilityPredictor
        click.echo(_c("Database:", "cyan") + " " + app.config["SQLALCHEMY_DATABASE_URI"])
        click.echo(_c("ML model path:", "cyan") + " " + app.config["ML_MODEL_PATH"])
        try:
            meta = VulnerabilityPredictor().model_info()
            click.echo(_c("ML model:", "cyan"))
            for k, v in meta.items():
                click.echo(f"  {k}: {v}")
        except Exception as exc:
            click.echo(_c(f"ML model: not available ({exc})", "yellow"))


if __name__ == "__main__":
    cli()
