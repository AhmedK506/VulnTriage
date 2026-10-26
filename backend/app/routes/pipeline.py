"""
Pipeline orchestration route.

Triggers the full triage pipeline for a completed upload:
  normalise -> deduplicate -> map CWEs -> enrich with NVD
  -> ML predict -> confidence score -> optional PoC validation
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models.scanner_upload import ScannerUpload
from app.engines.normalisation import NormalisationEngine
from app.engines.deduplication import DeduplicationEngine
from app.engines.cwe_mapper import CweMapper
from app.engines.nvd_enrichment import NvdEnrichmentEngine
from app.engines.cwe_cvss_enrichment import CweCvssEnrichmentEngine
from app.engines.confidence_engine import ConfidenceEngine
from app.ml.predictor import VulnerabilityPredictor

pipeline_bp = Blueprint("pipeline", __name__)


@pipeline_bp.post("/run/<int:upload_id>")
@jwt_required()
def run_pipeline(upload_id: int):
    user_id = int(get_jwt_identity())
    upload = ScannerUpload.query.filter_by(id=upload_id, user_id=user_id).first_or_404()

    if upload.status != "completed":
        return jsonify({"error": "Upload must be in 'completed' state to run pipeline"}), 400

    results = {}

    # 1. Normalise
    norm = NormalisationEngine()
    results["normalised"] = norm.normalise_upload(upload_id)

    # 2. Deduplicate (across all user findings)
    dedup = DeduplicationEngine()
    results["duplicates_removed"] = dedup.merge_duplicates()

    # 3. Map CWEs
    mapper = CweMapper()
    results["cwe_mapped"] = mapper.map_all_unclassified()

    # 4. NVD enrichment
    nvd = NvdEnrichmentEngine()
    results["nvd_enriched"] = nvd.enrich_all_pending()

    # 4b. CWE→CVSS-vector enrichment — give vector-less findings (e.g. ZAP) a
    #     plausible, data-derived CVSS vector so the ML model has real features.
    cwe_cvss = CweCvssEnrichmentEngine()
    results["cwe_vector_inferred"] = cwe_cvss.enrich_all_pending()

    # 5. ML prioritisation
    try:
        predictor = VulnerabilityPredictor()
        results["ml_predicted"] = predictor.predict_all_unpredicted()
    except FileNotFoundError as exc:
        results["ml_predicted"] = 0
        results["ml_warning"] = str(exc)

    # 5b. Optional exploit lookup (Exploit-DB via searchsploit)
    search_exploits = request.json.get("search_exploits", False) if request.is_json else False
    if search_exploits:
        from app.engines.exploit_search import ExploitSearchEngine
        results["exploit_search"] = ExploitSearchEngine().enrich_all()

    # 6. Confidence scoring
    engine = ConfidenceEngine()
    results["confidence_scored"] = engine.score_all()

    # 7. Optional PoC validation
    run_poc = request.json.get("run_poc", False) if request.is_json else False
    poc_scope = request.json.get("poc_scope") if request.is_json else None
    if run_poc:
        from app.engines.poc_validator import PocValidator
        from app.models.normalized_finding import NormalizedFinding
        from app.models.vulnerability import Vulnerability
        validator = PocValidator(scope=poc_scope)
        owned_upload_ids = db.session.query(ScannerUpload.id).filter_by(user_id=user_id).subquery()
        findings = (
            NormalizedFinding.query
            .join(NormalizedFinding.source_vulnerability)
            .filter(Vulnerability.upload_id.in_(owned_upload_ids))
            .filter(NormalizedFinding.url.isnot(None))
            .limit(20)
            .all()
        )
        poc_count = 0
        for f in findings:
            try:
                validator.validate_finding(f)
                poc_count += 1
            except Exception:
                pass
        results["poc_validated"] = poc_count
        db.session.commit()

    # 7. Auto-generate PDF report
    from app.engines.report_generator import ReportGenerator
    from app.models.report import Report
    from datetime import datetime

    rpt = Report(
        user_id=user_id,
        title=f"Triage Report — {upload.original_filename} — {datetime.utcnow().strftime('%d %b %Y')}",
        report_type="pdf",
        status="pending",
        upload_ids=[upload_id],
    )
    db.session.add(rpt)
    db.session.commit()
    try:
        ReportGenerator().generate(rpt.id, ai_summary=True)
        results["report_id"] = rpt.id
    except Exception as exc:
        results["report_warning"] = str(exc)

    return jsonify({"upload_id": upload_id, "pipeline_results": results}), 200


@pipeline_bp.get("/ml/info")
@jwt_required()
def ml_info():
    predictor = VulnerabilityPredictor()
    return jsonify(predictor.model_info()), 200


@pipeline_bp.get("/scanners")
@jwt_required()
def scanners_status():
    """Which scanners can auto mode actually run right now."""
    from app.engines.scanner_runner import scanner_availability
    return jsonify(scanner_availability()), 200


@pipeline_bp.post("/autoscan")
@jwt_required()
def auto_scan_route():
    """Start an Auto Scan in the background; returns a job_id to poll."""
    import threading
    from flask import current_app
    from app.engines.auto_scan import AutoScanOrchestrator, AutoScanError
    from app.engines.autoscan_jobs import create_job, add_step, finish_job

    user_id = int(get_jwt_identity())
    body = request.json or {}
    target = (body.get("target") or "").strip()
    scanners = body.get("scanners") or []
    search_exploits = bool(body.get("search_exploits"))
    run_poc = bool(body.get("run_poc"))
    poc_scope = body.get("poc_scope")

    if not target:
        return jsonify({"error": "target is required"}), 400
    if not body.get("authorise"):
        return jsonify({"error": "authorisation required: confirm you may actively scan this target"}), 400

    job_id = create_job(target, scanners, search_exploits, run_poc)
    app_obj = current_app._get_current_object()

    def _worker():
        # Own app context + DB session for this thread.
        with app_obj.app_context():
            try:
                results = AutoScanOrchestrator().run(
                    target=target, scanners=scanners, user_id=user_id, authorise=True,
                    search_exploits=search_exploits, run_poc=run_poc, poc_scope=poc_scope,
                    progress=lambda m: add_step(job_id, m),
                )
                finish_job(job_id, result=results)
            except AutoScanError as exc:
                finish_job(job_id, error=str(exc))
            except Exception as exc:  # noqa: BLE001 — surface unexpected errors to the UI
                finish_job(job_id, error=f"unexpected error: {exc}")
            finally:
                db.session.remove()

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"job_id": job_id}), 202


@pipeline_bp.get("/autoscan/status/<job_id>")
@jwt_required()
def auto_scan_status(job_id: str):
    from app.engines.autoscan_jobs import get_job
    job = get_job(job_id)
    if not job:
        return jsonify({"error": "unknown job"}), 404
    return jsonify(job), 200
