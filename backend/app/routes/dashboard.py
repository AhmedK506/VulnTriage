from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import func
from app import db
from app.models.scanner_upload import ScannerUpload
from app.models.vulnerability import Vulnerability
from app.models.normalized_finding import NormalizedFinding
from app.models.confidence_score import ConfidenceScore

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("/summary")
@jwt_required()
def summary():
    user_id = int(get_jwt_identity())

    owned_upload_ids = (
        db.session.query(ScannerUpload.id).filter_by(user_id=user_id).subquery()
    )
    owned_vuln_ids = (
        db.session.query(Vulnerability.id)
        .filter(Vulnerability.upload_id.in_(owned_upload_ids))
        .subquery()
    )

    findings_q = NormalizedFinding.query.filter(
        NormalizedFinding.vulnerability_id.in_(owned_vuln_ids)
    )
    total_findings = findings_q.count()

    severity_counts = (
        db.session.query(NormalizedFinding.severity, func.count(NormalizedFinding.id))
        .filter(NormalizedFinding.vulnerability_id.in_(owned_vuln_ids))
        .group_by(NormalizedFinding.severity)
        .all()
    )

    classification_counts = (
        db.session.query(NormalizedFinding.classification, func.count(NormalizedFinding.id))
        .filter(NormalizedFinding.vulnerability_id.in_(owned_vuln_ids))
        .group_by(NormalizedFinding.classification)
        .all()
    )

    upload_count = ScannerUpload.query.filter_by(user_id=user_id).count()

    scanner_breakdown = (
        db.session.query(ScannerUpload.scanner_type, func.count(ScannerUpload.id))
        .filter_by(user_id=user_id)
        .group_by(ScannerUpload.scanner_type)
        .all()
    )

    return jsonify(
        {
            "total_findings": total_findings,
            "upload_count": upload_count,
            "severity_breakdown": {s: c for s, c in severity_counts},
            "classification_breakdown": {
                cl or "Unclassified": c for cl, c in classification_counts
            },
            "scanner_breakdown": {s: c for s, c in scanner_breakdown},
        }
    ), 200


@dashboard_bp.get("/top-findings")
@jwt_required()
def top_findings():
    user_id = int(get_jwt_identity())

    owned_upload_ids = (
        db.session.query(ScannerUpload.id).filter_by(user_id=user_id).subquery()
    )
    owned_vuln_ids = (
        db.session.query(Vulnerability.id)
        .filter(Vulnerability.upload_id.in_(owned_upload_ids))
        .subquery()
    )

    top = (
        NormalizedFinding.query
        .filter(NormalizedFinding.vulnerability_id.in_(owned_vuln_ids))
        .filter(NormalizedFinding.cvss_score.isnot(None))
        .order_by(NormalizedFinding.cvss_score.desc())
        .limit(10)
        .all()
    )

    return jsonify({"top_findings": [f.to_dict() for f in top]}), 200


@dashboard_bp.delete("/data")
@jwt_required()
def clear_data():
    """Delete all of the current user's scan data — uploads (which cascade to
    vulnerabilities, findings, ML/confidence/PoC records) and reports, plus their
    files. Keeps the user account and the shared CWE reference table. Used to
    start a clean session against a different target."""
    import os
    from app.models.report import Report

    user_id = int(get_jwt_identity())

    uploads = ScannerUpload.query.filter_by(user_id=user_id).all()
    reports = Report.query.filter_by(user_id=user_id).all()

    # Remove files from disk first (best-effort), then the DB rows.
    for r in reports:
        if r.file_path and os.path.exists(r.file_path):
            try:
                os.remove(r.file_path)
            except OSError:
                pass
    for u in uploads:
        if u.file_path and os.path.exists(u.file_path):
            try:
                os.remove(u.file_path)
            except OSError:
                pass

    n_uploads, n_reports = len(uploads), len(reports)
    for r in reports:
        db.session.delete(r)
    for u in uploads:                    # cascades to vulns → findings → derived
        db.session.delete(u)
    db.session.commit()

    return jsonify({
        "message": "Scan data cleared",
        "uploads_deleted": n_uploads,
        "reports_deleted": n_reports,
    }), 200
