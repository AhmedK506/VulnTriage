from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models.normalized_finding import NormalizedFinding
from app.models.scanner_upload import ScannerUpload
from app.models.ml_prediction import MlPrediction
from app.models.confidence_score import ConfidenceScore

vuln_bp = Blueprint("vulnerabilities", __name__)


def _user_owns_finding(finding: NormalizedFinding, user_id: int) -> bool:
    """Check the finding traces back to an upload owned by this user."""
    vuln = finding.source_vulnerability
    return vuln and vuln.upload.user_id == user_id


@vuln_bp.get("/")
@jwt_required()
def list_findings():
    user_id = int(get_jwt_identity())
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)

    severity = request.args.get("severity")
    classification = request.args.get("classification")
    upload_id = request.args.get("upload_id", type=int)

    # Join through vulnerabilities -> scanner_uploads to filter by user
    query = (
        NormalizedFinding.query
        .join(NormalizedFinding.source_vulnerability)
        .join(ScannerUpload, ScannerUpload.id == db.Column("upload_id"))
        .filter(ScannerUpload.user_id == user_id)
    )

    # Simpler approach: sub-query on upload ids the user owns
    owned_upload_ids = db.session.query(ScannerUpload.id).filter_by(user_id=user_id).subquery()
    from app.models.vulnerability import Vulnerability
    query = (
        NormalizedFinding.query
        .join(NormalizedFinding.source_vulnerability)
        .filter(Vulnerability.upload_id.in_(owned_upload_ids))
    )

    if severity:
        query = query.filter(NormalizedFinding.severity == severity)
    if classification:
        query = query.filter(NormalizedFinding.classification == classification)
    if upload_id:
        query = query.filter(Vulnerability.upload_id == upload_id)

    query = query.order_by(NormalizedFinding.cvss_score.desc().nullslast())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    results = []
    for f in pagination.items:
        d = f.to_dict()
        if f.ml_prediction:
            d["ml_prediction"] = f.ml_prediction.to_dict()
        if f.confidence_score:
            d["confidence_score"] = f.confidence_score.to_dict()
        results.append(d)

    return jsonify(
        {
            "findings": results,
            "total": pagination.total,
            "pages": pagination.pages,
            "page": page,
        }
    ), 200


@vuln_bp.get("/<int:finding_id>")
@jwt_required()
def get_finding(finding_id: int):
    user_id = int(get_jwt_identity())
    finding = NormalizedFinding.query.get_or_404(finding_id)

    if not _user_owns_finding(finding, user_id):
        return jsonify({"error": "Not found"}), 404

    d = finding.to_dict()
    if finding.ml_prediction:
        d["ml_prediction"] = finding.ml_prediction.to_dict()
    if finding.confidence_score:
        d["confidence_score"] = finding.confidence_score.to_dict()
    d["poc_validations"] = [p.to_dict() for p in finding.poc_validations]
    return jsonify(d), 200


@vuln_bp.patch("/<int:finding_id>/classification")
@jwt_required()
def update_classification(finding_id: int):
    """Allow an analyst to manually override the classification."""
    user_id = int(get_jwt_identity())
    finding = NormalizedFinding.query.get_or_404(finding_id)

    if not _user_owns_finding(finding, user_id):
        return jsonify({"error": "Not found"}), 404

    data = request.get_json(silent=True) or {}
    new_class = data.get("classification")
    valid = {"Confirmed", "Needs Manual Verification", "Not Confirmed"}
    if new_class not in valid:
        return jsonify({"error": f"classification must be one of {valid}"}), 400

    finding.classification = new_class
    db.session.commit()
    return jsonify({"id": finding.id, "classification": finding.classification}), 200
