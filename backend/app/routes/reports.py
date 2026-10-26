from datetime import datetime

from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity

from app import db
from app.models.report import Report

reports_bp = Blueprint("reports", __name__)


@reports_bp.get("/")
@jwt_required()
def list_reports():
    user_id = int(get_jwt_identity())
    reports = (
        Report.query.filter_by(user_id=user_id)
        .order_by(Report.created_at.desc())
        .all()
    )
    return jsonify({"reports": [r.to_dict() for r in reports]}), 200


@reports_bp.post("/generate")
@jwt_required()
def generate_report():
    user_id = int(get_jwt_identity())
    data = request.get_json() or {}

    upload_ids  = data.get("upload_ids") or []
    report_type = data.get("report_type", "pdf")
    # Include the optional Gemini analysis when enabled (default on); it is a
    # no-op unless GEMINI_API_KEY is configured, so this is always safe.
    ai_summary  = bool(data.get("ai_summary", True))
    title = data.get(
        "title",
        f"Vulnerability Triage Report — {datetime.utcnow().strftime('%d %b %Y %H:%M')}",
    )

    report = Report(
        user_id=user_id,
        title=title,
        report_type=report_type,
        status="pending",
        upload_ids=upload_ids or None,
    )
    db.session.add(report)
    db.session.commit()

    from app.engines.report_generator import ReportGenerator
    generator = ReportGenerator()
    try:
        generator.generate(report.id, ai_summary=ai_summary)
    except Exception as exc:
        return jsonify({"error": f"Report generation failed: {exc}"}), 500

    return jsonify({"report": report.to_dict()}), 201


@reports_bp.get("/<int:report_id>")
@jwt_required()
def get_report(report_id: int):
    user_id = int(get_jwt_identity())
    report = Report.query.filter_by(id=report_id, user_id=user_id).first_or_404()
    return jsonify(report.to_dict()), 200


@reports_bp.get("/<int:report_id>/download")
@jwt_required()
def download_report(report_id: int):
    import os
    user_id = int(get_jwt_identity())
    report = Report.query.filter_by(id=report_id, user_id=user_id).first_or_404()

    if report.status != "completed" or not report.file_path:
        return jsonify({"error": "Report not ready"}), 400

    if not os.path.exists(report.file_path):
        return jsonify({"error": "Report file not found on disk"}), 404

    mime = "application/pdf" if report.report_type == "pdf" else "application/octet-stream"
    return send_file(
        report.file_path,
        mimetype=mime,
        as_attachment=True,
        download_name=f"vuln_report_{report.id}.{report.report_type}",
    )
