import os
import uuid
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models.user import User
from app.models.scanner_upload import ScannerUpload
from app.utils.helpers import allowed_file, get_scanner_type
from app.parsers import parse_scanner_file

upload_bp = Blueprint("upload", __name__)


@upload_bp.post("/")
@jwt_required()
def upload_file():
    user_id = int(get_jwt_identity())

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename, current_app.config["ALLOWED_EXTENSIONS"]):
        return jsonify({"error": "File type not supported. Allowed: xml, json, jsonl, csv, nessus"}), 400

    scanner_type = request.form.get("scanner_type", "").lower()
    if scanner_type not in ScannerUpload.SUPPORTED_SCANNERS:
        # Attempt auto-detection from filename/extension
        scanner_type = get_scanner_type(file.filename)
        if not scanner_type:
            return jsonify(
                {"error": f"scanner_type required. Supported: {ScannerUpload.SUPPORTED_SCANNERS}"}
            ), 400

    # Save file with unique name to avoid collisions
    ext = file.filename.rsplit(".", 1)[-1].lower()
    unique_name = f"{uuid.uuid4().hex}.{ext}"
    save_path = os.path.join(current_app.config["UPLOAD_FOLDER"], unique_name)
    file.save(save_path)

    file_size = os.path.getsize(save_path)

    upload = ScannerUpload(
        user_id=user_id,
        filename=unique_name,
        original_filename=file.filename,
        scanner_type=scanner_type,
        file_size=file_size,
        file_path=save_path,
        status="processing",
    )
    db.session.add(upload)
    db.session.commit()

    try:
        vuln_count = parse_scanner_file(upload, save_path, scanner_type)
        upload.status = "completed"
        upload.vulnerability_count = vuln_count
        upload.processed_at = datetime.utcnow()
    except Exception as exc:
        upload.status = "failed"
        upload.error_message = str(exc)
        current_app.logger.exception("Parse error for upload %s", upload.id)

    db.session.commit()
    return jsonify({"upload": upload.to_dict()}), 201


@upload_bp.get("/")
@jwt_required()
def list_uploads():
    user_id = int(get_jwt_identity())
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), 100)

    pagination = (
        ScannerUpload.query.filter_by(user_id=user_id)
        .order_by(ScannerUpload.uploaded_at.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )

    return jsonify(
        {
            "uploads": [u.to_dict() for u in pagination.items],
            "total": pagination.total,
            "pages": pagination.pages,
            "page": page,
        }
    ), 200


@upload_bp.get("/<int:upload_id>")
@jwt_required()
def get_upload(upload_id: int):
    user_id = int(get_jwt_identity())
    upload = ScannerUpload.query.filter_by(id=upload_id, user_id=user_id).first_or_404()
    return jsonify(upload.to_dict()), 200


@upload_bp.delete("/<int:upload_id>")
@jwt_required()
def delete_upload(upload_id: int):
    user_id = int(get_jwt_identity())
    upload = ScannerUpload.query.filter_by(id=upload_id, user_id=user_id).first_or_404()

    if os.path.exists(upload.file_path):
        os.remove(upload.file_path)

    db.session.delete(upload)
    db.session.commit()
    return jsonify({"message": "Upload deleted"}), 200
