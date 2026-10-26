from datetime import datetime
from app import db


class ScannerUpload(db.Model):
    __tablename__ = "scanner_uploads"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    scanner_type = db.Column(db.String(50), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(30), nullable=False, default="pending")
    # status: pending | processing | completed | failed
    error_message = db.Column(db.Text, nullable=True)
    vulnerability_count = db.Column(db.Integer, default=0)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    processed_at = db.Column(db.DateTime, nullable=True)

    vulnerabilities = db.relationship(
        "Vulnerability", backref="upload", lazy="dynamic", cascade="all, delete-orphan"
    )

    SUPPORTED_SCANNERS = ["zap", "nuclei", "nessus"]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "filename": self.original_filename,
            "scanner_type": self.scanner_type,
            "file_size": self.file_size,
            "status": self.status,
            "error_message": self.error_message,
            "vulnerability_count": self.vulnerability_count,
            "uploaded_at": self.uploaded_at.isoformat(),
            "processed_at": self.processed_at.isoformat() if self.processed_at else None,
        }
