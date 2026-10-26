from datetime import datetime
from app import db


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    title = db.Column(db.String(300), nullable=False)
    report_type = db.Column(db.String(30), nullable=False, default="pdf")
    # pdf | docx | json

    # Summary stats embedded at generation time
    total_findings = db.Column(db.Integer, default=0)
    confirmed_count = db.Column(db.Integer, default=0)
    needs_review_count = db.Column(db.Integer, default=0)
    not_confirmed_count = db.Column(db.Integer, default=0)

    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)

    file_path = db.Column(db.String(500), nullable=True)
    status = db.Column(db.String(20), nullable=False, default="pending")
    # pending | generating | completed | failed

    generated_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # JSON blob of upload IDs that contributed to this report
    upload_ids = db.Column(db.JSON, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "title": self.title,
            "report_type": self.report_type,
            "total_findings": self.total_findings,
            "confirmed_count": self.confirmed_count,
            "needs_review_count": self.needs_review_count,
            "not_confirmed_count": self.not_confirmed_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "file_path": self.file_path,
            "status": self.status,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None,
            "created_at": self.created_at.isoformat(),
            "upload_ids": self.upload_ids,
        }
