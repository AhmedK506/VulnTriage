from datetime import datetime
from app import db


class PocValidation(db.Model):
    """
    Records a controlled Proof-of-Concept validation attempt for a finding.
    PoC validation is optional and only covers safe, non-destructive checks.
    """

    __tablename__ = "poc_validations"

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(
        db.Integer,
        db.ForeignKey("normalized_findings.id"),
        nullable=False,
        index=True,
    )

    validation_type = db.Column(db.String(50), nullable=False)
    # e.g. header_check | response_analysis | payload_reflection | port_check

    target_url = db.Column(db.Text, nullable=True)
    payload_used = db.Column(db.Text, nullable=True)
    http_method = db.Column(db.String(10), nullable=True)

    result = db.Column(db.String(20), nullable=False)
    # confirmed | not_confirmed | error | skipped

    response_code = db.Column(db.Integer, nullable=True)
    response_snippet = db.Column(db.Text, nullable=True)
    evidence = db.Column(db.Text, nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    validated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "validation_type": self.validation_type,
            "target_url": self.target_url,
            "payload_used": self.payload_used,
            "http_method": self.http_method,
            "result": self.result,
            "response_code": self.response_code,
            "response_snippet": self.response_snippet,
            "evidence": self.evidence,
            "error_message": self.error_message,
            "validated_at": self.validated_at.isoformat(),
        }
