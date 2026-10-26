from datetime import datetime
from app import db


class ConfidenceScore(db.Model):
    """
    Confidence Engine output for a normalised finding.
    Score 0-100 determines classification into:
      70-100 -> Confirmed
      40-69  -> Needs Manual Verification
      0-39   -> Not Confirmed
    """

    __tablename__ = "confidence_scores"

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(
        db.Integer,
        db.ForeignKey("normalized_findings.id"),
        nullable=False,
        unique=True,
        index=True,
    )

    score = db.Column(db.Float, nullable=False)
    classification = db.Column(db.String(30), nullable=False)

    # Individual factor contributions (0-100 each, weighted during aggregation)
    scanner_agreement_score = db.Column(db.Float, nullable=True)
    cve_availability_score = db.Column(db.Float, nullable=True)
    cwe_mapping_score = db.Column(db.Float, nullable=True)
    ml_priority_score = db.Column(db.Float, nullable=True)
    exploit_availability_score = db.Column(db.Float, nullable=True)
    poc_validation_score = db.Column(db.Float, nullable=True)

    factor_breakdown = db.Column(db.JSON, nullable=True)

    calculated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "score": self.score,
            "classification": self.classification,
            "scanner_agreement_score": self.scanner_agreement_score,
            "cve_availability_score": self.cve_availability_score,
            "cwe_mapping_score": self.cwe_mapping_score,
            "ml_priority_score": self.ml_priority_score,
            "exploit_availability_score": self.exploit_availability_score,
            "poc_validation_score": self.poc_validation_score,
            "factor_breakdown": self.factor_breakdown,
            "calculated_at": self.calculated_at.isoformat(),
        }
