from datetime import datetime
from app import db


class MlPrediction(db.Model):
    """
    Stores the Random Forest model's priority prediction for a normalised finding.
    Priority labels: Critical | High | Medium | Low
    """

    __tablename__ = "ml_predictions"

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(
        db.Integer,
        db.ForeignKey("normalized_findings.id"),
        nullable=False,
        unique=True,
        index=True,
    )

    predicted_priority = db.Column(db.String(20), nullable=False)
    # Critical / High / Medium / Low

    # Probability for each class from predict_proba
    prob_critical = db.Column(db.Float, nullable=True)
    prob_high = db.Column(db.Float, nullable=True)
    prob_medium = db.Column(db.Float, nullable=True)
    prob_low = db.Column(db.Float, nullable=True)

    model_version = db.Column(db.String(50), nullable=True)
    feature_vector = db.Column(db.JSON, nullable=True)

    predicted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "predicted_priority": self.predicted_priority,
            "prob_critical": self.prob_critical,
            "prob_high": self.prob_high,
            "prob_medium": self.prob_medium,
            "prob_low": self.prob_low,
            "model_version": self.model_version,
            "predicted_at": self.predicted_at.isoformat(),
        }
