from datetime import datetime
from app import db


class NormalizedFinding(db.Model):
    """
    Deduplicated, normalised representation of a vulnerability.
    Multiple raw Vulnerability records from different scanners may map
    to a single NormalizedFinding when they describe the same issue.
    """

    __tablename__ = "normalized_findings"

    id = db.Column(db.Integer, primary_key=True)
    # Primary source vulnerability
    vulnerability_id = db.Column(
        db.Integer, db.ForeignKey("vulnerabilities.id"), nullable=False, unique=True
    )

    # Deduplication group — findings with the same group_hash are the same issue
    group_hash = db.Column(db.String(64), nullable=False, index=True)
    scanner_count = db.Column(db.Integer, default=1, nullable=False)
    scanner_sources = db.Column(db.JSON, nullable=True)  # list of scanner names

    # Normalised fields
    title = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=True)
    url = db.Column(db.Text, nullable=True)
    parameter = db.Column(db.String(255), nullable=True)
    method = db.Column(db.String(10), nullable=True)

    # Unified severity (Critical/High/Medium/Low/Informational)
    severity = db.Column(db.String(20), nullable=False, default="Unknown")

    cve_id = db.Column(db.String(30), nullable=True, index=True)
    cwe_id = db.Column(db.String(30), nullable=True)
    cvss_score = db.Column(db.Float, nullable=True)
    cvss_vector = db.Column(db.String(200), nullable=True)

    # CVSS v3 metric breakdown (populated by NVD enrichment)
    attack_vector = db.Column(db.String(20), nullable=True)
    attack_complexity = db.Column(db.String(10), nullable=True)
    privileges_required = db.Column(db.String(10), nullable=True)
    user_interaction = db.Column(db.String(10), nullable=True)
    scope = db.Column(db.String(10), nullable=True)
    confidentiality_impact = db.Column(db.String(10), nullable=True)
    integrity_impact = db.Column(db.String(10), nullable=True)
    availability_impact = db.Column(db.String(10), nullable=True)

    # NVD enrichment flags
    nvd_enriched = db.Column(db.Boolean, default=False)
    exploit_available = db.Column(db.Boolean, default=False)

    solution = db.Column(db.Text, nullable=True)
    reference = db.Column(db.Text, nullable=True)

    # Final triage outcome
    classification = db.Column(db.String(30), nullable=True)
    # classification: Confirmed | Needs Manual Verification | Not Confirmed

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    ml_prediction = db.relationship(
        "MlPrediction", backref="finding", uselist=False, cascade="all, delete-orphan"
    )
    confidence_score = db.relationship(
        "ConfidenceScore", backref="finding", uselist=False, cascade="all, delete-orphan"
    )
    poc_validations = db.relationship(
        "PocValidation", backref="finding", lazy="dynamic", cascade="all, delete-orphan"
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "vulnerability_id": self.vulnerability_id,
            "group_hash": self.group_hash,
            "scanner_count": self.scanner_count,
            "scanner_sources": self.scanner_sources,
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "severity": self.severity,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "attack_vector": self.attack_vector,
            "attack_complexity": self.attack_complexity,
            "privileges_required": self.privileges_required,
            "user_interaction": self.user_interaction,
            "scope": self.scope,
            "confidentiality_impact": self.confidentiality_impact,
            "integrity_impact": self.integrity_impact,
            "availability_impact": self.availability_impact,
            "nvd_enriched": self.nvd_enriched,
            "exploit_available": self.exploit_available,
            "classification": self.classification,
            "solution": self.solution,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
