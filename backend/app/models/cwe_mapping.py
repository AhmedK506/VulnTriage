from app import db


class CweMapping(db.Model):
    """
    Reference table of CWE entries loaded from the CWE catalogue.
    Used by the CWE Mapper to enrich findings with structured weakness data.
    """

    __tablename__ = "cwe_mappings"

    id = db.Column(db.Integer, primary_key=True)
    cwe_id = db.Column(db.String(20), unique=True, nullable=False, index=True)
    name = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(100), nullable=True)
    # OWASP Top 10 mapping if applicable
    owasp_category = db.Column(db.String(100), nullable=True)
    severity_hint = db.Column(db.String(20), nullable=True)

    def to_dict(self) -> dict:
        return {
            "cwe_id": self.cwe_id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "owasp_category": self.owasp_category,
            "severity_hint": self.severity_hint,
        }
