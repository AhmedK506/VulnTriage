"""
Normalisation Engine

Takes raw Vulnerability rows from the database and produces NormalizedFinding rows.
Normalisation ensures every finding has:
  - A consistent severity label
  - Parsed CVSS data
  - Cleaned text fields
  - A deduplication hash via the Deduplication Engine
"""

from app import db
from app.models.vulnerability import Vulnerability
from app.models.normalized_finding import NormalizedFinding
from app.engines.deduplication import DeduplicationEngine
from app.utils.helpers import (
    normalize_severity,
    cvss_score_to_severity,
    extract_cwe_id,
    extract_cve_id,
    sanitize_text,
    html_to_text,
)


class NormalisationEngine:
    def __init__(self):
        self.dedup = DeduplicationEngine()

    def normalise_upload(self, upload_id: int) -> int:
        """
        Normalise all raw vulnerabilities for a given upload.
        Returns count of NormalizedFinding rows created.
        """
        raw_vulns = Vulnerability.query.filter_by(upload_id=upload_id).all()
        count = 0
        for vuln in raw_vulns:
            if vuln.normalized_finding:
                continue  # already normalised
            finding = self._normalise_one(vuln)
            db.session.add(finding)
            count += 1

        db.session.commit()
        return count

    def _normalise_one(self, vuln: Vulnerability) -> NormalizedFinding:
        # Determine best severity
        if vuln.cvss_score is not None:
            severity = cvss_score_to_severity(vuln.cvss_score)
        else:
            severity = normalize_severity(vuln.raw_severity or vuln.raw_risk or "")

        # Normalise CWE — run the scanner's own value through extract_cwe_id too,
        # so placeholders like CWE-0 are dropped (-> None) and the mapper/NVD can
        # fill a real weakness class instead of treating the placeholder as valid.
        cwe_id = extract_cwe_id(vuln.cwe_id or "") or extract_cwe_id(vuln.description or "")

        # Normalise CVE
        cve_id = vuln.cve_id or extract_cve_id(vuln.reference or "")

        group_hash = self.dedup.compute_hash(
            name=vuln.name,
            url=vuln.url,
            parameter=vuln.parameter,
            cwe_id=cwe_id,
        )

        return NormalizedFinding(
            vulnerability_id=vuln.id,
            group_hash=group_hash,
            scanner_count=1,
            scanner_sources=[vuln.scanner_type],
            title=sanitize_text(vuln.name, 500),
            description=html_to_text(vuln.description),
            url=sanitize_text(vuln.url),
            parameter=sanitize_text(vuln.parameter, 255),
            method=vuln.method,
            severity=severity,
            cve_id=cve_id,
            cwe_id=cwe_id,
            cvss_score=vuln.cvss_score,
            cvss_vector=vuln.cvss_vector,
            solution=html_to_text(vuln.solution),
            reference=sanitize_text(vuln.reference),
        )
