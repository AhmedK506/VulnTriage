"""
OWASP ZAP XML report parser.

ZAP produces reports in two common formats:
  1. Traditional XML  – <OWASPZAPReport><site><alerts><alertitem>
  2. Modern XML       – same structure with minor variations

This parser handles both by walking all <alertitem> elements.
"""

import defusedxml.ElementTree as ET
from app import db
from app.models.vulnerability import Vulnerability
from app.utils.helpers import (
    normalize_severity,
    extract_cwe_id,
    extract_cve_id,
    sanitize_text,
)


class ZapParser:
    def __init__(self, upload):
        self.upload = upload

    def parse(self, file_path: str) -> int:
        tree = ET.parse(file_path)
        root = tree.getroot()

        vulnerabilities = []
        for alert in root.iter("alertitem"):
            vuln = self._parse_alert(alert)
            if vuln:
                vulnerabilities.append(vuln)

        if vulnerabilities:
            db.session.bulk_save_objects(vulnerabilities)
            db.session.flush()

        return len(vulnerabilities)

    def _parse_alert(self, alert) -> Vulnerability | None:
        def text(tag: str) -> str | None:
            el = alert.find(tag)
            return sanitize_text(el.text) if el is not None else None

        name = text("alert") or text("name")
        if not name:
            return None

        raw_risk = text("riskdesc") or text("risk") or ""
        # riskdesc looks like "High (3)" – extract the word
        severity_word = raw_risk.split("(")[0].strip() if raw_risk else ""

        raw_cwe = text("cweid") or text("cwe")
        # Route through extract_cwe_id so ZAP's CWE-0 placeholder (cweid=0) is
        # dropped rather than stored as a bogus "CWE-0".
        cwe_id = extract_cwe_id(f"CWE-{raw_cwe}" if raw_cwe and raw_cwe.isdigit()
                                else (raw_cwe or ""))

        # ZAP doesn't natively link CVEs; check references field
        references = text("reference") or ""
        cve_id = extract_cve_id(references)

        # CVSS: ZAP reports don't always include a CVSS score; map from risk
        risk_to_cvss = {
            "Critical": 9.5,
            "High": 7.5,
            "Medium": 5.0,
            "Low": 2.0,
            "Informational": 0.0,
        }
        severity = normalize_severity(severity_word)
        cvss_estimate = risk_to_cvss.get(severity)

        instances = alert.find("instances")
        url = None
        parameter = None
        method = None
        evidence = None

        if instances is not None:
            first = instances.find("instance")
            if first is not None:
                url = sanitize_text(self._el_text(first, "uri"))
                method = sanitize_text(self._el_text(first, "method"))
                parameter = sanitize_text(self._el_text(first, "param"))
                evidence = sanitize_text(self._el_text(first, "evidence"))
        else:
            url = text("url") or text("uri")
            parameter = text("param")
            evidence = text("evidence")

        return Vulnerability(
            upload_id=self.upload.id,
            scanner_type="zap",
            name=name,
            description=text("desc") or text("description"),
            url=url,
            parameter=parameter,
            method=method,
            raw_severity=severity_word,
            raw_risk=raw_risk,
            cve_id=cve_id,
            cwe_id=cwe_id,
            cvss_score=cvss_estimate,
            evidence=evidence,
            solution=text("solution"),
            reference=references or None,
            raw_data={
                "pluginid": text("pluginid"),
                "alertRef": text("alertRef"),
                "confidence": text("confidence"),
                "confidencedesc": text("confidencedesc"),
                "otherinfo": text("otherinfo"),
            },
        )

    @staticmethod
    def _el_text(parent, tag: str) -> str | None:
        el = parent.find(tag)
        return el.text if el is not None else None
