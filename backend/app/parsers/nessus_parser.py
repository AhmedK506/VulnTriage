"""
Nessus .nessus XML parser.

A .nessus file is XML with structure:
<NessusClientData_v2>
  <Report name="...">
    <ReportHost name="...">
      <ReportItem port="..." svc_name="..." protocol="..." severity="N" pluginID="..." pluginName="...">
        <description>...</description>
        <solution>...</solution>
        <risk_factor>...</risk_factor>
        <cvss3_base_score>...</cvss3_base_score>
        <cvss3_vector>...</cvss3_vector>
        <cve>CVE-...</cve>
        <cwe>...</cwe>
        ...
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""

import defusedxml.ElementTree as ET
from app import db
from app.models.vulnerability import Vulnerability
from app.utils.helpers import (
    normalize_severity,
    extract_cwe_id,
    sanitize_text,
)

# Nessus integer severity -> label
NESSUS_SEVERITY = {
    "0": "Informational",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Critical",
}


class NessusParser:
    def __init__(self, upload):
        self.upload = upload

    def parse(self, file_path: str) -> int:
        tree = ET.parse(file_path)
        root = tree.getroot()

        vulnerabilities = []
        for report_host in root.iter("ReportHost"):
            host = report_host.get("name", "")
            for item in report_host.iter("ReportItem"):
                vuln = self._parse_item(item, host)
                if vuln:
                    vulnerabilities.append(vuln)

        if vulnerabilities:
            db.session.bulk_save_objects(vulnerabilities)
            db.session.flush()

        return len(vulnerabilities)

    def _parse_item(self, item, host: str) -> Vulnerability | None:
        plugin_name = item.get("pluginName", "")
        severity_int = item.get("severity", "0")

        # Skip purely informational unless they have a CVE
        severity_label = NESSUS_SEVERITY.get(severity_int, "Unknown")

        def text(tag: str) -> str | None:
            el = item.find(tag)
            return sanitize_text(el.text) if el is not None else None

        name = plugin_name or text("pluginName")
        if not name:
            return None

        # CVEs – may be multiple <cve> elements
        cves = [el.text.strip() for el in item.findall("cve") if el.text]
        cve_id = cves[0] if cves else None

        raw_cwe = text("cwe")
        cwe_id = extract_cwe_id(raw_cwe) if raw_cwe else None

        cvss_score = None
        raw_score = text("cvss3_base_score") or text("cvss_base_score")
        if raw_score:
            try:
                cvss_score = float(raw_score)
            except ValueError:
                pass

        cvss_vector = text("cvss3_vector") or text("cvss_vector")

        port = item.get("port", "")
        protocol = item.get("protocol", "")
        svc_name = item.get("svc_name", "")
        url = f"{protocol}://{host}:{port}" if host and port else host

        # Extract CVSS v3 metrics from vector string if present
        references = "\n".join(
            el.text.strip() for el in item.findall("see_also") if el.text
        )

        return Vulnerability(
            upload_id=self.upload.id,
            scanner_type="nessus",
            name=name,
            description=text("description") or text("synopsis"),
            url=sanitize_text(url),
            parameter=svc_name or None,
            method=protocol.upper() if protocol else None,
            raw_severity=severity_label,
            raw_risk=severity_label,
            cve_id=cve_id,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            cvss_vector=sanitize_text(cvss_vector),
            evidence=text("plugin_output"),
            solution=text("solution"),
            reference=sanitize_text(references) if references else None,
            raw_data={
                "plugin_id": item.get("pluginID"),
                "plugin_family": item.get("pluginFamily"),
                "port": port,
                "protocol": protocol,
                "svc_name": svc_name,
                "host": host,
                "all_cves": cves,
                "risk_factor": text("risk_factor"),
                "exploit_available": text("exploit_available"),
                "exploitability_ease": text("exploitability_ease"),
            },
        )
