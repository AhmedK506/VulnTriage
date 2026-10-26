"""
Nuclei JSON report parser.

Nuclei outputs one JSON object per line (JSONL) or a JSON array.
Each object looks like:
{
  "template-id": "...",
  "info": { "name": "...", "severity": "high", "tags": [...], "classification": {...} },
  "matched-at": "https://...",
  "type": "http",
  "host": "...",
  "curl-command": "...",
  "request": "...",
  "response": "..."
}
"""

import json
from app import db
from app.models.vulnerability import Vulnerability
from app.utils.helpers import (
    normalize_severity,
    extract_cwe_id,
    extract_cve_id,
    sanitize_text,
)


class NucleiParser:
    def __init__(self, upload):
        self.upload = upload

    def parse(self, file_path: str) -> int:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read().strip()

        records = self._load_records(content)
        vulnerabilities = []
        for record in records:
            vuln = self._parse_record(record)
            if vuln:
                vulnerabilities.append(vuln)

        if vulnerabilities:
            db.session.bulk_save_objects(vulnerabilities)
            db.session.flush()

        return len(vulnerabilities)

    def _load_records(self, content: str) -> list[dict]:
        """Support both JSON array and JSONL (one object per line)."""
        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        except json.JSONDecodeError:
            pass

        records = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records

    def _parse_record(self, record: dict) -> Vulnerability | None:
        info = record.get("info", {})
        name = info.get("name") or record.get("template-id")
        if not name:
            return None

        raw_severity = info.get("severity", "")
        severity = normalize_severity(raw_severity)

        classification = info.get("classification", {})
        cve_ids = classification.get("cve-id", [])
        cve_id = (cve_ids[0] if isinstance(cve_ids, list) and cve_ids else
                  extract_cve_id(str(cve_ids)))

        cwe_ids = classification.get("cwe-id", [])
        cwe_raw = cwe_ids[0] if isinstance(cwe_ids, list) and cwe_ids else None
        cwe_id = extract_cwe_id(str(cwe_raw)) if cwe_raw else None

        cvss_score = classification.get("cvss-score")
        cvss_vector = classification.get("cvss-metrics")

        url = record.get("matched-at") or record.get("host")
        method = None
        evidence = None

        # Extract from curl-command or request if available
        curl = record.get("curl-command", "")
        if curl:
            parts = curl.split()
            for i, p in enumerate(parts):
                if p == "-X" and i + 1 < len(parts):
                    method = parts[i + 1].upper()

        request_raw = record.get("request", "")
        if request_raw and not method:
            method = request_raw.split(" ")[0] if request_raw else None

        response_raw = record.get("response", "")
        if response_raw:
            evidence = sanitize_text(response_raw[:500])

        tags = info.get("tags", [])
        reference = "\n".join(info.get("reference", []) or [])

        severity_to_cvss = {
            "Critical": 9.5,
            "High": 7.5,
            "Medium": 5.0,
            "Low": 2.0,
            "Informational": 0.0,
        }
        if cvss_score is None:
            cvss_score = severity_to_cvss.get(severity)

        return Vulnerability(
            upload_id=self.upload.id,
            scanner_type="nuclei",
            name=name,
            description=sanitize_text(info.get("description")),
            url=sanitize_text(url),
            parameter=None,
            method=method,
            raw_severity=raw_severity,
            cve_id=cve_id,
            cwe_id=cwe_id,
            cvss_score=float(cvss_score) if cvss_score is not None else None,
            cvss_vector=sanitize_text(cvss_vector),
            evidence=evidence,
            solution=sanitize_text(info.get("remediation")),
            reference=sanitize_text(reference) if reference else None,
            raw_data={
                "template-id": record.get("template-id"),
                "type": record.get("type"),
                "host": record.get("host"),
                "tags": tags,
                "author": info.get("author"),
            },
        )
