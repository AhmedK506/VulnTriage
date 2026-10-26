"""
NVD Enrichment Engine

Enriches NormalizedFindings with data from the National Vulnerability Database.
For findings that have a CVE ID, it fetches:
  - CVSS v3 base score and vector
  - Individual CVSS metric values (attack vector, complexity, etc.)
  - Exploit availability

Two modes:
  1. Local mode – streams the pre-downloaded NVD JSON 2.0 feeds in ml_data/nvd/
     (CVE-YYYY.json[.xz]). The feeds are read straight from .xz with ijson
     (constant memory) — the box is disk-full, so they are never decompressed to
     disk. Only the CVE IDs actually being looked up are kept, so memory stays
     bounded by the scan size, not the ~108k-record feed.
  2. API mode  – live queries to api.nvd.nist.gov (requires NVD_API_KEY), used as
     a fallback when a CVE is not in the local feeds.
"""

import lzma
import os
import time
import ijson
import requests
from flask import current_app
from app import db
from app.models.normalized_finding import NormalizedFinding
from app.utils.helpers import cvss_score_to_severity


class NvdEnrichmentEngine:
    # NVD API rate limit: 5 req/30s without key, 50 req/30s with key
    _RATE_LIMIT_DELAY = 0.7  # seconds between API requests

    def __init__(self):
        # Lazily-built {CVE-ID: trimmed record} cache and the set of IDs we have
        # already scanned the feeds for (so repeat lookups don't rescan).
        self._local_index: dict | None = None
        self._indexed_ids: set | None = None

    def enrich_finding(self, finding: NormalizedFinding) -> bool:
        """Enrich a single finding. Returns True if data was added."""
        if not finding.cve_id:
            return False
        if finding.nvd_enriched:
            return False

        cve_data = self._lookup_cve(finding.cve_id)
        if not cve_data:
            return False

        self._apply_cve_data(finding, cve_data)
        finding.nvd_enriched = True
        db.session.add(finding)
        return True

    def enrich_all_pending(self) -> int:
        """Enrich all findings with CVE IDs that haven't been enriched yet."""
        pending = NormalizedFinding.query.filter(
            NormalizedFinding.cve_id.isnot(None),
            NormalizedFinding.nvd_enriched.is_(False),
        ).all()

        # Warm the local index once for every wanted CVE, so the feeds are
        # streamed a single time instead of per finding.
        self._extend_local_index({f.cve_id.upper() for f in pending if f.cve_id})

        enriched = 0
        for finding in pending:
            if self.enrich_finding(finding):
                enriched += 1

        db.session.commit()
        return enriched

    def _lookup_cve(self, cve_id: str) -> dict | None:
        """Try local feeds first, then the NVD API."""
        local = self._lookup_local(cve_id)
        if local:
            return local
        return self._lookup_api(cve_id)

    def _lookup_local(self, cve_id: str) -> dict | None:
        """Return the trimmed NVD record for cve_id from the local feeds."""
        cid = cve_id.upper()
        if self._indexed_ids is None or cid not in self._indexed_ids:
            self._extend_local_index({cid})
        return (self._local_index or {}).get(cid)

    def _extend_local_index(self, wanted: set) -> None:
        """Stream the NVD feeds once, caching trimmed records for `wanted` IDs.

        Reads .json and .json.xz feeds via ijson (constant memory) and keeps only
        the requested CVEs, so memory stays proportional to the scan, not the feed.
        """
        if self._local_index is None:
            self._local_index, self._indexed_ids = {}, set()
        todo = {w for w in wanted if w and w not in self._indexed_ids}
        if not todo:
            return
        self._indexed_ids |= todo

        nvd_dir = self._nvd_dir()
        if not nvd_dir or not os.path.isdir(nvd_dir):
            return

        remaining = set(todo)
        for fname in sorted(os.listdir(nvd_dir)):
            if not remaining:
                break
            if fname.endswith(".json.xz"):
                opener = lambda p: lzma.open(p, "rt", encoding="utf-8")
            elif fname.endswith(".json"):
                opener = lambda p: open(p, "rt", encoding="utf-8")
            else:
                continue
            self._scan_feed(os.path.join(nvd_dir, fname), opener, remaining)

    @staticmethod
    def _nvd_dir() -> str | None:
        """Locate ml_data/nvd via the ML_MODEL_PATH config (.../ml_data/models),
        matching the convention used by cwe_cvss_enrichment; falls back to a
        path relative to this file."""
        model_dir = current_app.config.get("ML_MODEL_PATH")
        if model_dir:
            return os.path.join(os.path.dirname(model_dir), "nvd")
        here = os.path.dirname(os.path.abspath(__file__))  # .../backend/app/engines
        return os.path.normpath(
            os.path.join(here, "..", "..", "..", "ml_data", "nvd")
        )

    def _scan_feed(self, path: str, opener, remaining: set) -> None:
        # NVD 2.0 feeds nest records under "cve_items"; API-style dumps use
        # "vulnerabilities" (each item wrapping a "cve"). Try both.
        for prefix in ("cve_items.item", "vulnerabilities.item"):
            found_any = False
            try:
                with opener(path) as fh:
                    for item in ijson.items(fh, prefix):
                        found_any = True
                        cve = item.get("cve", item)
                        cid = (cve.get("id") or "").upper()
                        if cid in remaining:
                            self._local_index[cid] = {
                                "metrics": cve.get("metrics", {}),
                                "weaknesses": cve.get("weaknesses", []),
                                "vulnStatus": cve.get("vulnStatus", ""),
                                "cisaExploitAdd": cve.get("cisaExploitAdd"),
                            }
                            remaining.discard(cid)
                            if not remaining:
                                return
            except (OSError, ijson.JSONError):
                found_any = False
            if found_any:
                return  # correct prefix for this file; no need to try the other

    def _lookup_api(self, cve_id: str) -> dict | None:
        base_url = current_app.config.get("NVD_BASE_URL")
        if not base_url:
            return None
        api_key = current_app.config.get("NVD_API_KEY", "")

        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        try:
            time.sleep(self._RATE_LIMIT_DELAY)  # rate-limit only real API calls
            response = requests.get(
                base_url,
                params={"cveId": cve_id},
                headers=headers,
                timeout=10,
            )
            if response.status_code != 200:
                return None
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return vulns[0].get("cve")
        except requests.RequestException:
            pass
        return None

    @staticmethod
    def _cwe_from_weaknesses(weaknesses: list) -> str | None:
        """Extract a CWE-NNN id from an NVD weaknesses block, preferring the
        'Primary' weakness. Ignores non-CWE markers (NVD-CWE-noinfo/Other)."""
        fallback = None
        for w in weaknesses or []:
            for d in w.get("description", []):
                val = (d.get("value") or "").strip()
                if val.startswith("CWE-") and val[4:].isdigit():
                    if (w.get("type") or "").lower() == "primary":
                        return val
                    fallback = fallback or val
        return fallback

    @classmethod
    def _apply_cve_data(cls, finding: NormalizedFinding, cve: dict) -> None:
        """Write NVD CVE data fields onto the finding."""
        metrics = cve.get("metrics", {})

        # Prefer CVSS v3.1, fallback to v3.0
        cvss_v3 = (
            metrics.get("cvssMetricV31", [{}])[0].get("cvssData")
            or metrics.get("cvssMetricV30", [{}])[0].get("cvssData")
            or {}
        )

        # NVD's official CVSS v3 for this exact CVE is authoritative, so apply the
        # score, severity, vector and all sub-metrics together as one consistent
        # set — never leave a scanner's heuristic score paired with NVD's vector.
        # Only touch these when NVD actually has a v3 vector; otherwise leave any
        # scanner-provided CVSS data intact (don't null it out).
        vector = cvss_v3.get("vectorString")
        if vector:
            finding.cvss_vector = vector
            score = cvss_v3.get("baseScore")
            if score is not None:
                finding.cvss_score = float(score)
                finding.severity = cvss_score_to_severity(finding.cvss_score)
            finding.attack_vector = cvss_v3.get("attackVector")
            finding.attack_complexity = cvss_v3.get("attackComplexity")
            finding.privileges_required = cvss_v3.get("privilegesRequired")
            finding.user_interaction = cvss_v3.get("userInteraction")
            finding.scope = cvss_v3.get("scope")
            finding.confidentiality_impact = cvss_v3.get("confidentialityImpact")
            finding.integrity_impact = cvss_v3.get("integrityImpact")
            finding.availability_impact = cvss_v3.get("availabilityImpact")

        # Backfill an authoritative CWE from NVD when the scanner gave none —
        # helps findings that carry a CVE but no weakness class (feeds the CWE
        # confidence factor and the CWE->CVSS vector inference downstream). A
        # scanner-provided CWE is left untouched.
        if not finding.cwe_id:
            cwe = cls._cwe_from_weaknesses(cve.get("weaknesses", []))
            if cwe:
                finding.cwe_id = cwe

        # Check for known exploits via CISA KEV data embedded in NVD feed
        cisa = cve.get("cisaExploitAdd")
        vuln_status = cve.get("vulnStatus", "")
        finding.exploit_available = bool(cisa) or "exploit" in vuln_status.lower()
