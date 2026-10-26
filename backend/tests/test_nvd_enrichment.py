"""NVD enrichment tests.

Exercise the pure record-application path on an unpersisted NormalizedFinding
with a synthetic NVD 2.0 record, so they need no database, app context, or the
git-ignored ml_data/nvd feeds. (The .xz streaming/lookup path is covered by the
live pipeline, not here, since it depends on the large local feeds.)
"""

from app.models.normalized_finding import NormalizedFinding
from app.engines.nvd_enrichment import NvdEnrichmentEngine


# Minimal record mimicking the NVD 2.0 feed shape used by _apply_cve_data.
CVE_REC = {
    "metrics": {"cvssMetricV31": [{"cvssData": {
        "baseScore": 9.8,
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "attackVector": "NETWORK", "attackComplexity": "LOW",
        "privilegesRequired": "NONE", "userInteraction": "NONE",
        "scope": "UNCHANGED", "confidentialityImpact": "HIGH",
        "integrityImpact": "HIGH", "availabilityImpact": "HIGH",
    }}]},
    "weaknesses": [
        {"type": "Secondary", "description": [{"lang": "en", "value": "CWE-20"}]},
        {"type": "Primary", "description": [{"lang": "en", "value": "CWE-89"}]},
    ],
    "vulnStatus": "Analyzed",
}


def test_cwe_from_weaknesses_prefers_primary():
    assert NvdEnrichmentEngine._cwe_from_weaknesses(CVE_REC["weaknesses"]) == "CWE-89"


def test_cwe_from_weaknesses_ignores_non_cwe_markers():
    ws = [{"type": "Primary", "description": [{"lang": "en", "value": "NVD-CWE-noinfo"}]}]
    assert NvdEnrichmentEngine._cwe_from_weaknesses(ws) is None
    assert NvdEnrichmentEngine._cwe_from_weaknesses([]) is None


def test_cwe_from_weaknesses_secondary_fallback():
    ws = [{"type": "Secondary", "description": [{"lang": "en", "value": "CWE-611"}]}]
    assert NvdEnrichmentEngine._cwe_from_weaknesses(ws) == "CWE-611"


def test_apply_backfills_cwe_and_cvss_when_missing():
    f = NormalizedFinding(group_hash="n1", title="x", severity="Medium",
                          cwe_id=None, cvss_score=None)
    NvdEnrichmentEngine._apply_cve_data(f, CVE_REC)
    assert f.cwe_id == "CWE-89"                 # backfilled from weaknesses
    assert f.cvss_score == 9.8
    assert f.attack_vector == "NETWORK"
    assert f.cvss_vector.startswith("CVSS:3.1/")


def test_apply_preserves_scanner_provided_cwe():
    f = NormalizedFinding(group_hash="n2", title="x", cwe_id="CWE-79", cvss_score=None)
    NvdEnrichmentEngine._apply_cve_data(f, CVE_REC)
    assert f.cwe_id == "CWE-79"                 # scanner CWE not overwritten


def test_apply_uses_authoritative_nvd_cvss_consistently():
    # NVD's official CVSS wins over a scanner's heuristic score, and score+vector
    # stay consistent (no scanner score paired with an NVD vector).
    f = NormalizedFinding(group_hash="n3", title="x", cwe_id=None, cvss_score=5.0)
    NvdEnrichmentEngine._apply_cve_data(f, CVE_REC)
    assert f.cvss_score == 9.8
    assert f.cvss_vector == CVE_REC["metrics"]["cvssMetricV31"][0]["cvssData"]["vectorString"]
    assert f.attack_vector == "NETWORK"


def test_apply_preserves_scanner_cvss_when_nvd_has_no_v3():
    # A CVE with no v3 metrics must not null out scanner-provided CVSS fields.
    rec = {"weaknesses": [], "vulnStatus": "Analyzed"}   # no "metrics"
    f = NormalizedFinding(group_hash="n4", title="x", cvss_score=6.1,
                          cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                          attack_vector="NETWORK")
    NvdEnrichmentEngine._apply_cve_data(f, rec)
    assert f.cvss_score == 6.1
    assert f.attack_vector == "NETWORK"          # not wiped to None
