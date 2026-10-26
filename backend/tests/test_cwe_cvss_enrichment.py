"""CWE→CVSS-vector enrichment tests.

These build an unpersisted NormalizedFinding (no flush/commit), so no Vulnerability
FK row is needed; we only assert the in-memory field population. Requires
ml_data/cwe_cvss_profiles.json (built by app.ml.cwe_profile_builder).
"""

import pytest

from app.models.normalized_finding import NormalizedFinding
from app.engines.cwe_cvss_enrichment import CweCvssEnrichmentEngine, _profiles_path
import os


pytestmark = pytest.mark.skipif(
    not os.path.exists(_profiles_path()),
    reason="cwe_cvss_profiles.json not built",
)


def test_fills_vector_for_vectorless_cwe(app):
    f = NormalizedFinding(group_hash="h1", title="SQL Injection",
                          severity="High", cwe_id="CWE-89")
    applied = CweCvssEnrichmentEngine().enrich_finding(f)
    assert applied is True
    # SQLi profile is network/low-complexity with high impact.
    assert f.attack_vector == "NETWORK"
    assert f.confidentiality_impact == "HIGH"
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3.1/")
    assert getattr(f, "_vector_inferred", False) is True


def test_does_not_overwrite_existing_vector(app):
    f = NormalizedFinding(group_hash="h2", title="x", severity="High",
                          cwe_id="CWE-79", attack_vector="LOCAL")
    applied = CweCvssEnrichmentEngine().enrich_finding(f)
    assert applied is False
    assert f.attack_vector == "LOCAL"  # untouched


def test_unknown_cwe_falls_back_to_global(app):
    # A CWE not in the profile should still get the global modal vector.
    f = NormalizedFinding(group_hash="h3", title="weird", severity="Medium",
                          cwe_id="CWE-99999")
    applied = CweCvssEnrichmentEngine().enrich_finding(f)
    assert applied is True
    assert f.attack_vector is not None
    assert f._vector_inferred_from == "global"
