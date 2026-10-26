"""
Standalone smoke test for Phase 9 report generator.
Builds a PDF from mock data without Flask context.
"""

import sys, os, types, tempfile

# ── Stub Flask / SQLAlchemy ───────────────────────────────────────────────────

class _FakeDb:
    class session:
        @staticmethod
        def get(model, pk): return None
        @staticmethod
        def commit(): pass

app_mod = types.ModuleType("app")
app_mod.db = _FakeDb()
sys.modules["app"] = app_mod

# Stub model modules with placeholder classes
for m in ("app.models.user", "app.models.report", "app.models.normalized_finding",
          "app.models.vulnerability", "app.models.scanner_upload"):
    mod_stub = types.ModuleType(m)
    class_name = m.split(".")[-1].title().replace("_", "")
    setattr(mod_stub, class_name, type(class_name, (), {}))
    sys.modules[m] = mod_stub

# Alias the specific names the generator imports
sys.modules["app.models.normalized_finding"].NormalizedFinding = object
sys.modules["app.models.report"].Report = object

# Stub sqlalchemy.func
sa = types.ModuleType("sqlalchemy")
sa.func = type("func", (), {"coalesce": staticmethod(lambda *a, **kw: None)})()
sys.modules["sqlalchemy"] = sa

# ── Load report_generator bypassing the Flask app factory ────────────────────

import importlib.util, pathlib

gen_path = pathlib.Path(__file__).parent / "backend" / "app" / "engines" / "report_generator.py"
spec = importlib.util.spec_from_file_location("report_generator", gen_path)
rg_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rg_mod)
ReportGenerator = rg_mod.ReportGenerator

# ── Mock data ────────────────────────────────────────────────────────────────

class MockCS:
    score = 78.0

class MockML:
    predicted_priority = "High"

class MockFinding:
    def __init__(self, title, severity, cvss, cwe=None, cve=None, classification=None):
        self.title            = title
        self.severity         = severity
        self.cvss_score       = cvss
        self.cwe_id           = cwe
        self.cve_id           = cve
        self.classification   = classification
        self.url              = "https://example.com/path?id=1"
        self.description      = f"Detailed description of {title}. An attacker could exploit this vulnerability to compromise the target."
        self.solution         = f"Apply the vendor patch for {title}. Validate all user input and encode output."
        self.scanner_count    = 2
        self.scanner_sources  = ["zap", "nessus"]
        self.confidence_score = MockCS()
        self.ml_prediction    = MockML()

class MockReport:
    id            = 1
    user_id       = 1
    title         = "VulnTriage Smoke Test Report"
    report_type   = "pdf"
    upload_ids    = []

findings = [
    MockFinding("SQL Injection in Login Form",     "Critical", 9.8, "CWE-89",  "CVE-2024-1001", "Confirmed"),
    MockFinding("Reflected XSS via Search Query",  "Critical", 9.1, "CWE-79",  "CVE-2024-1002", "Confirmed"),
    MockFinding("SSRF via Webhook URL",            "High",     8.1, "CWE-918", None,             "Needs Manual Verification"),
    MockFinding("Insecure Direct Object Reference","High",     7.5, "CWE-863", "CVE-2024-1003",  "Confirmed"),
    MockFinding("XXE in XML Upload",               "High",     7.2, "CWE-611", None,             "Not Confirmed"),
    MockFinding("CSRF on Profile Update",          "Medium",   4.3, "CWE-352", None,             None),
    MockFinding("Information Disclosure",          "Medium",   5.3, "CWE-200", None,             "Not Confirmed"),
    MockFinding("Weak Password Policy",            "Low",      3.1, "CWE-521", None,             "Not Confirmed"),
    MockFinding("Open Redirect",                   "Low",      3.5, "CWE-601", None,             "Needs Manual Verification"),
    MockFinding("Missing Security Header",         "Informational", 0.0, None, None,             None),
]

# ── Generate PDF ──────────────────────────────────────────────────────────────

gen      = ReportGenerator()
out_path = os.path.join(tempfile.gettempdir(), "vuln_triage_test_report.pdf")

gen._build_pdf(out_path, MockReport(), findings, "analyst_test")

size = os.path.getsize(out_path)
print(f"\n  PDF generated : {out_path}")
print(f"  File size     : {size:,} bytes ({size // 1024} KB)")
print(f"  Result        : {'PASS' if size > 10_000 else 'FAIL — file too small'}")
