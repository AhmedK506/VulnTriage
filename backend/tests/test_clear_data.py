"""Test the dashboard 'clear scan data' endpoint (fresh-session reset)."""

from app import db
from app.models.user import User
from app.models.scanner_upload import ScannerUpload
from app.models.vulnerability import Vulnerability
from app.models.normalized_finding import NormalizedFinding
from app.models.report import Report
from app.models.cwe_mapping import CweMapping


def _auth(client):
    r = client.post("/api/auth/register", json={
        "username": "clr", "email": "clr@t.local", "password": "password123"})
    token = r.get_json()["token"]
    uid = User.query.filter_by(username="clr").first().id
    return token, uid


def test_clear_data_cascades_and_keeps_account_and_cwe(client):
    token, uid = _auth(client)
    # Full chain: upload -> vulnerability -> normalized finding (exercises the
    # cascade — a bare upload wouldn't catch the vulnerability->finding bug).
    up = ScannerUpload(user_id=uid, filename="f.xml", original_filename="f.xml",
                       scanner_type="zap", file_size=1,
                       file_path="/tmp/vt_nonexistent.xml", status="completed")
    db.session.add(up)
    db.session.flush()
    vuln = Vulnerability(upload_id=up.id, scanner_type="zap", name="XSS")
    db.session.add(vuln)
    db.session.flush()
    db.session.add(NormalizedFinding(vulnerability_id=vuln.id, group_hash="h",
                                     title="XSS", severity="High"))
    db.session.add(Report(user_id=uid, title="r", report_type="pdf", status="completed"))
    db.session.add(CweMapping(cwe_id="CWE-79", name="XSS"))   # shared ref data
    db.session.commit()

    r = client.delete("/api/dashboard/data", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["uploads_deleted"] == 1 and body["reports_deleted"] == 1

    assert ScannerUpload.query.filter_by(user_id=uid).count() == 0
    assert Vulnerability.query.count() == 0
    assert NormalizedFinding.query.count() == 0               # cascaded, not orphaned
    assert Report.query.filter_by(user_id=uid).count() == 0
    assert User.query.filter_by(id=uid).count() == 1          # account kept
    assert CweMapping.query.count() == 1                      # reference data kept


def test_clear_data_requires_auth(client):
    assert client.delete("/api/dashboard/data").status_code == 401
