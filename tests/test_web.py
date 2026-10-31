"""
tests/test_web.py — Automated Tests for CertVerify Web Routes & Flow
"""

import sys
from pathlib import Path
import pytest
from starlette.testclient import TestClient

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app import app
from database import DB_PATH

client = TestClient(app)


def test_01_root_unauthenticated_shows_login():
    """Accessing / unauthenticated should show the login page directly."""
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 200
    assert "Welcome to CertVerify" in response.text
    assert "Secure Academic Certificate Verification" in response.text
    assert 'name="username"' in response.text
    assert 'name="password"' in response.text
    # Ensure no demo credentials or academic codes exposed
    assert "admin123" not in response.text
    assert "BIS 703" not in response.text
    assert "VTU" not in response.text


def test_02_verify_page_requires_auth():
    """Unauthenticated access to /verify must redirect to /login."""
    response = client.get("/verify", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["location"]


def test_03_login_failure():
    """Invalid credentials should show error message on login page."""
    response = client.post(
        "/login",
        data={"username": "wronguser", "password": "wrongpassword"},
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "Invalid username or password" in response.text


def test_04_login_success_and_redirect():
    """Valid credentials should set session and redirect directly to /verify."""
    session_client = TestClient(app)
    response = session_client.post(
        "/login",
        data={"username": "admin", "password": "admin123"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["location"] == "/verify"

    # Following redirect to /verify
    verify_page = session_client.get("/verify")
    assert verify_page.status_code == 200
    assert "Verify Your Certificate" in verify_page.text
    assert "Upload your academic certificate to verify its authenticity" in verify_page.text
    assert "Browse Files" in verify_page.text
    assert "Verify Certificate" in verify_page.text
    assert "Verify Another Certificate" not in verify_page.text  # Only appears after result

    # When authenticated, visiting / redirects to /verify
    root_page = session_client.get("/", follow_redirects=False)
    assert root_page.status_code == 302
    assert root_page.headers["location"] == "/verify"


def test_05_valid_certificate_verification():
    """Uploading a valid signed JSON certificate should return VALID status."""
    session_client = TestClient(app)
    session_client.post("/login", data={"username": "admin", "password": "admin123"})

    sample_path = PROJECT_ROOT / "sample_certificates" / "valid_CERT-2026-001.json"
    assert sample_path.exists(), "valid_CERT-2026-001.json must exist"

    with open(sample_path, "rb") as f:
        response = session_client.post(
            "/verify",
            files={"certificate_file": ("valid_CERT-2026-001.json", f, "application/json")},
        )

    assert response.status_code == 200
    assert "Certificate Verified Successfully" in response.text
    assert "CERT-2026-001" in response.text
    assert "Ananya Sharma" in response.text
    assert "Verified (RSA-2048 / SHA-256)" in response.text
    assert "Verify Another Certificate" in response.text


def test_06_tampered_certificate_verification():
    """Uploading a tampered certificate should return INVALID status with explanation."""
    session_client = TestClient(app)
    session_client.post("/login", data={"username": "admin", "password": "admin123"})

    sample_path = PROJECT_ROOT / "sample_certificates" / "tampered_CERT-2026-001.json"
    assert sample_path.exists(), "tampered_CERT-2026-001.json must exist"

    with open(sample_path, "rb") as f:
        response = session_client.post(
            "/verify",
            files={"certificate_file": ("tampered_CERT-2026-001.json", f, "application/json")},
        )

    assert response.status_code == 200
    assert "Invalid Certificate" in response.text
    assert "The digital signature does not match the certificate data" in response.text
    assert "Verify Another Certificate" in response.text


def test_07_unknown_certificate_verification():
    """Uploading an unregistered certificate should return NOT FOUND status."""
    session_client = TestClient(app)
    session_client.post("/login", data={"username": "admin", "password": "admin123"})

    sample_path = PROJECT_ROOT / "sample_certificates" / "unknown_CERT-2026-999.json"
    assert sample_path.exists(), "unknown_CERT-2026-999.json must exist"

    with open(sample_path, "rb") as f:
        response = session_client.post(
            "/verify",
            files={"certificate_file": ("unknown_CERT-2026-999.json", f, "application/json")},
        )

    assert response.status_code == 200
    assert "Certificate Not Found" in response.text
    assert "The certificate is not registered in the trusted database" in response.text
    assert "Verify Another Certificate" in response.text


def test_08_revoked_certificate_verification():
    """Uploading a revoked certificate should return REVOKED status."""
    from database import get_certificate_by_id, insert_certificate, revoke_certificate
    from crypto_utils import KEY_ISSUER_ID

    # Ensure revoked certificate record exists for the test
    if not get_certificate_by_id("CERT-2026-002", db_path=DB_PATH):
        insert_certificate(
            cert_id="CERT-2026-002",
            student_name="Vikram Aditya Hegde",
            course="Bachelor of Engineering in Information Science and Engineering",
            institution="Vemana Institute of Technology",
            issue_date="15 January 2026",
            canonical_json='{"cert_id":"CERT-2026-002","course":"Bachelor of Engineering in Information Science and Engineering","institution":"Vemana Institute of Technology","issue_date":"15 January 2026","student_name":"Vikram Aditya Hegde"}',
            sha256_hash="bac1564b1606a689bb829e6808afae82592e480ed2057445bdea06100718ea76",
            signature=b"test-signature",
            issuer_id=KEY_ISSUER_ID,
            db_path=DB_PATH,
        )
        revoke_certificate("CERT-2026-002", "Credential canceled by Academic Council under VTU Exam Malpractice Regulations Section 14(a)", db_path=DB_PATH)

    session_client = TestClient(app)
    session_client.post("/login", data={"username": "admin", "password": "admin123"})

    sample_path = PROJECT_ROOT / "sample_certificates" / "revoked_CERT-2026-002.json"
    assert sample_path.exists(), "revoked_CERT-2026-002.json must exist"

    with open(sample_path, "rb") as f:
        response = session_client.post(
            "/verify",
            files={"certificate_file": ("revoked_CERT-2026-002.json", f, "application/json")},
        )

    assert response.status_code == 200
    assert "Certificate Revoked" in response.text
    assert "The certificate has been revoked by the issuing authority" in response.text
    assert "Verify Another Certificate" in response.text


def test_09_valid_pdf_upload_verifies():
    """Uploading a digitally signed PDF certificate directly verifies as VALID."""
    session_client = TestClient(app)
    session_client.post("/login", data={"username": "admin", "password": "admin123"})

    sample_path = PROJECT_ROOT / "sample_certificates" / "valid_CERT-2026-001.pdf"
    assert sample_path.exists(), "valid_CERT-2026-001.pdf must exist"

    with open(sample_path, "rb") as f:
        response = session_client.post(
            "/verify",
            files={"certificate_file": ("valid_CERT-2026-001.pdf", f, "application/pdf")},
        )

    assert response.status_code == 200
    assert "Certificate Verified Successfully" in response.text
    assert "Ananya Sharma" in response.text
    assert "CERT-2026-001" in response.text


def test_09b_tampered_pdf_rejected():
    """Uploading a tampered PDF certificate fails verification."""
    session_client = TestClient(app)
    session_client.post("/login", data={"username": "admin", "password": "admin123"})

    sample_path = PROJECT_ROOT / "sample_certificates" / "tampered_CERT-2026-001.pdf"
    assert sample_path.exists(), "tampered_CERT-2026-001.pdf must exist"

    with open(sample_path, "rb") as f:
        response = session_client.post(
            "/verify",
            files={"certificate_file": ("tampered_CERT-2026-001.pdf", f, "application/pdf")},
        )

    assert response.status_code == 200
    assert "Invalid Certificate" in response.text


def test_09c_plain_unsigned_pdf_rejected():
    """Uploading a plain unsigned PDF informs the user that it lacks an embedded signature."""
    session_client = TestClient(app)
    session_client.post("/login", data={"username": "admin", "password": "admin123"})

    # Create a plain unsigned PDF in memory
    plain_pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"

    response = session_client.post(
        "/verify",
        files={"certificate_file": ("plain_unsigned.pdf", plain_pdf_bytes, "application/pdf")},
    )

    assert response.status_code == 200
    assert "does not contain an embedded cryptographic digital signature" in response.text


def test_10_logout():
    """Logging out clears session and redirects to /."""
    session_client = TestClient(app)
    session_client.post("/login", data={"username": "admin", "password": "admin123"})

    # Check authenticated
    res = session_client.get("/verify")
    assert res.status_code == 200

    # Logout
    logout_res = session_client.get("/logout", follow_redirects=False)
    assert logout_res.status_code == 302
    assert logout_res.headers["location"] == "/"

    # Subsequent access to /verify should redirect to /login
    after_res = session_client.get("/verify", follow_redirects=False)
    assert after_res.status_code == 302
    assert "/login" in after_res.headers["location"]


def test_11_admin_routes_protected():
    """Admin routes /certificates and /issue require authentication."""
    anon = TestClient(app)
    for route in ["/certificates", "/issue"]:
        res = anon.get(route, follow_redirects=False)
        assert res.status_code == 302
        assert "/login" in res.headers["location"]


def test_12_download_endpoints():
    """Authenticated users can download PDF and JSON certificates."""
    session_client = TestClient(app)
    session_client.post("/login", data={"username": "admin", "password": "admin123"})

    # PDF download
    pdf_res = session_client.get("/download/pdf/CERT-2026-001")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 1000

    # JSON download
    json_res = session_client.get("/download/json/CERT-2026-001")
    assert json_res.status_code == 200
    assert "application/json" in json_res.headers["content-type"]
    assert b"CERT-2026-001" in json_res.content



def test_13_issue_certificate_with_usn_and_calendar():
    """Issuing certificate with USN and calendar date converts date and registers USN."""
    session_client = TestClient(app)
    session_client.post("/login", data={"username": "admin", "password": "admin123"})

    response = session_client.post(
        "/issue",
        data={
            "cert_id": "CERT-2026-991",
            "student_name": "Test USN Student",
            "usn": "1VI22IS099",
            "course": "Bachelor of Engineering in Information Science and Engineering",
            "institution": "Vemana Institute of Technology",
            "issue_date": "2026-10-30",
        },
    )
    assert response.status_code == 200
    assert "Certificate Issued Successfully" in response.text
    assert "CERT-2026-991" in response.text
    assert "1VI22IS099" in response.text

    # Teardown test certificate so registry remains clean
    import sqlite3
    conn = sqlite3.connect(str(DB_PATH))
    with conn:
        conn.execute("DELETE FROM certificates WHERE cert_id = 'CERT-2026-991'")
    conn.close()
    for ext in ['.pdf', '.json']:
        p = PROJECT_ROOT / 'sample_certificates' / f'CERT-2026-991{ext}'
        if p.exists():
            p.unlink()

    # Teardown test certificate so registry remains clean
    import sqlite3
    conn = sqlite3.connect(str(DB_PATH))
    with conn:
        conn.execute("DELETE FROM certificates WHERE cert_id = 'CERT-2026-991'")
    conn.close()
    for ext in ['.pdf', '.json']:
        p = PROJECT_ROOT / 'sample_certificates' / f'CERT-2026-991{ext}'
        if p.exists():
            p.unlink()


def test_14_edit_certificate_status_malpractice():
    """Admin can edit certificate status to REVOKED for malpractice."""
    session_client = TestClient(app)
    session_client.post("/login", data={"username": "admin", "password": "admin123"})

    res = session_client.post(
        "/update-status/CERT-2026-001",
        data={"status": "REVOKED", "reason": "Academic malpractice reported during VTU evaluation"},
        follow_redirects=False,
    )
    assert res.status_code == 302
    assert res.headers["location"] == "/certificates"

    # Check that reason appears in certificates table
    certs_page = session_client.get("/certificates")
    assert "Academic malpractice reported" in certs_page.text

    # Restore to ACTIVE
    restore_res = session_client.post(
        "/update-status/CERT-2026-001",
        data={"status": "ACTIVE", "reason": ""},
        follow_redirects=False,
    )
    assert restore_res.status_code == 302
