"""
tests/test_crypto.py — Automated Tests for the Digital Certificate System

============================================================
HOW TO RUN:
    cd "c:\\Users\\kaviy\\Downloads\\INS Proj\\Digital-certificate-verification"
    python -m pytest tests/ -v

WHAT IS TESTED:
  1.  Key pair creation and persistence (generate only when absent)
  2.  Signing and verifying original data
  3.  Rejecting modified certificate data
  4.  Valid sample certificate verification (end-to-end)
  5.  Tampered sample certificate rejection
  6.  Unknown certificate rejection (NOT_FOUND)
  7.  PDF fields match signed data (canonical JSON check)
  8.  Database persistence after re-init
  9.  Repeated sample generation without duplicate records
  10. Certificate revocation

ISOLATION:
  Tests use separate KEY files and a separate TEST DATABASE
  so they never touch the production data.
============================================================
"""

import json
import base64
import sys
import os
import shutil
import tempfile
from pathlib import Path

import pytest

# Ensure the project root is on sys.path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import crypto_utils          # noqa: E402
import database              # noqa: E402
from certificate_service import (   # noqa: E402
    CertificateData,
    issue_certificate,
    verify_certificate,
    revoke,
)


# ─── Test Fixtures ────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def temp_instance(tmp_path_factory):
    """
    Create a temporary directory for test keys and a test database.
    This isolates tests from the real instance/ directory.
    """
    instance = tmp_path_factory.mktemp("test_instance")
    # Monkey-patch crypto_utils paths to use the temp dir
    original_instance = crypto_utils.INSTANCE_DIR
    original_private  = crypto_utils.PRIVATE_KEY_PATH
    original_public   = crypto_utils.PUBLIC_KEY_PATH

    crypto_utils.INSTANCE_DIR    = instance
    crypto_utils.PRIVATE_KEY_PATH = instance / "private_key.pem"
    crypto_utils.PUBLIC_KEY_PATH  = instance / "public_key.pem"

    yield instance

    # Restore originals after module tests complete
    crypto_utils.INSTANCE_DIR    = original_instance
    crypto_utils.PRIVATE_KEY_PATH = original_private
    crypto_utils.PUBLIC_KEY_PATH  = original_public


@pytest.fixture(scope="module")
def test_db(temp_instance):
    """Create an isolated test SQLite database."""
    db_path = temp_instance / "test_certificates.db"
    database.init_db(db_path)
    return db_path


@pytest.fixture(scope="module")
def generated_keys(temp_instance):
    """Generate RSA keys into the temp instance dir."""
    crypto_utils.initialize_keys()
    return temp_instance


@pytest.fixture(scope="module")
def sample_cert():
    """A standard test certificate."""
    return CertificateData(
        cert_id      = "TEST-CERT-001",
        student_name = "Test Student",
        course       = "B.E. Test Engineering",
        institution  = "Test College",
        issue_date   = "01 January 2026",
    )


# ══════════════════════════════════════════════════════════════════════════════
# TEST 1: Key pair creation and persistence
# ══════════════════════════════════════════════════════════════════════════════

def test_01_key_generation(temp_instance, generated_keys):
    """Keys should be created only when absent. Both files must exist after init."""
    assert crypto_utils.PRIVATE_KEY_PATH.exists(), "Private key file should exist"
    assert crypto_utils.PUBLIC_KEY_PATH.exists(),  "Public key file should exist"


def test_01b_key_persistence(temp_instance, generated_keys):
    """Calling initialize_keys() again should NOT overwrite existing keys."""
    # Read the original keys
    orig_private = crypto_utils.PRIVATE_KEY_PATH.read_bytes()
    orig_public  = crypto_utils.PUBLIC_KEY_PATH.read_bytes()

    # Call init again
    crypto_utils.initialize_keys()

    # Keys should be unchanged
    assert crypto_utils.PRIVATE_KEY_PATH.read_bytes() == orig_private, \
        "Private key should not change on second init"
    assert crypto_utils.PUBLIC_KEY_PATH.read_bytes() == orig_public, \
        "Public key should not change on second init"


# ══════════════════════════════════════════════════════════════════════════════
# TEST 2: Signing and verifying original data
# ══════════════════════════════════════════════════════════════════════════════

def test_02_sign_and_verify(generated_keys, sample_cert):
    """Signing a certificate and then verifying with the same data should return True."""
    cert_dict = sample_cert.to_dict()

    # Sign
    signature_bytes = crypto_utils.sign_certificate_data(cert_dict)
    assert isinstance(signature_bytes, bytes), "Signature should be bytes"
    assert len(signature_bytes) > 0,           "Signature should not be empty"

    # Verify
    result = crypto_utils.verify_certificate_signature(cert_dict, signature_bytes)
    assert result is True, "Signature verification should return True for original data"


# ══════════════════════════════════════════════════════════════════════════════
# TEST 3: Rejecting modified certificate data
# ══════════════════════════════════════════════════════════════════════════════

def test_03_reject_modified_data(generated_keys, sample_cert):
    """If data is changed after signing, verification must fail."""
    original_dict = sample_cert.to_dict()
    signature_bytes = crypto_utils.sign_certificate_data(original_dict)

    # Tamper with the data: change the student name
    tampered_dict = dict(original_dict)
    tampered_dict["student_name"] = "Impostor"

    # Verification should FAIL
    result = crypto_utils.verify_certificate_signature(tampered_dict, signature_bytes)
    assert result is False, \
        "Signature verification must return False when data has been modified"


# ══════════════════════════════════════════════════════════════════════════════
# TEST 4: Valid sample certificate verification (end-to-end)
# ══════════════════════════════════════════════════════════════════════════════

def test_04_valid_certificate_end_to_end(generated_keys, test_db):
    """Issue a certificate, then verify it → should return VALID."""
    cert = CertificateData(
        cert_id      = "E2E-TEST-001",
        student_name = "Ananya Test",
        course       = "B.E. E2E Testing",
        institution  = "Test University",
        issue_date   = "15 June 2026",
    )

    # Issue (sign + store in DB)
    issue_result = issue_certificate(cert, db_path=test_db)
    assert issue_result["cert_id"] == "E2E-TEST-001"

    # Verify with the exact same data
    ver_result = verify_certificate(cert.to_dict(), db_path=test_db)
    assert ver_result.status == "VALID", \
        f"Expected VALID, got {ver_result.status}: {ver_result.explanation}"
    assert ver_result.signature_valid is True
    assert ver_result.data_integrity is True


def test_04b_certificate_with_usn(generated_keys, test_db):
    """Issue a certificate with USN, then verify it → should return VALID with matching USN."""
    cert = CertificateData(
        cert_id      = "E2E-TEST-USN",
        student_name = "Kavya R",
        course       = "Bachelor of Engineering in Information Science and Engineering",
        institution  = "Vemana Institute of Technology",
        issue_date   = "15 June 2026",
        usn          = "1VI22IS045",
    )
    issue_certificate(cert, db_path=test_db)
    ver = verify_certificate(cert.to_dict(), db_path=test_db)
    assert ver.status == "VALID"
    assert ver.usn == "1VI22IS045"
    assert ver.signature_valid is True
    assert ver.data_integrity is True


def test_04b_certificate_with_usn(generated_keys, test_db):
    """Issue a certificate with USN, then verify it → should return VALID with matching USN."""
    cert = CertificateData(
        cert_id      = "E2E-TEST-USN",
        student_name = "Kavya R",
        course       = "Bachelor of Engineering in Information Science and Engineering",
        institution  = "Vemana Institute of Technology",
        issue_date   = "15 June 2026",
        usn          = "1VI22IS045",
    )
    issue_certificate(cert, db_path=test_db)
    ver = verify_certificate(cert.to_dict(), db_path=test_db)
    assert ver.status == "VALID"
    assert ver.usn == "1VI22IS045"
    assert ver.signature_valid is True
    assert ver.data_integrity is True


# ══════════════════════════════════════════════════════════════════════════════
# TEST 5: Tampered certificate rejection
# ══════════════════════════════════════════════════════════════════════════════

def test_05_tampered_certificate_rejected(generated_keys, test_db):
    """Verify a certificate where data was modified → should return INVALID."""
    cert = CertificateData(
        cert_id      = "E2E-TEST-002",
        student_name = "Real Student",
        course       = "B.E. Testing",
        institution  = "Test University",
        issue_date   = "15 June 2026",
    )
    issue_certificate(cert, db_path=test_db)

    # Submit with a changed name (tampered)
    tampered = dict(cert.to_dict())
    tampered["student_name"] = "Fake Student"

    ver_result = verify_certificate(tampered, db_path=test_db)
    assert ver_result.status == "INVALID", \
        f"Expected INVALID for tampered data, got {ver_result.status}"
    assert ver_result.signature_valid is False or ver_result.data_integrity is False, \
        "Either signature check or data integrity check should fail"


# ══════════════════════════════════════════════════════════════════════════════
# TEST 6: Unknown certificate rejection
# ══════════════════════════════════════════════════════════════════════════════

def test_06_unknown_certificate_not_found(generated_keys, test_db):
    """A cert_id that was never registered should return NOT_FOUND, not TAMPERED."""
    unknown = {
        "cert_id":      "UNKNOWN-CERT-999",
        "student_name": "Ghost Student",
        "course":       "B.E. Nonexistent",
        "institution":  "Unknown College",
        "issue_date":   "01 April 2026",
    }

    ver_result = verify_certificate(unknown, db_path=test_db)
    assert ver_result.status == "NOT_FOUND", \
        f"Expected NOT_FOUND for unregistered cert, got {ver_result.status}"
    # Must NOT be reported as TAMPERED when it's simply unknown
    assert ver_result.status != "INVALID", \
        "An unknown certificate must not be called TAMPERED/INVALID"


# ══════════════════════════════════════════════════════════════════════════════
# TEST 7: PDF fields matching signed data (canonical JSON consistency)
# ══════════════════════════════════════════════════════════════════════════════

def test_07_canonical_json_determinism():
    """
    The canonical JSON of the same data must always be identical.
    This is what ensures PDF data matches the signed data.
    """
    data1 = {
        "cert_id": "TEST-001",
        "student_name": "Alice",
        "course": "B.E. CS",
        "institution": "Test College",
        "issue_date": "01 Jan 2026",
    }
    # Same data, different key order
    data2 = {
        "student_name": "Alice",
        "institution": "Test College",
        "cert_id": "TEST-001",
        "issue_date": "01 Jan 2026",
        "course": "B.E. CS",
    }

    canon1 = crypto_utils.make_canonical_json(data1)
    canon2 = crypto_utils.make_canonical_json(data2)

    assert canon1 == canon2, \
        "Canonical JSON must be the same regardless of input key order"

    # Also check that changing ONE value changes the canonical JSON
    data3 = dict(data1)
    data3["student_name"] = "Bob"   # changed
    canon3 = crypto_utils.make_canonical_json(data3)
    assert canon1 != canon3, "Canonical JSON must change when data changes"


def test_07b_sha256_consistency():
    """SHA-256 of the same canonical JSON must always match."""
    data = {
        "cert_id": "TEST-001",
        "student_name": "Ananya Sharma",
        "course": "B.E. Information Science and Engineering",
        "institution": "Demo Engineering College",
        "issue_date": "01 October 2026",
    }
    canonical = crypto_utils.make_canonical_json(data)
    hash1 = crypto_utils.compute_sha256(canonical)
    hash2 = crypto_utils.compute_sha256(canonical)
    assert hash1 == hash2 == 64 * "0" or len(hash1) == 64, \
        "SHA-256 hash must be 64 hex characters"
    assert hash1 == hash2, "SHA-256 must be deterministic"


# ══════════════════════════════════════════════════════════════════════════════
# TEST 8: Database persistence after re-init
# ══════════════════════════════════════════════════════════════════════════════

def test_08_database_persistence(generated_keys, test_db):
    """
    After init_db() is called again on an existing database,
    existing records must not be deleted.
    """
    cert = CertificateData(
        cert_id      = "PERSIST-001",
        student_name = "Persist Student",
        course       = "B.E. Persistence",
        institution  = "Test University",
        issue_date   = "01 July 2026",
    )
    issue_certificate(cert, db_path=test_db)

    # Re-initialise the database
    database.init_db(test_db)

    # The record should still be there
    row = database.get_certificate_by_id("PERSIST-001", db_path=test_db)
    assert row is not None, "Certificate should persist after database re-init"
    assert row["student_name"] == "Persist Student"


# ══════════════════════════════════════════════════════════════════════════════
# TEST 9: Repeated issuance without duplicate records
# ══════════════════════════════════════════════════════════════════════════════

def test_09_no_duplicate_records(generated_keys, test_db):
    """
    Issuing the same cert_id twice must not create a duplicate.
    The second call should silently skip (already_existed=True).
    """
    cert = CertificateData(
        cert_id      = "DEDUP-001",
        student_name = "Dedup Student",
        course       = "B.E. Deduplication",
        institution  = "Test University",
        issue_date   = "01 August 2026",
    )

    result1 = issue_certificate(cert, db_path=test_db)
    result2 = issue_certificate(cert, db_path=test_db)  # second time

    assert result1["already_existed"] is False, "First issue should create a new record"
    assert result2["already_existed"] is True,  "Second issue of same cert_id should not create a duplicate"

    # Count records in DB
    all_certs = database.get_all_certificates(db_path=test_db)
    dedup_count = sum(1 for c in all_certs if c["cert_id"] == "DEDUP-001")
    assert dedup_count == 1, f"Expected 1 DEDUP-001 record, found {dedup_count}"


# ══════════════════════════════════════════════════════════════════════════════
# TEST 10: Certificate revocation
# ══════════════════════════════════════════════════════════════════════════════

def test_10_revocation(generated_keys, test_db):
    """A revoked certificate must return REVOKED status during verification."""
    cert = CertificateData(
        cert_id      = "REVOKE-TEST-001",
        student_name = "Revoked Student",
        course       = "B.E. Revocation Testing",
        institution  = "Test University",
        issue_date   = "01 September 2026",
    )
    issue_certificate(cert, db_path=test_db)

    # Before revocation: should be VALID
    before = verify_certificate(cert.to_dict(), db_path=test_db)
    assert before.status == "VALID", f"Should be VALID before revocation, got {before.status}"

    # Revoke it
    success = revoke("REVOKE-TEST-001", "Test revocation", db_path=test_db)
    assert success is True, "Revocation should return True when cert exists"

    # After revocation: should be REVOKED
    after = verify_certificate(cert.to_dict(), db_path=test_db)
    assert after.status == "REVOKED", f"Should be REVOKED after revocation, got {after.status}"
    assert after.revoke_reason == "Test revocation"


# ══════════════════════════════════════════════════════════════════════════════
# TEST 11: Missing cert_id returns error, not crash
# ══════════════════════════════════════════════════════════════════════════════

def test_11_missing_cert_id_handled(test_db):
    """Submitting an empty cert_id should return INVALID, not crash."""
    result = verify_certificate({
        "cert_id": "",
        "student_name": "Nobody",
        "course": "B.E. Nothing",
        "institution": "Nowhere",
        "issue_date": "01 Jan 2026",
    }, db_path=test_db)
    assert result.status in ("INVALID", "NOT_FOUND"), \
        "Empty cert_id should not crash — should return INVALID or NOT_FOUND"


# ══════════════════════════════════════════════════════════════════════════════
# TEST 12: Corrupt signature bytes rejected gracefully
# ══════════════════════════════════════════════════════════════════════════════

def test_12_corrupt_signature_rejected(generated_keys):
    """Passing garbage bytes as a signature must return False, not raise an exception."""
    data = {
        "cert_id": "TEST-001",
        "student_name": "Alice",
        "course": "B.E. CS",
        "institution": "Test College",
        "issue_date": "01 Jan 2026",
    }
    garbage_sig = b"\x00\x01\x02GARBAGE_SIGNATURE\xff\xfe"
    result = crypto_utils.verify_certificate_signature(data, garbage_sig)
    assert result is False, "Corrupt signature must return False (not raise exception)"

