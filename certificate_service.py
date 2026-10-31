"""
certificate_service.py — Certificate Issuance and Verification Logic

============================================================
BEGINNER'S GUIDE
============================================================
This file is the BRAIN of the system. It connects:
  - crypto_utils.py  (signing and verifying)
  - database.py      (storing and retrieving trusted records)

VERIFICATION WORKFLOW (step by step):
  1. Parse the submitted certificate data (cert_id, name, course, etc.)
  2. Look up the cert_id in the trusted database.
  3. If NOT FOUND → result is "NOT_FOUND" (unknown certificate).
  4. If FOUND → compare each field against the trusted stored data.
  5. Recalculate the SHA-256 hash of the submitted canonical JSON.
  6. Verify the RSA-PSS signature using the trusted stored signature + public key.
  7. Check revocation status.
  8. Return the final result with a detailed explanation.

IMPORTANT: We never trust the submitted data on its own.
We always compare it against what is stored in the trusted database.
============================================================
"""

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from crypto_utils import (
    make_canonical_json,
    compute_sha256,
    sign_certificate_data,
    verify_certificate_signature,
    KEY_ISSUER_ID,
)
from database import (
    insert_certificate,
    get_certificate_by_id,
    revoke_certificate,
    DB_PATH,
    TEST_DB_PATH,
)


# ─── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class CertificateData:
    """
    Represents the fields of a certificate.
    A dataclass automatically creates __init__, __repr__, etc.
    """
    cert_id: str
    student_name: str
    course: str
    institution: str
    issue_date: str
    usn: str = ""

    def to_dict(self) -> dict:
        """Convert to a plain dictionary for JSON serialization."""
        data = {
            "cert_id": self.cert_id,
            "student_name": self.student_name,
            "course": self.course,
            "institution": self.institution,
            "issue_date": self.issue_date,
        }
        if self.usn:
            data["usn"] = self.usn
        return data


@dataclass
class VerificationResult:
    """
    Contains the full result of a certificate verification.
    Every field has a clear meaning for the result page.
    """
    status: str                     # "VALID", "INVALID", "NOT_FOUND", "REVOKED"
    cert_id: str
    student_name: str
    course: str
    institution: str
    issue_date: str
    signature_valid: Optional[bool]     # None if we couldn't check
    data_integrity: Optional[bool]      # True = data matches trusted record
    explanation: str                    # Human-readable explanation
    usn: str = ""
    revoke_reason: Optional[str] = None


# ─── Certificate Issuance ────────────────────────────────────────────────────

def issue_certificate(cert_data: CertificateData, db_path: Path = DB_PATH) -> dict:
    """
    Issue a new certificate:
    1. Build canonical JSON from the certificate fields.
    2. Compute SHA-256 hash of the canonical JSON.
    3. Sign the canonical JSON with the RSA private key.
    4. Store everything in the trusted database.

    Returns a dict with the canonical_json, sha256_hash, and signature (base64).
    """
    data_dict = cert_data.to_dict()
    canonical = make_canonical_json(data_dict)
    sha256 = compute_sha256(canonical)
    signature_bytes = sign_certificate_data(data_dict)  # raw bytes

    # Store in the trusted database
    inserted = insert_certificate(
        cert_id=cert_data.cert_id,
        student_name=cert_data.student_name,
        course=cert_data.course,
        institution=cert_data.institution,
        issue_date=cert_data.issue_date,
        canonical_json=canonical,
        sha256_hash=sha256,
        signature=signature_bytes,
        issuer_id=KEY_ISSUER_ID,
        usn=cert_data.usn,
        db_path=db_path,
    )

    if not inserted:
        print(f"[certificate_service] cert_id '{cert_data.cert_id}' already in DB — skipping insert.")

    return {
        "cert_id": cert_data.cert_id,
        "canonical_json": canonical,
        "sha256_hash": sha256,
        "signature_b64": base64.b64encode(signature_bytes).decode(),
        "issuer_id": KEY_ISSUER_ID,
        "already_existed": not inserted,
    }


# ─── Certificate Verification ────────────────────────────────────────────────

def verify_certificate(submitted: dict, db_path: Path = DB_PATH) -> VerificationResult:
    """
    THE MAIN VERIFICATION FUNCTION.

    Input:  submitted — a dict with certificate fields (from user upload or form).
    Output: VerificationResult with full details of what passed and what failed.

    This function performs REAL cryptographic checks — no hardcoding.
    """
    # ── Step 1: Extract submitted fields ─────────────────────────────────────
    cert_id       = submitted.get("cert_id", "").strip()
    student_name  = submitted.get("student_name", "").strip()
    course        = submitted.get("course", "").strip()
    institution   = submitted.get("institution", "").strip()
    issue_date    = submitted.get("issue_date", "").strip()
    usn           = submitted.get("usn", "").strip()

    # Validate that required fields are present
    if not cert_id:
        return VerificationResult(
            status="INVALID",
            cert_id="", student_name=student_name, course=course,
            institution=institution, issue_date=issue_date,
            signature_valid=None, data_integrity=None,
            explanation="Certificate ID is missing or empty.",
            usn=usn,
        )

    # ── Step 2: Look up the cert_id in the trusted database ──────────────────
    db_row = get_certificate_by_id(cert_id, db_path=db_path)

    if db_row is None:
        # The certificate ID is not in our trusted registry at all.
        # This is the "UNKNOWN / NOT REGISTERED" case.
        return VerificationResult(
            status="NOT_FOUND",
            cert_id=cert_id, student_name=student_name, course=course,
            institution=institution, issue_date=issue_date,
            signature_valid=None, data_integrity=None,
            explanation=(
                f"Certificate ID '{cert_id}' is not registered in the trusted database. "
                "This certificate was not issued by our system."
            ),
            usn=usn,
        )

    db_keys = db_row.keys() if hasattr(db_row, "keys") else []
    record_usn = db_row["usn"] if "usn" in db_keys and db_row["usn"] else (usn or "")

    # ── Step 3: Check revocation status ──────────────────────────────────────
    if db_row["revoked"] == 1:
        return VerificationResult(
            status="REVOKED",
            cert_id=cert_id, student_name=db_row["student_name"],
            course=db_row["course"], institution=db_row["institution"],
            issue_date=db_row["issue_date"],
            signature_valid=None, data_integrity=None,
            explanation=f"This certificate has been REVOKED. Reason: {db_row['revoke_reason'] or 'Not specified'}.",
            usn=record_usn,
            revoke_reason=db_row["revoke_reason"],
        )

    # ── Step 4: Compare submitted data against trusted record ─────────────────
    # Build the submitted data dict for canonical JSON computation
    submitted_data = {
        "cert_id": cert_id,
        "student_name": student_name,
        "course": course,
        "institution": institution,
        "issue_date": issue_date,
    }
    trusted_canonical   = db_row["canonical_json"]
    if '"usn"' in trusted_canonical:
        submitted_data["usn"] = usn

    submitted_canonical = make_canonical_json(submitted_data)

    data_matches = (submitted_canonical == trusted_canonical)

    # ── Step 5: Recalculate SHA-256 hash ─────────────────────────────────────
    submitted_hash = compute_sha256(submitted_canonical)
    trusted_hash   = db_row["sha256_hash"]
    hash_matches   = (submitted_hash == trusted_hash)

    # ── Step 6: Verify the RSA-PSS signature ─────────────────────────────────
    # We verify the SUBMITTED data against the TRUSTED signature.
    # If the data was tampered, the submitted canonical JSON differs from
    # what was signed — so the signature check will FAIL.
    trusted_signature_bytes = db_row["signature"]  # raw bytes from DB (BLOB)

    try:
        sig_valid = verify_certificate_signature(submitted_data, trusted_signature_bytes)
    except Exception as exc:
        sig_valid = False
        print(f"[certificate_service] Signature check error: {exc}")

    # ── Step 7: Decide the final status ──────────────────────────────────────
    if data_matches and sig_valid:
        return VerificationResult(
            status="VALID",
            cert_id=cert_id, student_name=student_name, course=course,
            institution=institution, issue_date=issue_date,
            signature_valid=True, data_integrity=True,
            explanation=(
                "✅ Certificate is VALID. "
                "The certificate data matches the trusted record exactly, "
                "and the RSA-PSS digital signature is authentic."
            ),
            usn=record_usn,
        )
    else:
        # Build a detailed explanation of what failed
        reasons = []
        if not data_matches:
            reasons.append("The submitted certificate data does NOT match the trusted record.")
        if not sig_valid:
            reasons.append("The RSA-PSS digital signature verification FAILED.")
        if not hash_matches:
            reasons.append(f"SHA-256 hash mismatch: submitted={submitted_hash[:16]}… ≠ trusted={trusted_hash[:16]}…")

        return VerificationResult(
            status="INVALID",
            cert_id=cert_id, student_name=student_name, course=course,
            institution=institution, issue_date=issue_date,
            signature_valid=sig_valid, data_integrity=data_matches,
            explanation=(
                "❌ Certificate is INVALID / TAMPERED. " + " ".join(reasons)
            ),
            usn=record_usn,
        )


def revoke(cert_id: str, reason: str, db_path: Path = DB_PATH) -> bool:
    """Revoke a certificate by its ID. Returns True if found and revoked."""
    return revoke_certificate(cert_id, reason, db_path=db_path)

