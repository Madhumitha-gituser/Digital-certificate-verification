# -*- coding: utf-8 -*-
"""
generate_samples.py -- Generate Sample Certificates for CertVerify System
"""

import json
import base64
import sys
from pathlib import Path
import io

# Ensure UTF-8 output on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Add project directory to path
sys.path.insert(0, str(Path(__file__).parent))

from crypto_utils import (
    initialize_keys,
    make_canonical_json,
    compute_sha256,
    sign_certificate_data,
    KEY_ISSUER_ID,
)
from certificate_service import CertificateData, issue_certificate
from database import init_db, revoke_certificate, get_connection, DB_PATH
from pdf_generator import generate_certificate_pdf

# Output folder
SAMPLES_DIR = Path(__file__).parent / "sample_certificates"
SAMPLES_DIR.mkdir(exist_ok=True)


def save_json_package(filename: str, data: dict) -> Path:
    """Save a certificate JSON package to the samples folder."""
    path = SAMPLES_DIR / filename
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def sep():
    print("-" * 60)


# ==============================================================================
# STEP 1 -- Ensure keys and database exist
# ==============================================================================

print("=" * 60)
print("  CertVerify — Digital Certificate Verification System")
print("  Vemana Institute of Technology — Sample Generator")
print("=" * 60)
print()

print("[Step 1] Initialising RSA keys...")
initialize_keys()

print()
print("[Step 2] Initialising database...")
init_db(DB_PATH)

# Clear old demo sample records so they get cleanly re-issued with Vemana IT
conn = get_connection(DB_PATH)
with conn:
    conn.execute("DELETE FROM certificates WHERE cert_id IN ('CERT-2026-001', 'CERT-2026-002')")
conn.close()

print()

# ==============================================================================
# SAMPLE A -- Valid Certificate (Vemana Institute of Technology)
# ==============================================================================

sep()
print("[Sample A] Generating VALID certificate...")

valid_cert = CertificateData(
    cert_id      = "CERT-2026-001",
    student_name = "Ananya Sharma",
    course       = "Bachelor of Engineering in Information Science and Engineering",
    institution  = "Vemana Institute of Technology",
    issue_date   = "01 October 2026",
)

result_valid = issue_certificate(valid_cert, db_path=DB_PATH)

valid_package = {
    "certificate": valid_cert.to_dict(),
    "sha256_hash": result_valid["sha256_hash"],
    "signature":   result_valid["signature_b64"],
    "issuer_id":   result_valid["issuer_id"],
    "canonical_json": result_valid["canonical_json"],
}

valid_json_name = "valid_CERT-2026-001.json"
valid_json_path = save_json_package(valid_json_name, valid_package)

valid_pdf_path = SAMPLES_DIR / "valid_CERT-2026-001.pdf"
generate_certificate_pdf(
    cert_id           = valid_cert.cert_id,
    student_name      = valid_cert.student_name,
    course            = valid_cert.course,
    institution       = valid_cert.institution,
    issue_date        = valid_cert.issue_date,
    output_path       = valid_pdf_path,
    label             = "VALID",
    sha256_hash       = result_valid["sha256_hash"],
    canonical_json_ref= valid_json_name,
    signature_b64     = result_valid["signature_b64"],
)

print("  [OK] JSON: " + str(valid_json_path.resolve()))
print("  [OK] PDF:  " + str(valid_pdf_path.resolve()))


# ==============================================================================
# SAMPLE B -- Tampered Certificate
# Original signature preserved, but recipient name modified.
# ==============================================================================

print()
sep()
print("[Sample B] Generating TAMPERED certificate...")

tampered_data = {
    "cert_id":      "CERT-2026-001",
    "student_name": "Fake Student",     # Forged name
    "course":       "Bachelor of Engineering in Information Science and Engineering",
    "institution":  "Vemana Institute of Technology",
    "issue_date":   "01 October 2026",
}

original_signature_b64 = result_valid["signature_b64"]
tampered_canonical     = make_canonical_json(tampered_data)
tampered_hash          = compute_sha256(tampered_canonical)

tampered_package = {
    "certificate":    tampered_data,
    "sha256_hash":    tampered_hash,
    "signature":      original_signature_b64,
    "issuer_id":      KEY_ISSUER_ID,
    "canonical_json": tampered_canonical,
}

tampered_json_name = "tampered_CERT-2026-001.json"
tampered_json_path = save_json_package(tampered_json_name, tampered_package)

tampered_pdf_path = SAMPLES_DIR / "tampered_CERT-2026-001.pdf"
generate_certificate_pdf(
    cert_id           = tampered_data["cert_id"],
    student_name      = tampered_data["student_name"],
    course            = tampered_data["course"],
    institution       = tampered_data["institution"],
    issue_date        = tampered_data["issue_date"],
    output_path       = tampered_pdf_path,
    label             = "TAMPERED",
    sha256_hash       = tampered_hash,
    canonical_json_ref= tampered_json_name,
    signature_b64     = original_signature_b64,
)

print("  [TAMPERED] JSON: " + str(tampered_json_path.resolve()))
print("  [TAMPERED] PDF:  " + str(tampered_pdf_path.resolve()))


# ==============================================================================
# SAMPLE C -- Unknown Certificate (NOT registered in DB)
# ==============================================================================

print()
sep()
print("[Sample C] Generating UNKNOWN certificate...")

unknown_data = {
    "cert_id":      "CERT-2026-999",
    "student_name": "Rahul Kumar",
    "course":       "Bachelor of Engineering in Computer Science and Engineering",
    "institution":  "Vemana Institute of Technology",
    "issue_date":   "15 March 2026",
}

unknown_canonical = make_canonical_json(unknown_data)
unknown_hash      = compute_sha256(unknown_canonical)

unknown_package = {
    "certificate":    unknown_data,
    "sha256_hash":    unknown_hash,
    "signature":      "UNSIGNED_NOT_IN_TRUSTED_DATABASE",
    "issuer_id":      "UNKNOWN_ISSUER",
    "canonical_json": unknown_canonical,
}

unknown_json_name = "unknown_CERT-2026-999.json"
unknown_json_path = save_json_package(unknown_json_name, unknown_package)

unknown_pdf_path = SAMPLES_DIR / "unknown_CERT-2026-999.pdf"
generate_certificate_pdf(
    cert_id           = unknown_data["cert_id"],
    student_name      = unknown_data["student_name"],
    course            = unknown_data["course"],
    institution       = unknown_data["institution"],
    issue_date        = unknown_data["issue_date"],
    output_path       = unknown_pdf_path,
    label             = "UNKNOWN",
    sha256_hash       = unknown_hash,
    canonical_json_ref= unknown_json_name,
    signature_b64     = "UNSIGNED_NOT_IN_TRUSTED_DATABASE",
)

print("  [UNKNOWN] JSON: " + str(unknown_json_path.resolve()))
print("  [UNKNOWN] PDF:  " + str(unknown_pdf_path.resolve()))


# ==============================================================================
# SAMPLE D -- Revoked Certificate (Registered in DB, marked revoked)
# ==============================================================================

print()
sep()
print("[Sample D] Generating REVOKED certificate...")

revoked_cert = CertificateData(
    cert_id      = "CERT-2026-002",
    student_name = "David Miller",
    course       = "Bachelor of Engineering in Information Science and Engineering",
    institution  = "Vemana Institute of Technology",
    issue_date   = "15 January 2026",
)

result_revoked = issue_certificate(revoked_cert, db_path=DB_PATH)

# Mark revoked in database
revoke_certificate("CERT-2026-002", "Credential revoked by authority due to administrative review", db_path=DB_PATH)

revoked_package = {
    "certificate":    revoked_cert.to_dict(),
    "sha256_hash":    result_revoked["sha256_hash"],
    "signature":      result_revoked["signature_b64"],
    "issuer_id":      result_revoked["issuer_id"],
    "canonical_json": result_revoked["canonical_json"],
}

revoked_json_name = "revoked_CERT-2026-002.json"
revoked_json_path = save_json_package(revoked_json_name, revoked_package)

revoked_pdf_path = SAMPLES_DIR / "revoked_CERT-2026-002.pdf"
generate_certificate_pdf(
    cert_id           = revoked_cert.cert_id,
    student_name      = revoked_cert.student_name,
    course            = revoked_cert.course,
    institution       = revoked_cert.institution,
    issue_date        = revoked_cert.issue_date,
    output_path       = revoked_pdf_path,
    label             = "REVOKED",
    sha256_hash       = result_revoked["sha256_hash"],
    canonical_json_ref= revoked_json_name,
    signature_b64     = result_revoked["signature_b64"],
)

print("  [REVOKED] JSON: " + str(revoked_json_path.resolve()))
print("  [REVOKED] PDF:  " + str(revoked_pdf_path.resolve()))


# ==============================================================================
# SUMMARY
# ==============================================================================

print()
print("=" * 60)
print("  SAMPLE GENERATION COMPLETE")
print("=" * 60)
print()
print("Files created in: " + str(SAMPLES_DIR.resolve()))
print("  [VALID]     valid_CERT-2026-001.json  &  valid_CERT-2026-001.pdf")
print("  [TAMPERED]  tampered_CERT-2026-001.json  &  tampered_CERT-2026-001.pdf")
print("  [UNKNOWN]   unknown_CERT-2026-999.json  &  unknown_CERT-2026-999.pdf")
print("  [REVOKED]   revoked_CERT-2026-002.json  &  revoked_CERT-2026-002.pdf")
print()
