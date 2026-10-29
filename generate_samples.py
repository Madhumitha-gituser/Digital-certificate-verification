# -*- coding: utf-8 -*-
"""
generate_samples.py -- Generate Three Sample Certificates for Demo

HOW TO RUN:
    python generate_samples.py

This script is SAFE to run more than once:
  - It will NOT delete existing database records.
  - It will NOT regenerate RSA keys if they already exist.
  - It WILL overwrite PDF files but not DB records.

WHAT IT CREATES:
  sample_certificates/
    valid_CERT-2026-001.json      <- signed certificate data (upload to verify)
    valid_CERT-2026-001.pdf       <- visual certificate PDF
    tampered_CERT-2026-001.json   <- original sig + modified data (should FAIL)
    tampered_CERT-2026-001.pdf    <- PDF showing the tampered name
    unknown_CERT-2026-999.json    <- unsigned, not in DB (should be NOT FOUND)
    unknown_CERT-2026-999.pdf     <- PDF for the unknown certificate

  instance/
    private_key.pem               <- RSA-2048 private key (NEVER share this)
    public_key.pem                <- RSA-2048 public key (safe to share)
    certificates.db               <- SQLite trusted certificate store
"""

import json
import base64
import sys
from pathlib import Path

# Ensure UTF-8 output on Windows
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Add the project directory to path so we can import our modules
sys.path.insert(0, str(Path(__file__).parent))

from crypto_utils import (
    initialize_keys,
    make_canonical_json,
    compute_sha256,
    sign_certificate_data,
    KEY_ISSUER_ID,
)
from certificate_service import CertificateData, issue_certificate
from database import init_db, DB_PATH
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
print("  Digital Certificate Verification System")
print("  Sample Generator -- VTU INS BIS 703")
print("=" * 60)
print()

print("[Step 1] Initialising RSA keys...")
initialize_keys()

print()
print("[Step 2] Initialising database...")
init_db(DB_PATH)

print()

# ==============================================================================
# SAMPLE A -- Valid Certificate
# ==============================================================================

sep()
print("[Sample A] Generating VALID certificate...")

valid_cert = CertificateData(
    cert_id      = "CERT-2026-001",
    student_name = "Ananya Sharma",
    course       = "B.E. Information Science and Engineering",
    institution  = "Demo Engineering College",
    issue_date   = "01 October 2026",
)

# Issue: signs data and stores in DB
result = issue_certificate(valid_cert, db_path=DB_PATH)

# Build the JSON package (this is what users upload to verify)
valid_package = {
    "certificate": valid_cert.to_dict(),
    "sha256_hash": result["sha256_hash"],
    "signature":   result["signature_b64"],
    "issuer_id":   result["issuer_id"],
    "canonical_json": result["canonical_json"],
}

valid_json_name = "valid_CERT-2026-001.json"
valid_json_path = save_json_package(valid_json_name, valid_package)

# Generate PDF
valid_pdf_path = SAMPLES_DIR / "valid_CERT-2026-001.pdf"
generate_certificate_pdf(
    cert_id           = valid_cert.cert_id,
    student_name      = valid_cert.student_name,
    course            = valid_cert.course,
    institution       = valid_cert.institution,
    issue_date        = valid_cert.issue_date,
    output_path       = valid_pdf_path,
    label             = "VALID",
    sha256_hash       = result["sha256_hash"],
    canonical_json_ref= valid_json_name,
)

print("  [OK] JSON: " + str(valid_json_path.resolve()))
print("  [OK] PDF:  " + str(valid_pdf_path.resolve()))


# ==============================================================================
# SAMPLE B -- Tampered Certificate
# IMPORTANT: We use the ORIGINAL signature but CHANGE the data.
#            Verification will FAIL because the signature covers the original data.
# ==============================================================================

print()
sep()
print("[Sample B] Generating TAMPERED certificate...")

tampered_data = {
    "cert_id":      "CERT-2026-001",
    "student_name": "Fake Student",     # <-- CHANGED (tampered!)
    "course":       "B.E. Information Science and Engineering",
    "institution":  "Demo Engineering College",
    "issue_date":   "01 October 2026",
}

# Keep the ORIGINAL signature -- do NOT re-sign the tampered data
original_signature_b64 = result["signature_b64"]

tampered_canonical = make_canonical_json(tampered_data)
tampered_hash      = compute_sha256(tampered_canonical)

tampered_package = {
    "certificate":  tampered_data,
    "sha256_hash":  tampered_hash,
    "signature":    original_signature_b64,
    "issuer_id":    KEY_ISSUER_ID,
    "canonical_json": tampered_canonical,
    "_demo_note": (
        "TAMPERED: student_name changed to 'Fake Student'. "
        "The original RSA signature is preserved. "
        "Verification will fail because the signature was made for the original data."
    ),
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
)

print("  [WARN] JSON: " + str(tampered_json_path.resolve()))
print("  [WARN] PDF:  " + str(tampered_pdf_path.resolve()))
print("  [INFO] Note: Original signature preserved, but data was changed.")
print("  [INFO] When verified, signature check will FAIL -> status = INVALID/TAMPERED")


# ==============================================================================
# SAMPLE C -- Unknown Certificate (NOT registered in DB)
# ==============================================================================

print()
sep()
print("[Sample C] Generating UNKNOWN certificate...")

unknown_data = {
    "cert_id":      "CERT-2026-999",
    "student_name": "Rahul Kumar",
    "course":       "B.E. Computer Science and Engineering",
    "institution":  "Unknown Private Institute",
    "issue_date":   "15 March 2026",
}

unknown_canonical = make_canonical_json(unknown_data)
unknown_hash      = compute_sha256(unknown_canonical)

unknown_package = {
    "certificate":  unknown_data,
    "sha256_hash":  unknown_hash,
    "signature":    "UNSIGNED_NOT_FROM_TRUSTED_ISSUER",
    "issuer_id":    "UNKNOWN_ISSUER",
    "canonical_json": unknown_canonical,
    "_demo_note": (
        "UNKNOWN: This certificate ID is not registered in the trusted database. "
        "Verification result will be NOT_FOUND."
    ),
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
)

print("  [FAIL] JSON: " + str(unknown_json_path.resolve()))
print("  [FAIL] PDF:  " + str(unknown_pdf_path.resolve()))
print("  [INFO] Note: cert_id 'CERT-2026-999' is NOT in the trusted database.")
print("  [INFO] When verified, result = NOT_FOUND (not TAMPERED -- important distinction!)")


# ==============================================================================
# SUMMARY
# ==============================================================================

print()
print("=" * 60)
print("  SAMPLE GENERATION COMPLETE")
print("=" * 60)
print()
print("Files created in: " + str(SAMPLES_DIR.resolve()))
print()
print("  sample_certificates/")
print("  [OK]   " + valid_json_name)
print("  [OK]   valid_CERT-2026-001.pdf")
print("  [WARN] " + tampered_json_name)
print("  [WARN] tampered_CERT-2026-001.pdf")
print("  [FAIL] " + unknown_json_name)
print("  [FAIL] unknown_CERT-2026-999.pdf")
print()
print("  instance/")
print("  [KEY]  private_key.pem  (KEEP SECRET -- never commit to git)")
print("  [PUB]  public_key.pem   (safe to share)")
print("  [DB]   certificates.db  (trusted certificate store)")
print()
print("NEXT STEPS:")
print("  1. Start the server:  python app.py")
print("  2. Open browser:      http://127.0.0.1:8000")
print("  3. Go to /verify and upload one of the JSON files above.")
print()
print("EXPECTED RESULTS:")
print("  valid_CERT-2026-001.json    -> VALID")
print("  tampered_CERT-2026-001.json -> INVALID / TAMPERED")
print("  unknown_CERT-2026-999.json  -> NOT FOUND")
