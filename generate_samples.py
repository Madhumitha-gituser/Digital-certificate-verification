# -*- coding: utf-8 -*-
"""
generate_samples.py -- Generate Authentic Sample Certificates for CertVerify System
Produces realistic, rule-compliant certificates for all expected verification test cases:
  1. VALID: Authentic degree issued to Ananya Sharma (1VI22IS045)
  2. TAMPERED: Realistic degree presented by Karthik V. Gowda (1VI22IS034) with forged identity on original signature
  3. REVOKED: Authentic degree issued to Vikram Aditya Hegde (1VI22IS019), administratively revoked
  4. UNKNOWN: Authentic-looking degree for Siddharth N. Murthy (1VI22IS058), not present in registry
  5. UNSIGNED: Regular academic PDF document lacking embedded digital signature metadata
"""

import json
import base64
import sys
import shutil
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
    print("-" * 65)


# ==============================================================================
# STEP 1 -- Ensure keys and database exist
# ==============================================================================

print("=" * 65)
print("  CertVerify — Digital Certificate Verification System")
print("  Vemana Institute of Technology — Authentic Sample Generator")
print("=" * 65)
print()

print("[Step 1] Initialising RSA-2048 keys...")
initialize_keys()

print("[Step 2] Initialising trusted SQLite registry...")
init_db(DB_PATH)

# Clear old demo records so they get cleanly generated with institutional standards
conn = get_connection(DB_PATH)
with conn:
    conn.execute("DELETE FROM certificates WHERE cert_id IN ('CERT-2026-001', 'CERT-2026-002', 'CERT-2026-088')")
conn.close()

print()

# ==============================================================================
# CASE 1: VALID CERTIFICATE
# Student: Ananya Sharma (USN: 1VI22IS045)
# Expected Result: VALID
# ==============================================================================
sep()
print("[Case 1: VALID] Generating Authentic Verified Degree...")

valid_cert = CertificateData(
    cert_id      = "CERT-2026-001",
    student_name = "Ananya Sharma",
    course       = "Bachelor of Engineering in Information Science and Engineering",
    institution  = "Vemana Institute of Technology",
    issue_date   = "01 October 2026",
    usn          = "1VI22IS045",
)

result_valid = issue_certificate(valid_cert, db_path=DB_PATH)

valid_package = {
    "certificate": valid_cert.to_dict(),
    "sha256_hash": result_valid["sha256_hash"],
    "signature":   result_valid["signature_b64"],
    "issuer_id":   result_valid["issuer_id"],
    "canonical_json": result_valid["canonical_json"],
}

# 1. Save standard test file
save_json_package("valid_CERT-2026-001.json", valid_package)
save_json_package("CERT-2026-001.json", valid_package)

valid_pdf_path = SAMPLES_DIR / "valid_CERT-2026-001.pdf"
generate_certificate_pdf(
    cert_id           = valid_cert.cert_id,
    student_name      = valid_cert.student_name,
    course            = valid_cert.course,
    institution       = valid_cert.institution,
    issue_date        = valid_cert.issue_date,
    output_path       = valid_pdf_path,
    sha256_hash       = result_valid["sha256_hash"],
    canonical_json_ref= "valid_CERT-2026-001.json",
    signature_b64     = result_valid["signature_b64"],
    usn               = valid_cert.usn,
)

# 2. Save realistic presentation files
real_valid_pdf = SAMPLES_DIR / "Certificate_Ananya_Sharma_1VI22IS045.pdf"
real_valid_json = SAMPLES_DIR / "Certificate_Ananya_Sharma_1VI22IS045.json"
shutil.copyfile(valid_pdf_path, real_valid_pdf)
shutil.copyfile(SAMPLES_DIR / "valid_CERT-2026-001.json", real_valid_json)
shutil.copyfile(valid_pdf_path, SAMPLES_DIR / "CERT-2026-001.pdf")

print("  [OK] Realistic Demo PDF: " + real_valid_pdf.name)
print("  [OK] Standard Test PDF:  " + valid_pdf_path.name)


# ==============================================================================
# CASE 2: TAMPERED / FORGED CERTIFICATE
# Imposter: Karthik V. Gowda (USN: 1VI22IS034) modifies Ananya's certificate data.
# Visually identical to a real certificate, but RSA signature check FAILS.
# Expected Result: INVALID (Signature mismatch)
# ==============================================================================
print()
sep()
print("[Case 2: TAMPERED] Generating Realistic Tampered Degree...")

tampered_data = {
    "cert_id":      "CERT-2026-001",
    "student_name": "Karthik V. Gowda",
    "course":       "Bachelor of Engineering in Information Science and Engineering",
    "institution":  "Vemana Institute of Technology",
    "issue_date":   "01 October 2026",
    "usn":          "1VI22IS034",
}

original_signature_b64 = result_valid["signature_b64"]
tampered_canonical     = make_canonical_json(tampered_data)
tampered_hash          = compute_sha256(tampered_canonical)

tampered_package = {
    "certificate":    tampered_data,
    "sha256_hash":    tampered_hash,
    "signature":      original_signature_b64,  # Old signature signed for Ananya
    "issuer_id":      KEY_ISSUER_ID,
    "canonical_json": tampered_canonical,
}

tampered_json_name = "tampered_CERT-2026-001.json"
save_json_package(tampered_json_name, tampered_package)

tampered_pdf_path = SAMPLES_DIR / "tampered_CERT-2026-001.pdf"
generate_certificate_pdf(
    cert_id           = tampered_data["cert_id"],
    student_name      = tampered_data["student_name"],
    course            = tampered_data["course"],
    institution       = tampered_data["institution"],
    issue_date        = tampered_data["issue_date"],
    output_path       = tampered_pdf_path,
    sha256_hash       = tampered_hash,
    canonical_json_ref= tampered_json_name,
    signature_b64     = original_signature_b64,
    usn               = tampered_data["usn"],
)

real_tampered_pdf = SAMPLES_DIR / "Certificate_Karthik_Gowda_1VI22IS034.pdf"
real_tampered_json = SAMPLES_DIR / "Certificate_Karthik_Gowda_1VI22IS034.json"
shutil.copyfile(tampered_pdf_path, real_tampered_pdf)
shutil.copyfile(SAMPLES_DIR / tampered_json_name, real_tampered_json)

print("  [OK] Realistic Demo PDF: " + real_tampered_pdf.name)
print("  [OK] Standard Test PDF:  " + tampered_pdf_path.name)


# ==============================================================================
# CASE 3: REVOKED CERTIFICATE
# Student: Vikram Aditya Hegde (USN: 1VI22IS019)
# Valid signature, but marked REVOKED in the institutional registry.
# Expected Result: REVOKED
# ==============================================================================
print()
sep()
print("[Case 3: REVOKED] Generating Administratively Revoked Degree...")

revoked_cert = CertificateData(
    cert_id      = "CERT-2026-002",
    student_name = "Vikram Aditya Hegde",
    course       = "Bachelor of Engineering in Information Science and Engineering",
    institution  = "Vemana Institute of Technology",
    issue_date   = "15 January 2026",
    usn          = "1VI22IS019",
)

result_revoked = issue_certificate(revoked_cert, db_path=DB_PATH)

# Mark revoked in official registry
revocation_reason = "Credential canceled by Academic Council under VTU Exam Malpractice Regulations Section 14(a)"
revoke_certificate("CERT-2026-002", revocation_reason, db_path=DB_PATH)

revoked_package = {
    "certificate":    revoked_cert.to_dict(),
    "sha256_hash":    result_revoked["sha256_hash"],
    "signature":      result_revoked["signature_b64"],
    "issuer_id":      result_revoked["issuer_id"],
    "canonical_json": result_revoked["canonical_json"],
}

revoked_json_name = "revoked_CERT-2026-002.json"
save_json_package(revoked_json_name, revoked_package)
save_json_package("CERT-2026-002.json", revoked_package)

revoked_pdf_path = SAMPLES_DIR / "revoked_CERT-2026-002.pdf"
generate_certificate_pdf(
    cert_id           = revoked_cert.cert_id,
    student_name      = revoked_cert.student_name,
    course            = revoked_cert.course,
    institution       = revoked_cert.institution,
    issue_date        = revoked_cert.issue_date,
    output_path       = revoked_pdf_path,
    sha256_hash       = result_revoked["sha256_hash"],
    canonical_json_ref= revoked_json_name,
    signature_b64     = result_revoked["signature_b64"],
    usn               = revoked_cert.usn,
)

real_revoked_pdf = SAMPLES_DIR / "Certificate_Vikram_Hegde_1VI22IS019.pdf"
real_revoked_json = SAMPLES_DIR / "Certificate_Vikram_Hegde_1VI22IS019.json"
shutil.copyfile(revoked_pdf_path, real_revoked_pdf)
shutil.copyfile(SAMPLES_DIR / revoked_json_name, real_revoked_json)
shutil.copyfile(revoked_pdf_path, SAMPLES_DIR / "CERT-2026-002.pdf")

print("  [OK] Realistic Demo PDF: " + real_revoked_pdf.name)
print("  [OK] Standard Test PDF:  " + revoked_pdf_path.name)


# ==============================================================================
# CASE 4: UNKNOWN / UNREGISTERED CERTIFICATE
# Student: Siddharth N. Murthy (USN: 1VI22IS058)
# Not present in database at all.
# Expected Result: NOT_FOUND
# ==============================================================================
print()
sep()
print("[Case 4: UNKNOWN] Generating Unregistered Certificate...")

unknown_data = {
    "cert_id":      "CERT-2026-999",
    "student_name": "Siddharth N. Murthy",
    "course":       "Bachelor of Engineering in Information Science and Engineering",
    "institution":  "Vemana Institute of Technology",
    "issue_date":   "15 March 2026",
    "usn":          "1VI22IS058",
}

unknown_canonical = make_canonical_json(unknown_data)
unknown_hash      = compute_sha256(unknown_canonical)

unknown_package = {
    "certificate":    unknown_data,
    "sha256_hash":    unknown_hash,
    "signature":      "UNSIGNED_NOT_IN_TRUSTED_DATABASE",
    "issuer_id":      "EXTERNAL_UNVERIFIED_AUTHORITY",
    "canonical_json": unknown_canonical,
}

unknown_json_name = "unknown_CERT-2026-999.json"
save_json_package(unknown_json_name, unknown_package)

unknown_pdf_path = SAMPLES_DIR / "unknown_CERT-2026-999.pdf"
generate_certificate_pdf(
    cert_id           = unknown_data["cert_id"],
    student_name      = unknown_data["student_name"],
    course            = unknown_data["course"],
    institution       = unknown_data["institution"],
    issue_date        = unknown_data["issue_date"],
    output_path       = unknown_pdf_path,
    sha256_hash       = unknown_hash,
    canonical_json_ref= unknown_json_name,
    signature_b64     = "UNSIGNED_NOT_IN_TRUSTED_DATABASE",
    usn               = unknown_data["usn"],
)

real_unknown_pdf = SAMPLES_DIR / "Certificate_Siddharth_Murthy_1VI22IS058.pdf"
real_unknown_json = SAMPLES_DIR / "Certificate_Siddharth_Murthy_1VI22IS058.json"
shutil.copyfile(unknown_pdf_path, real_unknown_pdf)
shutil.copyfile(SAMPLES_DIR / unknown_json_name, real_unknown_json)

print("  [OK] Realistic Demo PDF: " + real_unknown_pdf.name)
print("  [OK] Standard Test PDF:  " + unknown_pdf_path.name)


# ==============================================================================
# CASE 5: PLAIN / UNSIGNED ACADEMIC DOCUMENT
# Standard syllabus/grade PDF lacking cryptographic metadata.
# Expected Result: Lacks embedded digital signature
# ==============================================================================
print()
sep()
print("[Case 5: UNSIGNED] Generating Plain Academic Document...")

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as pdf_canvas
from reportlab.lib.colors import HexColor

unsigned_pdf_path = SAMPLES_DIR / "Unsigned_Academic_Document.pdf"
u_canvas = pdf_canvas.Canvas(str(unsigned_pdf_path), pagesize=A4)
w, h = A4
u_canvas.setFont("Helvetica-Bold", 16)
u_canvas.setFillColor(HexColor("#0b192c"))
u_canvas.drawCentredString(w / 2.0, h - 80, "VEMANA INSTITUTE OF TECHNOLOGY")
u_canvas.setFont("Helvetica", 11)
u_canvas.setFillColor(HexColor("#475569"))
u_canvas.drawCentredString(w / 2.0, h - 105, "Internal Academic Coursework Summary — Term End Evaluation")
u_canvas.line(60, h - 120, w - 60, h - 120)
u_canvas.setFont("Helvetica-Bold", 12)
u_canvas.drawString(60, h - 160, "Candidate: Ananya Sharma")
u_canvas.drawString(60, h - 180, "USN: 1VI22IS045")
u_canvas.drawString(60, h - 200, "Branch: Information Science and Engineering")
u_canvas.setFont("Helvetica", 10)
u_canvas.drawString(60, h - 240, "Notice: This document is an informational grade slip and is NOT digitally signed.")
u_canvas.save()

print("  [OK] Plain Document PDF: " + unsigned_pdf_path.name)


# ==============================================================================
# SUMMARY TABLE
# ==============================================================================
print()
print("=" * 65)
print("  SAMPLE GENERATION COMPLETE")
print("=" * 65)
print(f"Target Directory: {SAMPLES_DIR.resolve()}\n")
print(f"{'File Name':<45} {'Recipient & USN':<30} {'Expected Result'}")
print("-" * 90)
print(f"{'Certificate_Ananya_Sharma_1VI22IS045.pdf':<45} {'Ananya Sharma (1VI22IS045)':<30} {'VALID'}")
print(f"{'Certificate_Karthik_Gowda_1VI22IS034.pdf':<45} {'Karthik V. Gowda (1VI22IS034)':<30} {'INVALID / TAMPERED'}")
print(f"{'Certificate_Vikram_Hegde_1VI22IS019.pdf':<45} {'Vikram Hegde (1VI22IS019)':<30} {'REVOKED'}")
print(f"{'Certificate_Siddharth_Murthy_1VI22IS058.pdf':<45} {'Siddharth Murthy (1VI22IS058)':<30} {'NOT FOUND'}")
print(f"{'Unsigned_Academic_Document.pdf':<45} {'General Grade Slip':<30} {'NO SIGNATURE'}")
print("=" * 65)
