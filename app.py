"""
app.py — FastAPI Web Application: Digital Certificate Verification System (CertVerify)
"""

import json
import base64
import os
from contextlib import asynccontextmanager
from pathlib import Path
from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from crypto_utils import initialize_keys, get_public_key_pem
from database import init_db, get_all_certificates, revoke_certificate, update_certificate_status, verify_admin_password, DB_PATH
from certificate_service import (
    CertificateData,
    issue_certificate,
    verify_certificate,
    VerificationResult,
)
from pdf_generator import generate_certificate_pdf, extract_certificate_from_pdf

# ─── App Initialisation & Lifespan ────────────────────────────────────────────
BASE_DIR = Path(__file__).parent

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run once when the server starts: ensure keys and DB exist."""
    print("[app] Starting CertVerify - Digital Certificate Verification System...")
    try:
        initialize_keys()
    except RuntimeError as e:
        print(f"[app] Key status: {e}")
    init_db(DB_PATH)
    print("[app] Server ready at http://127.0.0.1:8000")
    yield

app = FastAPI(
    title="CertVerify — Digital Certificate Verification System",
    description="Academic Certificate Verification System using RSA-2048 and SHA-256.",
    version="1.0.0",
    lifespan=lifespan,
)

# Session middleware: uses a secret key to sign session cookies
SESSION_SECRET = os.environ.get("SESSION_SECRET", "certverify-production-session-secret-key-2026")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

# Static files (CSS, JS, images)
static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Sample certificates directory
samples_dir = BASE_DIR / "sample_certificates"
samples_dir.mkdir(exist_ok=True)
app.mount("/samples", StaticFiles(directory=str(samples_dir)), name="samples")

# Jinja2 templates
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


# ─── Helper: Auth Check ───────────────────────────────────────────────────────

def is_authenticated(request: Request) -> bool:
    """Return True if the current session is authenticated."""
    return request.session.get("is_admin", False)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. FIRST PAGE — SIMPLE LOGIN PAGE & AUTHENTICATION
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """
    First Page: When a user opens http://127.0.0.1:8000/
    If authenticated -> redirect immediately to /verify
    Else -> show the simple, professional login page
    """
    if is_authenticated(request):
        return RedirectResponse(url="/verify", status_code=302)
    return templates.TemplateResponse(request, "login.html", {
        "error": None,
    })


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login route: redirect to verify if already authenticated."""
    if is_authenticated(request):
        return RedirectResponse(url="/verify", status_code=302)
    return templates.TemplateResponse(request, "login.html", {
        "error": None,
    })


@app.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    """
    Verify credentials against the SQLite database.
    On success: redirect immediately to the certificate verification page (/verify).
    """
    if verify_admin_password(username.strip(), password, db_path=DB_PATH):
        request.session["is_admin"] = True
        request.session["username"] = username.strip()
        return RedirectResponse(url="/verify", status_code=302)
    else:
        return templates.TemplateResponse(request, "login.html", {
            "error": "Invalid username or password.",
        })


@app.post("/", response_class=HTMLResponse)
async def root_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    """Allow direct submission from the root route as well."""
    return await login_post(request, username, password)


@app.get("/logout")
async def logout(request: Request):
    """Clear the session and redirect back to the login page."""
    request.session.clear()
    return RedirectResponse(url="/", status_code=302)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. AFTER LOGIN — DIRECT CERTIFICATE UPLOAD PAGE
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/verify", response_class=HTMLResponse)
async def verify_page(request: Request):
    """
    Certificate verification page: requires authentication.
    If not logged in, redirect to login page.
    """
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)

    return templates.TemplateResponse(request, "verify.html", {
        "admin": is_authenticated(request),
        "result": None,
        "error_msg": None,
    })


@app.post("/verify", response_class=HTMLResponse)
async def verify_post(
    request: Request,
    certificate_file: UploadFile = File(None),
    json_file: UploadFile = File(None),
):
    """
    Process certificate verification. Requires authentication.

    Supports:
    - Signed JSON certificate package (.json) with genuine RSA-2048 / SHA-256 verification.
    - PDF uploads (.pdf): distinguishes visual documents from genuine digital signatures.
      Ordinary PDFs without embedded digital signatures are accurately flagged.
    """
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)

    upload = certificate_file if (certificate_file and certificate_file.filename) else json_file
    error_msg = None
    result: VerificationResult | None = None

    try:
        if not upload or not upload.filename:
            raise ValueError("Please select a certificate file (.json or .pdf) to verify.")

        filename = upload.filename.lower()

        if filename.endswith(".json"):
            # ── 1. Signed JSON Package Verification ───────────────────────────
            content = await upload.read()
            if len(content) > 1_000_000:  # 1 MB limit
                raise ValueError("Uploaded file is too large (maximum allowed size is 1 MB).")

            try:
                package = json.loads(content.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                raise ValueError(f"Invalid JSON file format: {e}")

            # Extract the authoritative certificate block
            if isinstance(package, dict) and "certificate" in package:
                cert_block = package["certificate"]
            elif isinstance(package, dict) and "cert_id" in package:
                cert_block = package
            else:
                raise ValueError("JSON file missing required 'certificate' block.")

            required_fields = ["cert_id", "student_name", "course", "institution", "issue_date"]
            for field in required_fields:
                if field not in cert_block:
                    raise ValueError(f"Missing required field in certificate package: '{field}'")

            # Execute real cryptographic verification against SQLite trusted registry
            result = verify_certificate(cert_block, db_path=DB_PATH)

        elif filename.endswith(".pdf"):
            # ── 2. PDF Document Upload Analysis ──────────────────────────────
            content = await upload.read()
            if len(content) > 10_000_000:  # 10 MB limit
                raise ValueError("Uploaded PDF file is too large (maximum allowed size is 10 MB).")

            # Extract embedded cryptographic digital signature metadata
            extracted = extract_certificate_from_pdf(content)
            if extracted:
                cert_block = extracted.get("certificate", extracted)
                required_fields = ["cert_id", "student_name", "course", "institution", "issue_date"]
                for field in required_fields:
                    if field not in cert_block:
                        raise ValueError(f"Missing required field in certificate PDF metadata: '{field}'")

                # Execute genuine cryptographic verification against SQLite trusted registry
                result = verify_certificate(cert_block, db_path=DB_PATH)
            else:
                error_msg = (
                    "The uploaded PDF does not contain an embedded cryptographic digital signature. "
                    "Only verified academic certificates issued by Vemana Institute of Technology "
                    "contain the authentic RSA-2048 / SHA-256 digital signature."
                )

        else:
            raise ValueError("Unsupported file format. Please upload a signed certificate package (.json) or certificate document (.pdf).")

    except ValueError as e:
        error_msg = str(e)
    except Exception as e:
        print(f"[app] Verification processing error: {e}")
        error_msg = "An unexpected error occurred during verification. Please check the uploaded file."

    return templates.TemplateResponse(request, "verify.html", {
        "admin": is_authenticated(request),
        "result": result,
        "error_msg": error_msg,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN: CERTIFICATE REGISTRY & ISSUANCE
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/certificates", response_class=HTMLResponse)
async def list_certificates(request: Request):
    """Show all trusted certificates in the database (authenticated only)."""
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)

    certs = get_all_certificates(db_path=DB_PATH)
    return templates.TemplateResponse(request, "certificates.html", {
        "admin": True,
        "certificates": certs,
    })


@app.get("/issue", response_class=HTMLResponse)
async def issue_page(request: Request):
    """Show the issue-certificate form (authenticated only)."""
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)

    return templates.TemplateResponse(request, "issue.html", {
        "admin": True,
        "result": None,
        "error": None,
    })


@app.post("/issue", response_class=HTMLResponse)
async def issue_post(
    request: Request,
    cert_id: str = Form(...),
    student_name: str = Form(...),
    usn: str = Form(""),
    course: str = Form(...),
    institution: str = Form(...),
    issue_date: str = Form(...),
):
    """Issue a new certificate: sign it and store in the trusted database."""
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)

    error = None
    result_data = None

    if not all([cert_id.strip(), student_name.strip(), course.strip(),
                institution.strip(), issue_date.strip()]):
        error = "All fields are required."
    else:
        try:
            # Parse calendar picker date (YYYY-MM-DD) into readable academic format
            formatted_date = issue_date.strip()
            try:
                dt = datetime.strptime(formatted_date, "%Y-%m-%d")
                formatted_date = dt.strftime("%d %B %Y")
            except ValueError:
                pass

            cert = CertificateData(
                cert_id      = cert_id.strip(),
                student_name = student_name.strip(),
                course       = course.strip(),
                institution  = institution.strip(),
                issue_date   = formatted_date,
                usn          = usn.strip(),
            )
            result_data = issue_certificate(cert, db_path=DB_PATH)
            result_data["usn"] = cert.usn
            result_data["student_name"] = cert.student_name
            result_data["course"] = cert.course
            result_data["institution"] = cert.institution
            result_data["issue_date"] = cert.issue_date

            # Generate PDF and JSON package immediately for download
            pdf_path = samples_dir / f"{cert.cert_id}.pdf"
            generate_certificate_pdf(
                cert_id           = cert.cert_id,
                student_name      = cert.student_name,
                course            = cert.course,
                institution       = cert.institution,
                issue_date        = cert.issue_date,
                output_path       = pdf_path,
                label             = "VALID",
                sha256_hash       = result_data["sha256_hash"],
                canonical_json_ref= f"{cert.cert_id}.json",
                signature_b64     = result_data["signature_b64"],
                usn               = cert.usn,
            )
            json_path = samples_dir / f"{cert.cert_id}.json"
            json_package = {
                "certificate": cert.to_dict(),
                "sha256_hash": result_data["sha256_hash"],
                "signature":   result_data["signature_b64"],
                "issuer_id":   result_data["issuer_id"],
                "canonical_json": result_data["canonical_json"],
            }
            json_path.write_text(json.dumps(json_package, indent=2), encoding="utf-8")
            result_data["pdf_url"] = f"/download/pdf/{cert.cert_id}"
            result_data["json_url"] = f"/download/json/{cert.cert_id}"
        except FileNotFoundError as e:
            error = str(e)
        except Exception as e:
            print(f"[app] Issue error: {e}")
            error = "Failed to issue certificate. Check server logs."

    return templates.TemplateResponse(request, "issue.html", {
        "admin": True,
        "result": result_data,
        "error": error,
    })


@app.post("/revoke/{cert_id}")
async def revoke_cert(
    cert_id: str,
    request: Request,
    reason: str = Form("Revoked by administrator via registry interface"),
):
    """Revoke a certificate (authenticated only)."""
    if not is_authenticated(request):
        raise HTTPException(status_code=403, detail="Admin authentication required.")

    success = revoke_certificate(cert_id, reason, db_path=DB_PATH)
    if not success:
        raise HTTPException(status_code=404, detail=f"Certificate '{cert_id}' not found.")
    return RedirectResponse(url="/certificates", status_code=302)


@app.post("/update-status/{cert_id}")
async def update_cert_status(
    cert_id: str,
    request: Request,
    status: str = Form(...),
    reason: str = Form(""),
):
    """Edit status: toggle ACTIVE or REVOKED for malpractice."""
    if not is_authenticated(request):
        raise HTTPException(status_code=403, detail="Admin authentication required.")

    revoked_val = 1 if status.strip().upper() == "REVOKED" else 0
    clean_reason = reason.strip() if reason and reason.strip() else ("Credential canceled due to academic malpractice" if revoked_val else "")
    success = update_certificate_status(cert_id, revoked_val, clean_reason, db_path=DB_PATH)
    if not success:
        raise HTTPException(status_code=404, detail=f"Certificate '{cert_id}' not found.")
    return RedirectResponse(url="/certificates", status_code=302)


@app.post("/update-status/{cert_id}")
async def update_cert_status(
    cert_id: str,
    request: Request,
    status: str = Form(...),
    reason: str = Form(""),
):
    """Edit status: toggle ACTIVE or REVOKED for malpractice."""
    if not is_authenticated(request):
        raise HTTPException(status_code=403, detail="Admin authentication required.")

    revoked_val = 1 if status.strip().upper() == "REVOKED" else 0
    clean_reason = reason.strip() if reason and reason.strip() else ("Credential canceled due to academic malpractice" if revoked_val else "")
    success = update_certificate_status(cert_id, revoked_val, clean_reason, db_path=DB_PATH)
    if not success:
        raise HTTPException(status_code=404, detail=f"Certificate '{cert_id}' not found.")
    return RedirectResponse(url="/certificates", status_code=302)


# ─── Certificate File Download Endpoints (PDF & JSON) ─────────────────────────

@app.get("/download/pdf/{cert_id}")
async def download_certificate_pdf(cert_id: str, request: Request):
    """Serve or generate on-the-fly the visual PDF certificate for any registered ID."""
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)

    from database import get_certificate_by_id
    cert = get_certificate_by_id(cert_id, db_path=DB_PATH)
    if not cert:
        raise HTTPException(status_code=404, detail=f"Certificate '{cert_id}' not found.")

    pdf_path = samples_dir / f"{cert_id}.pdf"
    # Also check if named valid_{cert_id}.pdf
    if not pdf_path.exists():
        prefixed_pdf = samples_dir / f"valid_{cert_id}.pdf"
        if prefixed_pdf.exists():
            pdf_path = prefixed_pdf
        else:
            keys = cert.keys() if hasattr(cert, "keys") else []
            cert_usn = cert["usn"] if "usn" in keys and cert["usn"] else ""
            generate_certificate_pdf(
                cert_id           = cert["cert_id"],
                student_name      = cert["student_name"],
                course            = cert["course"],
                institution       = cert["institution"],
                issue_date        = cert["issue_date"],
                output_path       = pdf_path,
                label             = "REVOKED" if cert["revoked"] else "VALID",
                sha256_hash       = cert["sha256_hash"],
                canonical_json_ref= f"{cert_id}.json",
                signature_b64     = base64.b64encode(cert["signature"]).decode("utf-8"),
                usn               = cert_usn,
            )

    return FileResponse(
        str(pdf_path),
        media_type="application/pdf",
        filename=f"{cert_id}.pdf",
    )


@app.get("/download/json/{cert_id}")
async def download_certificate_json(cert_id: str, request: Request):
    """Serve or construct the authoritative signed JSON package for verification upload."""
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)

    from database import get_certificate_by_id
    cert = get_certificate_by_id(cert_id, db_path=DB_PATH)
    if not cert:
        raise HTTPException(status_code=404, detail=f"Certificate '{cert_id}' not found.")

    json_path = samples_dir / f"{cert_id}.json"
    if not json_path.exists():
        prefixed_json = samples_dir / f"valid_{cert_id}.json"
        if prefixed_json.exists():
            json_path = prefixed_json
        else:
            sig_b64 = base64.b64encode(cert["signature"]).decode("utf-8")
            pkg = {
                "certificate": {
                    "cert_id":      cert["cert_id"],
                    "student_name": cert["student_name"],
                    "course":       cert["course"],
                    "institution":  cert["institution"],
                    "issue_date":   cert["issue_date"],
                },
                "sha256_hash":    cert["sha256_hash"],
                "signature":      sig_b64,
                "issuer_id":      cert["issuer_id"],
                "canonical_json": cert["canonical_json"],
            }
            json_path.write_text(json.dumps(pkg, indent=2), encoding="utf-8")

    return FileResponse(
        str(json_path),
        media_type="application/json",
        filename=f"{cert_id}.json",
    )


# ─── Fallback / Utility Routes ────────────────────────────────────────────────

@app.get("/download/samples")
async def download_samples_info(request: Request):
    """Redirect to verify page."""
    return RedirectResponse(url="/verify", status_code=302)


# ─── Server Entrypoint ────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info",
    )
