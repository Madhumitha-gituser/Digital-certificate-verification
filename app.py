"""
app.py — FastAPI Web Application: Digital Certificate Verification System

============================================================
BEGINNER'S GUIDE
============================================================
FastAPI is a modern Python web framework that:
  - Automatically validates request data using Python type hints.
  - Auto-generates API documentation at /docs.
  - Uses async functions for high performance.
  - Renders HTML templates using Jinja2.

KEY ROUTES:
  GET  /              → Home page
  GET  /about         → About / how it works page
  GET  /issue         → Issue certificate form (admin only)
  POST /issue         → Submit new certificate
  GET  /certificates  → List all trusted certificates (admin only)
  GET  /verify        → Upload JSON package for verification
  POST /verify        → Process verification, show result
  GET  /login         → Admin login form
  POST /login         → Process login
  GET  /logout        → Clear session
  POST /revoke/{id}   → Revoke a certificate (admin only)

SESSIONS:
  We use a simple signed cookie (via Starlette's SessionMiddleware) to
  track whether an admin is logged in.

TEMPLATE ENGINE:
  Jinja2 renders HTML templates from the templates/ folder.
  The app passes data (like verification results) to templates as variables.
============================================================
"""

import json
import base64
import os
from pathlib import Path
from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from crypto_utils import initialize_keys, get_public_key_pem
from database import init_db, get_all_certificates, revoke_certificate, verify_admin_password, DB_PATH
from certificate_service import (
    CertificateData,
    issue_certificate,
    verify_certificate,
    VerificationResult,
)

# ─── App Initialisation ───────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent

app = FastAPI(
    title="CertVerify — Digital Certificate Verification System",
    description="Educational demonstration of digital certificate verification using RSA-2048 and SHA-256.",
    version="1.0.0",
)

# Session middleware: uses a secret key to sign cookies.
# In production, use a long random secret from environment variables.
SESSION_SECRET = os.environ.get("SESSION_SECRET", "ins-demo-secret-key-2026-change-in-prod")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

# Static files (CSS, JS, images)
static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Sample certificates served as downloadable files
samples_dir = BASE_DIR / "sample_certificates"
samples_dir.mkdir(exist_ok=True)
app.mount("/samples", StaticFiles(directory=str(samples_dir)), name="samples")

# Jinja2 templates
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


# ─── Startup: Init keys and DB ────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    """Run once when the server starts: ensure keys and DB exist."""
    print("[app] Starting Digital Certificate Verification System...")
    try:
        initialize_keys()
    except RuntimeError as e:
        print(f"[app] WARNING: Key initialisation issue: {e}")
    init_db(DB_PATH)
    print("[app] Server ready at http://127.0.0.1:8000")


# ─── Helper: Admin Auth Check ─────────────────────────────────────────────────

def is_admin(request: Request) -> bool:
    """Return True if the current session has admin access."""
    return request.session.get("is_admin", False)


def require_admin(request: Request):
    """Raise 403 if not logged in as admin."""
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Admin access required. Please log in.")


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page: explains the project and provides navigation."""
    return templates.TemplateResponse("home.html", {
        "request": request,
        "admin": is_admin(request),
    })


@app.get("/about", response_class=HTMLResponse)
async def about(request: Request):
    """About page: explains RSA, SHA-256, and the verification workflow."""
    try:
        pub_key_pem = get_public_key_pem()
    except FileNotFoundError:
        pub_key_pem = "(Public key not yet generated — run generate_samples.py)"

    return templates.TemplateResponse("about.html", {
        "request": request,
        "admin": is_admin(request),
        "public_key_pem": pub_key_pem,
    })


@app.get("/verify", response_class=HTMLResponse)
async def verify_page(request: Request):
    """GET: Show the certificate verification / upload form."""
    return templates.TemplateResponse("verify.html", {
        "request": request,
        "admin": is_admin(request),
        "result": None,
    })


@app.post("/verify", response_class=HTMLResponse)
async def verify_post(
    request: Request,
    json_file: UploadFile = File(None),
    cert_id: str = Form(""),
    student_name: str = Form(""),
    course: str = Form(""),
    institution: str = Form(""),
    issue_date: str = Form(""),
):
    """
    POST: Process certificate verification.

    Supports two input methods:
    1. Upload a JSON package file (the companion .json from generate_samples.py)
    2. Manually enter certificate fields in a form

    If a JSON file is uploaded, its 'certificate' field is extracted and verified.
    If only form fields are provided, those are verified directly.

    IMPORTANT: We verify the actual certificate fields — not just a file name or ID.
    """
    error_msg = None
    result: VerificationResult | None = None
    submitted_fields = {}

    try:
        if json_file and json_file.filename and json_file.filename.endswith(".json"):
            # ── JSON Package Upload ────────────────────────────────────────────
            content = await json_file.read()
            if len(content) > 1_000_000:  # 1 MB limit
                raise ValueError("Uploaded file is too large (max 1 MB).")

            try:
                package = json.loads(content.decode("utf-8"))
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON file: {e}")

            # Extract the 'certificate' block — this is the authoritative data
            if "certificate" not in package:
                raise ValueError("JSON file missing 'certificate' block.")

            cert_block = package["certificate"]

            # Validate that all required fields are present
            required_fields = ["cert_id", "student_name", "course", "institution", "issue_date"]
            for field in required_fields:
                if field not in cert_block:
                    raise ValueError(f"Missing field in certificate block: '{field}'")

            submitted_fields = cert_block

        elif cert_id.strip():
            # ── Manual Form Entry ──────────────────────────────────────────────
            submitted_fields = {
                "cert_id":      cert_id.strip(),
                "student_name": student_name.strip(),
                "course":       course.strip(),
                "institution":  institution.strip(),
                "issue_date":   issue_date.strip(),
            }
        else:
            error_msg = "Please upload a JSON certificate package or enter certificate details manually."

        if submitted_fields and not error_msg:
            # Run the actual cryptographic verification
            result = verify_certificate(submitted_fields, db_path=DB_PATH)

    except ValueError as e:
        error_msg = str(e)
    except Exception as e:
        # Never expose internal errors to users
        print(f"[app] Verification error: {e}")
        error_msg = "An error occurred during verification. Please check the uploaded file."

    return templates.TemplateResponse("verify.html", {
        "request": request,
        "admin": is_admin(request),
        "result": result,
        "error_msg": error_msg,
        "submitted": submitted_fields,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN: LOGIN / LOGOUT
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if is_admin(request):
        return RedirectResponse(url="/certificates", status_code=302)
    return templates.TemplateResponse("login.html", {
        "request": request,
        "admin": False,
        "error": None,
    })


@app.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    """Verify admin credentials and set session flag."""
    if verify_admin_password(username, password, db_path=DB_PATH):
        request.session["is_admin"] = True
        request.session["username"] = username
        return RedirectResponse(url="/certificates", status_code=302)
    else:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "admin": False,
            "error": "Invalid username or password.",
        })


@app.get("/logout")
async def logout(request: Request):
    """Clear the admin session."""
    request.session.clear()
    return RedirectResponse(url="/", status_code=302)


# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN: CERTIFICATE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/certificates", response_class=HTMLResponse)
async def list_certificates(request: Request):
    """Show all trusted certificates in the database (admin only)."""
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=302)

    certs = get_all_certificates(db_path=DB_PATH)
    return templates.TemplateResponse("certificates.html", {
        "request": request,
        "admin": True,
        "certificates": certs,
    })


@app.get("/issue", response_class=HTMLResponse)
async def issue_page(request: Request):
    """Show the issue-certificate form (admin only)."""
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("issue.html", {
        "request": request,
        "admin": True,
        "result": None,
        "error": None,
    })


@app.post("/issue", response_class=HTMLResponse)
async def issue_post(
    request: Request,
    cert_id: str = Form(...),
    student_name: str = Form(...),
    course: str = Form(...),
    institution: str = Form(...),
    issue_date: str = Form(...),
):
    """Issue a new certificate: sign it and store in the trusted database."""
    if not is_admin(request):
        return RedirectResponse(url="/login", status_code=302)

    error = None
    result_data = None

    # Basic validation
    if not all([cert_id.strip(), student_name.strip(), course.strip(),
                institution.strip(), issue_date.strip()]):
        error = "All fields are required."
    else:
        try:
            cert = CertificateData(
                cert_id      = cert_id.strip(),
                student_name = student_name.strip(),
                course       = course.strip(),
                institution  = institution.strip(),
                issue_date   = issue_date.strip(),
            )
            result_data = issue_certificate(cert, db_path=DB_PATH)
        except FileNotFoundError as e:
            error = str(e)
        except Exception as e:
            print(f"[app] Issue error: {e}")
            error = "Failed to issue certificate. Check server logs."

    return templates.TemplateResponse("issue.html", {
        "request": request,
        "admin": True,
        "result": result_data,
        "error": error,
    })


@app.post("/revoke/{cert_id}")
async def revoke_cert(
    cert_id: str,
    request: Request,
    reason: str = Form("Revoked by administrator"),
):
    """Revoke a certificate (admin only)."""
    if not is_admin(request):
        raise HTTPException(status_code=403, detail="Admin access required.")

    success = revoke_certificate(cert_id, reason, db_path=DB_PATH)
    if not success:
        raise HTTPException(status_code=404, detail=f"Certificate '{cert_id}' not found.")
    return RedirectResponse(url="/certificates", status_code=302)


# ─── Sample File Downloads ────────────────────────────────────────────────────

@app.get("/download/samples")
async def download_samples_info(request: Request):
    """Redirect to the samples directory listing."""
    return RedirectResponse(url="/", status_code=302)


# ─── Run the server ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="127.0.0.1",
        port=8000,
        reload=True,      # Auto-reloads when code changes (development mode)
        log_level="info",
    )

