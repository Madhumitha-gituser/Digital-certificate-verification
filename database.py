"""
database.py — SQLite Database Setup and Queries

============================================================
BEGINNER'S GUIDE
============================================================
SQLite is a lightweight, file-based database — no server needed.
Python has sqlite3 built-in, so nothing extra to install.

PARAMETERIZED QUERIES:
  We ALWAYS use ? placeholders instead of string formatting.
  WRONG (SQL injection risk):  f"SELECT * FROM certs WHERE id='{user_input}'"
  RIGHT (safe):                "SELECT * FROM certs WHERE id=?", (user_input,)
  This prevents malicious input like: cert_id = "'; DROP TABLE certificates;--"

SCHEMA:
  certificates — stores trusted, issued certificates and their signatures.
  admin_users  — stores admin login credentials.
============================================================
"""

import sqlite3
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).parent
INSTANCE_DIR = BASE_DIR / "instance"
DB_PATH = INSTANCE_DIR / "certificates.db"

# Separate database for tests so tests never touch production data
TEST_DB_PATH = INSTANCE_DIR / "test_certificates.db"


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """
    Open a SQLite connection with foreign key support enabled.
    Returns rows as sqlite3.Row objects (accessible by column name).
    """
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row   # row['column_name'] instead of row[0]
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Path = DB_PATH) -> None:
    """
    Create the database tables if they don't already exist.

    CREATE TABLE IF NOT EXISTS means this is SAFE to call on every startup —
    it won't destroy data that already exists.
    """
    conn = get_connection(db_path)
    with conn:
        # ── Trusted Certificate Store ──────────────────────────────────────────
        conn.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                cert_id         TEXT    NOT NULL UNIQUE,   -- e.g. CERT-2026-001
                student_name    TEXT    NOT NULL,
                usn             TEXT    DEFAULT '',        -- University Seat Number (e.g. 1VI22IS045)
                course          TEXT    NOT NULL,
                institution     TEXT    NOT NULL,
                issue_date      TEXT    NOT NULL,
                canonical_json  TEXT    NOT NULL,          -- the exact signed JSON
                sha256_hash     TEXT    NOT NULL,          -- SHA-256 of canonical_json
                signature       BLOB    NOT NULL,          -- raw RSA-PSS signature bytes
                issuer_id       TEXT    NOT NULL,          -- identifier of the signing CA
                issued_at       TEXT    NOT NULL,          -- ISO-8601 timestamp
                revoked         INTEGER NOT NULL DEFAULT 0,  -- 0=active, 1=revoked
                revoke_reason   TEXT
            )
        """)

        # Schema migration check: ensure 'usn' column exists on existing databases
        cols = [r[1] for r in conn.execute("PRAGMA table_info(certificates)").fetchall()]
        if "usn" not in cols and len(cols) > 0:
            conn.execute("ALTER TABLE certificates ADD COLUMN usn TEXT DEFAULT ''")

        # ── Admin Users ────────────────────────────────────────────────────────
        conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT    NOT NULL UNIQUE,
                password_hash   TEXT    NOT NULL,
                created_at      TEXT    NOT NULL
            )
        """)

        # ── Create default admin if table is empty ─────────────────────────────
        existing = conn.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0]
        if existing == 0:
            import hashlib
            pw_hash = hashlib.sha256(b"admin123").hexdigest()
            conn.execute(
                "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?, ?, ?)",
                ("admin", pw_hash, datetime.now(timezone.utc).isoformat()),
            )
    conn.close()
    print(f"[database] Database ready at {db_path}")


def insert_certificate(
    cert_id: str,
    student_name: str,
    course: str,
    institution: str,
    issue_date: str,
    canonical_json: str,
    sha256_hash: str,
    signature: bytes,
    issuer_id: str,
    usn: str = '',
    db_path: Path = DB_PATH,
) -> bool:
    """
    Insert a new trusted certificate record.
    Returns True if inserted, False if the cert_id already exists.
    """
    conn = get_connection(db_path)
    issued_at = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO certificates
                    (cert_id, student_name, usn, course, institution, issue_date,
                     canonical_json, sha256_hash, signature, issuer_id, issued_at, revoked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (cert_id, student_name, usn, course, institution, issue_date,
                 canonical_json, sha256_hash, signature, issuer_id, issued_at),
            )
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_certificate_by_id(cert_id: str, db_path: Path = DB_PATH) -> sqlite3.Row | None:
    """
    Look up a trusted certificate by its cert_id.
    Returns the full database row, or None if not found.
    """
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM certificates WHERE cert_id = ?",
            (cert_id,),
        ).fetchone()
        return row
    finally:
        conn.close()


def get_all_certificates(db_path: Path = DB_PATH) -> list:
    """Return all trusted certificate records (for the admin list view)."""
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM certificates ORDER BY issued_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def revoke_certificate(cert_id: str, reason: str, db_path: Path = DB_PATH) -> bool:
    """
    Mark a certificate as revoked.
    Returns True if the record was found and updated.
    """
    return update_certificate_status(cert_id, 1, reason, db_path=db_path)


def update_certificate_status(cert_id: str, revoked: int, reason: str = "", db_path: Path = DB_PATH) -> bool:
    """
    Update the status (ACTIVE or REVOKED) and optional reason for a certificate.
    """
    conn = get_connection(db_path)
    try:
        with conn:
            clean_reason = reason.strip() if reason and reason.strip() else ("Revoked due to academic malpractice" if revoked else None)
            cursor = conn.execute(
                "UPDATE certificates SET revoked = ?, revoke_reason = ? WHERE cert_id = ?",
                (revoked, clean_reason if revoked else None, cert_id),
            )
        return cursor.rowcount > 0
    finally:
        conn.close()


def verify_admin_password(username: str, password: str, db_path: Path = DB_PATH) -> bool:
    """Check username/password against the admin_users table."""
    import hashlib
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT id FROM admin_users WHERE username = ? AND password_hash = ?",
            (username, pw_hash),
        ).fetchone()
        return row is not None
    finally:
        conn.close()
