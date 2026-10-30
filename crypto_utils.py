"""
crypto_utils.py — RSA Key Management, Signing, and Verification

============================================================
BEGINNER'S GUIDE — What is happening here?
============================================================

RSA is a public-key cryptography algorithm. It works with a KEY PAIR:
  - PRIVATE KEY: kept secret by the certificate issuer (our server).
                 Used to CREATE (sign) a digital signature.
  - PUBLIC KEY:  shared with everyone.
                 Used to VERIFY a signature WITHOUT knowing the private key.

The magic: if a signature was made with a private key, only the matching
public key can verify it. You cannot forge a signature without the private key.

RSA-PSS PADDING:
  PSS = Probabilistic Signature Scheme. It adds randomness to each signature
  so two signings of the same data give different signatures, which is more
  secure than the older PKCS#1 v1.5 padding.

SHA-256 HASHING:
  Before signing, we hash the data with SHA-256. Hashing converts any
  amount of data into a fixed 256-bit fingerprint. Even a tiny change in
  data produces a completely different hash. This is how we detect tampering.

CANONICAL JSON:
  JSON allows many equivalent representations of the same data (e.g., different
  key orders, whitespace). We convert certificate data into ONE standard form
  (sorted keys, no extra spaces) before signing so the same data always produces
  the same bytes to sign. This is called "canonicalization".

WORKFLOW:
  Issue:   canonical_json → hash → RSA-sign with private key → store signature
  Verify:  submitted_data → canonical_json → hash → RSA-verify with public key
============================================================
"""

import json
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# ─── Key File Locations ────────────────────────────────────────────────────────
# Keys live in the 'instance/' folder which is NOT served publicly.
BASE_DIR = Path(__file__).parent
INSTANCE_DIR = BASE_DIR / "instance"
PRIVATE_KEY_PATH = INSTANCE_DIR / "private_key.pem"
PUBLIC_KEY_PATH = INSTANCE_DIR / "public_key.pem"

KEY_ISSUER_ID = "VemanaIT-CA-2026"


def ensure_instance_dir() -> None:
    """Create the instance directory if it does not exist."""
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)


def generate_rsa_key_pair() -> None:
    """
    Generate a 2048-bit RSA key pair and save to PEM files.

    This is called ONLY when no key files exist yet.
    RSA-2048 means the modulus n is 2048 bits long — this is the
    security foundation. The private key exponent d is kept secret;
    the public key (n, e=65537) is shared freely.
    """
    ensure_instance_dir()

    # Generate the private key
    private_key: RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,   # Standard value. 65537 = 2^16 + 1, a Fermat prime.
        key_size=2048,           # 2048 bits — NIST recommended minimum.
    )

    # Serialize private key to PEM format (encrypted with no passphrase for simplicity)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Derive the public key from the private key
    public_key: RSAPublicKey = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Write both keys to files
    PRIVATE_KEY_PATH.write_bytes(private_pem)
    PUBLIC_KEY_PATH.write_bytes(public_pem)
    print(f"[crypto_utils] Generated new RSA-2048 key pair.")
    print(f"  Private key -> {PRIVATE_KEY_PATH}")
    print(f"  Public  key -> {PUBLIC_KEY_PATH}")


def load_private_key() -> RSAPrivateKey:
    """
    Load the RSA private key from the PEM file.

    Raises FileNotFoundError if the key file is missing.
    We deliberately do NOT auto-generate here because if trusted records
    already exist in the database, regenerating the key would invalidate
    all existing signatures.
    """
    if not PRIVATE_KEY_PATH.exists():
        raise FileNotFoundError(
            f"Private key not found at {PRIVATE_KEY_PATH}. "
            "Run 'python generate_samples.py' to set up the system."
        )
    key_bytes = PRIVATE_KEY_PATH.read_bytes()
    return serialization.load_pem_private_key(key_bytes, password=None)


def load_public_key() -> RSAPublicKey:
    """
    Load the RSA public key from the PEM file.

    The public key is safe to share and is used for verification only.
    """
    if not PUBLIC_KEY_PATH.exists():
        raise FileNotFoundError(
            f"Public key not found at {PUBLIC_KEY_PATH}. "
            "Run 'python generate_samples.py' to set up the system."
        )
    key_bytes = PUBLIC_KEY_PATH.read_bytes()
    return serialization.load_pem_public_key(key_bytes)


def initialize_keys() -> None:
    """
    Ensure an RSA key pair exists. Generate only if BOTH key files are absent.

    Safety rule: if trusted records exist but keys are missing, we do NOT
    regenerate — that would silently break all existing signatures.
    """
    private_missing = not PRIVATE_KEY_PATH.exists()
    public_missing = not PUBLIC_KEY_PATH.exists()

    if private_missing and public_missing:
        print("[crypto_utils] No keys found — generating a fresh key pair.")
        generate_rsa_key_pair()
    elif private_missing or public_missing:
        raise RuntimeError(
            "One key file is missing while the other exists. "
            "This is a broken state. Check the 'instance/' folder manually. "
            f"Private key exists: {not private_missing}. "
            f"Public key exists: {not public_missing}."
        )
    else:
        print(f"[crypto_utils] RSA key pair already exists — reusing.")


def make_canonical_json(cert_data: dict) -> str:
    """
    Convert a certificate dictionary into canonical (standard) JSON.

    WHY CANONICAL JSON?
    JSON is flexible: {'b':1,'a':2} and {'a':2,'b':1} are equivalent,
    but produce different byte strings. If we sign one form and verify the
    other, verification will FAIL even though the data is identical.

    SOLUTION: Always sort keys alphabetically and strip extra whitespace.
    This gives ONE unique string for each unique set of data.

    Example:
        Input:  {'student_name': 'Ananya', 'cert_id': 'CERT-001'}
        Output: '{"cert_id": "CERT-001", "student_name": "Ananya"}'
    """
    return json.dumps(cert_data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def compute_sha256(data: str) -> str:
    """
    Compute the SHA-256 hash of a string and return it as a hex string.

    SHA-256 is a one-way function: easy to compute hash from data,
    impossible to recover data from hash. Any change in input data
    produces a completely different 256-bit (64 hex character) output.
    """
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def sign_certificate_data(cert_data: dict) -> bytes:
    """
    Sign certificate data using RSA-PSS with SHA-256.

    Steps:
    1. Convert cert_data to canonical JSON string.
    2. Load the private key.
    3. Sign the canonical JSON bytes using RSA-PSS + SHA-256.
    4. Return the raw signature bytes.

    The signature is stored in the database alongside the certificate.
    """
    canonical = make_canonical_json(cert_data)
    private_key = load_private_key()

    signature: bytes = private_key.sign(
        data=canonical.encode('utf-8'),
        # PSS padding with SHA-256 hash and maximum salt length
        padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),   # Mask Generation Function
            salt_length=padding.PSS.MAX_LENGTH,  # Maximum salt for security
        ),
        algorithm=hashes.SHA256(),
    )
    return signature


def verify_certificate_signature(cert_data: dict, signature_bytes: bytes) -> bool:
    """
    Verify that a signature matches the given certificate data.

    Steps:
    1. Convert the submitted cert_data to canonical JSON.
    2. Load the public key.
    3. Ask the public key to verify the signature against the canonical JSON.
    4. Return True if valid, False if the signature doesn't match.

    If someone changes even ONE character of cert_data, the canonical JSON
    changes, the hash changes, and verification FAILS — detecting tampering.
    """
    canonical = make_canonical_json(cert_data)
    public_key = load_public_key()

    try:
        public_key.verify(
            signature=signature_bytes,
            data=canonical.encode('utf-8'),
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            algorithm=hashes.SHA256(),
        )
        return True  # Signature matched — data is authentic and unmodified
    except InvalidSignature:
        return False  # Signature did not match — data was tampered or key mismatch
    except Exception as exc:
        print(f"[crypto_utils] Unexpected error during verification: {exc}")
        return False


def get_public_key_pem() -> str:
    """Return the public key as a PEM string (safe to display publicly)."""
    return PUBLIC_KEY_PATH.read_text()
