"""
pdf_generator.py — High-Fidelity Academic Degree Certificate Generator & PDF Verification
Designed specifically for Vemana Institute of Technology (Affiliated to VTU).
"""

import math
import json
import base64
import re
from pathlib import Path
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.colors import HexColor, white
from reportlab.pdfgen import canvas as pdf_canvas


# ─── Official Academic Color Palette ──────────────────────────────────────────
NAVY_HEADER   = HexColor("#0a192f")   # Regal deep navy for institution & titles
NAVY_TEXT     = HexColor("#1e293b")   # Slate navy for clear readable body text
GOLD_RICH     = HexColor("#b8860b")   # Traditional academic gold / bronze
GOLD_LIGHT    = HexColor("#c59b27")   # Highlight gold for borders & seals
BG_IVORY      = HexColor("#fdfcf9")   # Soft archival parchment ivory
WATERMARK_CLR = HexColor("#f4f0e6")   # Faint watermark background tint
INK_BLUE      = HexColor("#152d4a")   # Realistic fountain-pen blue for signatures
MUTED_SLATE   = HexColor("#64748b")   # Subdued metadata & descriptors


def draw_corner_ornament(c: pdf_canvas.Canvas, x: float, y: float, size: float, orientation: tuple):
    """Draw a traditional corner rosette ornament on the certificate borders."""
    ox, oy = orientation
    c.saveState()
    c.setStrokeColor(GOLD_RICH)
    c.setFillColor(GOLD_RICH)
    c.setLineWidth(1.0)
    
    # Corner square accent
    c.rect(x - (size / 2.0), y - (size / 2.0), size, size, fill=1, stroke=0)
    
    # Corner bracket accents
    c.setLineWidth(1.2)
    c.line(x, y, x + (ox * size * 2.2), y)
    c.line(x, y, x, y + (oy * size * 2.2))
    
    # Small corner diamond
    dx = x + (ox * size * 1.2)
    dy = y + (oy * size * 1.2)
    p = c.beginPath()
    p.moveTo(dx, dy + 2)
    p.lineTo(dx + 2, dy)
    p.lineTo(dx, dy - 2)
    p.lineTo(dx - 2, dy)
    p.close()
    c.drawPath(p, fill=1, stroke=0)
    
    c.restoreState()


def draw_watermark(c: pdf_canvas.Canvas, cx: float, cy: float):
    """Draw an authentic faint institutional crest watermark in the certificate center."""
    c.saveState()
    c.setStrokeColor(WATERMARK_CLR)
    c.setFillColor(WATERMARK_CLR)
    
    # Concentric watermark circles
    c.setLineWidth(2.5)
    c.circle(cx, cy, 108, fill=0, stroke=1)
    c.setLineWidth(1.0)
    c.circle(cx, cy, 98, fill=0, stroke=1)
    c.circle(cx, cy, 65, fill=0, stroke=1)
    
    # Center watermark crest text
    c.setFont("Times-Bold", 14)
    c.drawCentredString(cx, cy + 28, "VEMANA I.T.")
    c.setFont("Times-Roman", 9)
    c.drawCentredString(cx, cy + 12, "ESTABLISHED 1999")
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(cx, cy - 6, "★ ★ ★")
    c.setFont("Times-Roman", 8)
    c.drawCentredString(cx, cy - 22, "VERITAS & SCIENTIA")
    c.restoreState()


def draw_gold_seal(c: pdf_canvas.Canvas, cx: float, cy: float):
    """Draw a gold ceremonial institutional degree seal."""
    c.saveState()
    
    # Outer sawtooth / star perimeter dots
    c.setFillColor(GOLD_RICH)
    num_dots = 28
    radius = 33.0
    for i in range(num_dots):
        angle = (2.0 * math.pi * i) / num_dots
        dx = cx + (radius * math.cos(angle))
        dy = cy + (radius * math.sin(angle))
        c.circle(dx, dy, 1.2, fill=1, stroke=0)
    
    # Double gold ring
    c.setStrokeColor(GOLD_RICH)
    c.setLineWidth(1.8)
    c.circle(cx, cy, 30.5, fill=0, stroke=1)
    c.setLineWidth(0.8)
    c.circle(cx, cy, 27.0, fill=0, stroke=1)
    
    # Inner seal fill
    c.setFillColor(HexColor("#faf4e6"))
    c.circle(cx, cy, 26.0, fill=1, stroke=0)
    
    # Inner seal typography
    c.setFillColor(NAVY_HEADER)
    c.setFont("Helvetica-Bold", 6.0)
    c.drawCentredString(cx, cy + 11, "VEMANA IT")
    c.setFillColor(GOLD_RICH)
    c.setFont("Times-Bold", 7.5)
    c.drawCentredString(cx, cy + 1, "★ SEAL ★")
    c.setFillColor(NAVY_HEADER)
    c.setFont("Helvetica-Bold", 5.5)
    c.drawCentredString(cx, cy - 9, "OFFICIAL DEGREE")
    c.setFont("Times-Roman", 5.0)
    c.drawCentredString(cx, cy - 16, "BENGALURU")
    
    c.restoreState()


def draw_pen_signature(c: pdf_canvas.Canvas, x: float, y: float, style: int = 1):
    """Draw a stylized, natural fountain-pen ink signature above the signature line."""
    c.saveState()
    c.setStrokeColor(INK_BLUE)
    c.setLineWidth(1.1)
    p = c.beginPath()
    
    if style == 1:
        # Head of Department signature flourish
        p.moveTo(x - 42, y + 2)
        p.curveTo(x - 28, y + 20, x - 18, y - 6, x - 2, y + 16)
        p.curveTo(x + 10, y - 8, x + 22, y + 18, x + 38, y + 4)
        p.moveTo(x - 34, y - 4)
        p.curveTo(x - 8, y - 8, x + 16, y - 3, x + 44, y - 5)
    else:
        # Principal signature flourish
        p.moveTo(x - 45, y)
        p.curveTo(x - 30, y + 22, x - 15, y + 4, x + 2, y + 18)
        p.curveTo(x + 14, y - 6, x + 28, y + 14, x + 46, y + 2)
        p.moveTo(x - 40, y - 5)
        p.curveTo(x - 10, y - 9, x + 20, y - 5, x + 48, y - 7)
        
    c.drawPath(p, fill=0, stroke=1)
    c.restoreState()


def generate_certificate_pdf(
    cert_id: str,
    student_name: str,
    course: str,
    institution: str = "Vemana Institute of Technology",
    issue_date: str = "01 October 2026",
    output_path: Path = None,
    label: str = "VALID",
    sha256_hash: str = "",
    canonical_json_ref: str = "",
    signature_b64: str = "",
    usn: str = "",
) -> Path:
    """
    Generate an authentic, masterfully aligned landscape academic degree certificate,
    embedding the cryptographic digital signature payload directly into the document metadata.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    c = pdf_canvas.Canvas(str(output_path), pagesize=landscape(A4))
    width, height = landscape(A4)  # 841.89 x 595.28 pt
    cx = width / 2.0               # Center X: 420.95 pt

    # Embed Cryptographic Payload in PDF Metadata
    payload = {
        "certificate": {
            "cert_id": cert_id,
            "student_name": student_name,
            "usn": usn.strip() if usn else "",
            "course": course,
            "institution": institution,
            "issue_date": issue_date,
        },
        "sha256_hash": sha256_hash,
        "signature": signature_b64,
        "issuer_id": "VemanaIT-CA-2026",
        "canonical_json_ref": canonical_json_ref,
    }
    b64_payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    c.setTitle(f"CERTIFICATE-{cert_id}")
    c.setAuthor(institution)
    c.setSubject(b64_payload)

    # 1. Background Fill
    c.setFillColor(BG_IVORY)
    c.rect(0, 0, width, height, fill=1, stroke=0)

    # 2. Central Watermark
    draw_watermark(c, cx, 280)

    # 3. Triple Multi-Layer Architectural Borders
    b_out = 20.0
    c.setStrokeColor(NAVY_HEADER)
    c.setLineWidth(1.0)
    c.rect(b_out, b_out, width - 2 * b_out, height - 2 * b_out, fill=0, stroke=1)

    b_mid = b_out + 4.5
    c.setStrokeColor(GOLD_RICH)
    c.setLineWidth(2.5)
    c.rect(b_mid, b_mid, width - 2 * b_mid, height - 2 * b_mid, fill=0, stroke=1)

    b_in = b_mid + 4.5
    c.setStrokeColor(NAVY_HEADER)
    c.setLineWidth(0.75)
    c.rect(b_in, b_in, width - 2 * b_in, height - 2 * b_in, fill=0, stroke=1)

    # 4. Corner Rosette Ornaments
    orn_dist = b_mid
    orn_size = 5.0
    draw_corner_ornament(c, orn_dist, height - orn_dist, orn_size, (1, -1))           # Top Left
    draw_corner_ornament(c, width - orn_dist, height - orn_dist, orn_size, (-1, -1))  # Top Right
    draw_corner_ornament(c, orn_dist, orn_dist, orn_size, (1, 1))                    # Bottom Left
    draw_corner_ornament(c, width - orn_dist, orn_dist, orn_size, (-1, 1))           # Bottom Right

    # 5. Top Header Section
    c.setFillColor(GOLD_RICH)
    c.setFont("Helvetica-Bold", 8.5)
    c.drawCentredString(cx, 536, "KARNATAKA REDDY JANA SANGHA (KRJS)")

    inst_name = (institution or "Vemana Institute of Technology").strip()
    c.setFillColor(NAVY_HEADER)
    c.setFont("Times-Bold", 24)
    c.drawCentredString(cx, 508, inst_name.upper())

    c.setFillColor(MUTED_SLATE)
    c.setFont("Times-Roman", 9.5)
    c.drawCentredString(cx, 492, "Affiliated to Visvesvaraya Technological University, Belagavi  •  Approved by AICTE, New Delhi")
    c.setFont("Times-Roman", 8.5)
    c.drawCentredString(cx, 479, "Accredited by NAAC & NBA  |  Koramangala, Bengaluru - 560034, Karnataka, India")

    # Divider bar with center ornamental diamond
    c.setStrokeColor(GOLD_LIGHT)
    c.setLineWidth(1.0)
    c.line(cx - 190, 468, cx - 10, 468)
    c.line(cx + 10, 468, cx + 190, 468)
    p = c.beginPath()
    p.moveTo(cx, 471)
    p.lineTo(cx + 4, 468)
    p.lineTo(cx, 465)
    p.lineTo(cx - 4, 468)
    p.close()
    c.setFillColor(GOLD_RICH)
    c.drawPath(p, fill=1, stroke=0)

    # 6. Department Line
    c.setFillColor(HexColor("#1b365d"))
    c.setFont("Helvetica-Bold", 10.5)
    c.drawCentredString(cx, 450, "DEPARTMENT OF INFORMATION SCIENCE AND ENGINEERING")

    # 7. Certificate Degree Title
    c.setFillColor(NAVY_HEADER)
    c.setFont("Times-BoldItalic", 21)
    c.drawCentredString(cx, 420, "Degree of Bachelor of Engineering")

    # Flourish line under Degree
    c.setFillColor(GOLD_RICH)
    c.setFont("Times-Roman", 9)
    c.drawCentredString(cx, 404, "— ❖ —")

    # 8. Preamble
    c.setFillColor(NAVY_TEXT)
    c.setFont("Times-Italic", 12.5)
    c.drawCentredString(cx, 384, "This is to certify that")

    # 9. Student Recipient Name
    c.setFillColor(NAVY_HEADER)
    c.setFont("Times-Bold", 26)
    c.drawCentredString(cx, 348, student_name)

    # Majestic gold accent rule beneath the name
    name_w = c.stringWidth(student_name, "Times-Bold", 26)
    rule_half = max(name_w / 2.0 + 20, 110)
    c.setStrokeColor(GOLD_RICH)
    c.setLineWidth(1.4)
    c.line(cx - rule_half, 341, cx + rule_half, 341)
    c.circle(cx - rule_half, 341, 1.5, fill=1, stroke=0)
    c.circle(cx + rule_half, 341, 1.5, fill=1, stroke=0)

    # 10. Student Registration & Seat Number
    c.setFillColor(MUTED_SLATE)
    c.setFont("Helvetica-Bold", 9.0)
    usn_display = usn.strip() if usn and usn.strip() else f"1VI22IS{cert_id[-3:] if len(cert_id)>=3 else '001'}"
    usn_text = f"USN: {usn_display}   |   Certificate ID: {cert_id}"
    c.drawCentredString(cx, 325, usn_text)

    # 11. Conferment Text
    c.setFillColor(NAVY_TEXT)
    c.setFont("Times-Roman", 11.5)
    c.drawCentredString(cx, 298, "having fulfilled all academic requirements and passed the prescribed examinations")
    c.drawCentredString(cx, 282, "has been duly admitted to the degree of")

    # 12. Course Name
    c.setFillColor(HexColor("#1b365d"))
    c.setFont("Times-Bold", 14.5)
    c.drawCentredString(cx, 260, course)

    # 13. Honors & Award Date
    c.setFillColor(NAVY_TEXT)
    c.setFont("Times-Roman", 11.0)
    honors_text = f"with First Class with Distinction, awarded at Bengaluru on {issue_date}."
    c.drawCentredString(cx, 240, honors_text)

    # 14. Ceremonial Gold Seal (Centered between signatures)
    seal_y = 156
    draw_gold_seal(c, cx, seal_y)
    c.setFillColor(MUTED_SLATE)
    c.setFont("Helvetica-Bold", 7.0)
    c.drawCentredString(cx, seal_y - 39, "OFFICIAL INSTITUTIONAL SEAL")

    # 15. Signatures (Left: HOD, Right: Principal)
    sig_line_y = 150
    sig_w = 160.0

    # Left: Head of Department
    left_cx = 185.0
    draw_pen_signature(c, left_cx, sig_line_y + 16, style=1)
    c.setStrokeColor(NAVY_HEADER)
    c.setLineWidth(0.8)
    c.line(left_cx - sig_w / 2.0, sig_line_y, left_cx + sig_w / 2.0, sig_line_y)
    
    c.setFillColor(NAVY_HEADER)
    c.setFont("Times-Bold", 10.5)
    c.drawCentredString(left_cx, sig_line_y - 14, "Dr. Rajanna M")
    c.setFillColor(MUTED_SLATE)
    c.setFont("Times-Roman", 8.5)
    c.drawCentredString(left_cx, sig_line_y - 25, "Professor & Head of Department")
    c.drawCentredString(left_cx, sig_line_y - 35, "Dept. of Information Science & Engineering")

    # Right: Principal
    right_cx = width - 185.0
    draw_pen_signature(c, right_cx, sig_line_y + 16, style=2)
    c.setStrokeColor(NAVY_HEADER)
    c.setLineWidth(0.8)
    c.line(right_cx - sig_w / 2.0, sig_line_y, right_cx + sig_w / 2.0, sig_line_y)
    
    c.setFillColor(NAVY_HEADER)
    c.setFont("Times-Bold", 10.5)
    c.drawCentredString(right_cx, sig_line_y - 14, "Dr. Chandra Shekar S. M.")
    c.setFillColor(MUTED_SLATE)
    c.setFont("Times-Roman", 8.5)
    c.drawCentredString(right_cx, sig_line_y - 25, "Principal")
    c.drawCentredString(right_cx, sig_line_y - 35, "Vemana Institute of Technology")

    # 16. Security & Cryptographic Integrity Footer Bar
    bar_y = 66
    c.setStrokeColor(HexColor("#cbd5e1"))
    c.setLineWidth(0.6)
    c.line(b_in + 12, bar_y, width - b_in - 12, bar_y)

    c.setFillColor(NAVY_HEADER)
    c.setFont("Helvetica-Bold", 7.5)
    sec_banner = f"CERTIFICATE VERIFICATION CODE: {cert_id}   •   SECURITY: RSA-2048 / SHA-256 PSS DIGITAL SIGNATURE"
    c.drawCentredString(cx, 53, sec_banner)

    if sha256_hash:
        c.setFont("Courier", 6.8)
        c.setFillColor(MUTED_SLATE)
        digest_str = f"Authoritative SHA-256 Fingerprint: {sha256_hash}"
        c.drawCentredString(cx, 42, digest_str)

    c.save()
    print(f"[pdf_generator] Masterpiece certificate saved -> {output_path}")
    return output_path


def extract_certificate_from_pdf(pdf_bytes: bytes) -> dict | None:
    """
    Extract the embedded authoritative cryptographic certificate package
    from a certificate PDF.
    """
    # 1. Look for base64 encoded payload in /Subject
    match = re.search(rb'/Subject\s*\(([A-Za-z0-9+/=]+)\)', pdf_bytes)
    if match:
        try:
            b64_str = match.group(1).decode('ascii')
            raw_bytes = base64.b64decode(b64_str.encode('ascii'))
            data = json.loads(raw_bytes.decode('utf-8'))
            if isinstance(data, dict):
                return data
        except Exception as e:
            print(f"[pdf_generator] Error decoding base64 metadata: {e}")

    # 2. Fallback: look for direct JSON payload in /Subject
    match2 = re.search(rb'/Subject\s*\((.*?)\)', pdf_bytes)
    if match2:
        try:
            raw = match2.group(1).decode('utf-8', errors='ignore')
            data = json.loads(raw)
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    return None
