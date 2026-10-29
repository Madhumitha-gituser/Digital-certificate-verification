"""
pdf_generator.py — Generate Certificate PDFs using ReportLab

============================================================
BEGINNER'S GUIDE
============================================================
ReportLab is a Python library that creates PDF files programmatically.
We use it to draw text, lines, and shapes onto a "canvas" (like a
virtual page), then save it as a PDF.

The PDF is a VISUAL REPRESENTATION of the certificate.
The JSON signed-data file is the AUTHORITATIVE CRYPTOGRAPHIC RECORD.

IMPORTANT: We do NOT use PDF digital signatures (that requires
separate infrastructure like Adobe Acrobat's signing). Instead, we
include a visible QR-code text / verification note in the PDF, and
the actual cryptographic proof lives in the companion .json file.

The PDF includes an "EDUCATIONAL DEMO" warning as required.
============================================================
"""

import textwrap
from pathlib import Path
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.colors import HexColor, white, black
from reportlab.pdfgen import canvas as pdf_canvas


# ─── Color Palette ────────────────────────────────────────────────────────────
DARK_BLUE   = HexColor("#1a237e")   # Header background
GOLD        = HexColor("#ffd700")   # Accent / border
LIGHT_GRAY  = HexColor("#f5f5f5")   # Body background
RED_WARNING = HexColor("#c62828")   # Warning banner
MED_BLUE    = HexColor("#283593")   # Sub-heading


def generate_certificate_pdf(
    cert_id: str,
    student_name: str,
    course: str,
    institution: str,
    issue_date: str,
    output_path: Path,
    label: str = "VALID",          # "VALID", "TAMPERED", "UNKNOWN"
    sha256_hash: str = "",         # first 32 chars shown in PDF
    canonical_json_ref: str = "",  # filename of the companion .json
) -> Path:
    """
    Generate a certificate PDF.

    Parameters
    ----------
    cert_id          : Certificate unique identifier
    student_name     : Recipient's name (what is displayed on the PDF)
    course           : Academic programme
    institution      : Issuing institution name
    issue_date       : Human-readable date string
    output_path      : Where to save the PDF
    label            : Badge label shown at the top-right ("VALID", "TAMPERED", "UNKNOWN")
    sha256_hash      : First 32 characters of the SHA-256 hash (displayed for reference)
    canonical_json_ref : Filename of the companion signed JSON (for verification link)

    Returns the output_path on success.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    c = pdf_canvas.Canvas(str(output_path), pagesize=A4)
    width, height = A4   # 595.27 x 841.89 points

    # ── Background ────────────────────────────────────────────────────────────
    c.setFillColor(LIGHT_GRAY)
    c.rect(0, 0, width, height, fill=1, stroke=0)

    # ── Gold border frame ─────────────────────────────────────────────────────
    margin = 1.2 * cm
    c.setStrokeColor(GOLD)
    c.setLineWidth(6)
    c.rect(margin, margin, width - 2 * margin, height - 2 * margin, fill=0, stroke=1)
    c.setLineWidth(2)
    inner = margin + 0.3 * cm
    c.rect(inner, inner, width - 2 * inner, height - 2 * inner, fill=0, stroke=1)

    # ── Dark blue header band ─────────────────────────────────────────────────
    header_top    = height - margin
    header_bottom = height - 5.5 * cm
    c.setFillColor(DARK_BLUE)
    c.rect(margin, header_bottom, width - 2 * margin, header_top - header_bottom, fill=1, stroke=0)

    # ── Educational Demo Warning Banner ───────────────────────────────────────
    # Required on all PDFs (per project spec)
    c.setFillColor(RED_WARNING)
    c.rect(margin, header_top - 0.9 * cm, width - 2 * margin, 0.85 * cm, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 9)
    warning_text = "⚠  EDUCATIONAL DEMO — NOT AN OFFICIAL CERTIFICATE  ⚠"
    c.drawCentredString(width / 2, header_top - 0.65 * cm, warning_text)

    # ── Header: Institution name ───────────────────────────────────────────────
    c.setFillColor(GOLD)
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(width / 2, height - 3.8 * cm, institution.upper())

    c.setFillColor(white)
    c.setFont("Helvetica", 11)
    c.drawCentredString(width / 2, height - 4.5 * cm,
                        "Department of Information Science and Engineering")

    # ── Status Badge (top-right) ───────────────────────────────────────────────
    badge_colors = {
        "VALID":    HexColor("#2e7d32"),  # green
        "TAMPERED": HexColor("#b71c1c"),  # red
        "UNKNOWN":  HexColor("#e65100"),  # orange
    }
    badge_color = badge_colors.get(label, HexColor("#616161"))
    bx, by = width - margin - 3.5 * cm, height - margin - 1.5 * cm
    c.setFillColor(badge_color)
    c.roundRect(bx, by, 3.2 * cm, 1.0 * cm, radius=0.2 * cm, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(bx + 1.6 * cm, by + 0.3 * cm, label)

    # ── "Certificate of Achievement" title ────────────────────────────────────
    c.setFillColor(DARK_BLUE)
    c.setFont("Helvetica-Bold", 26)
    c.drawCentredString(width / 2, height - 7.5 * cm, "Certificate of Achievement")

    c.setFillColor(MED_BLUE)
    c.setFont("Helvetica-Oblique", 13)
    c.drawCentredString(width / 2, height - 8.4 * cm,
                        "This is to certify that")

    # ── Student Name ──────────────────────────────────────────────────────────
    c.setFillColor(DARK_BLUE)
    c.setFont("Helvetica-Bold", 30)
    c.drawCentredString(width / 2, height - 10.0 * cm, student_name)

    # Underline under name
    name_width = c.stringWidth(student_name, "Helvetica-Bold", 30)
    c.setStrokeColor(GOLD)
    c.setLineWidth(2)
    c.line(width / 2 - name_width / 2, height - 10.3 * cm,
           width / 2 + name_width / 2, height - 10.3 * cm)

    # ── Course Text ───────────────────────────────────────────────────────────
    c.setFillColor(black)
    c.setFont("Helvetica", 13)
    c.drawCentredString(width / 2, height - 11.2 * cm,
                        "has successfully completed the programme")

    c.setFillColor(MED_BLUE)
    c.setFont("Helvetica-Bold", 16)
    # Wrap long course names
    wrapped = textwrap.fill(course, width=55)
    lines = wrapped.split("\n")
    y = height - 12.2 * cm
    for line in lines:
        c.drawCentredString(width / 2, y, line)
        y -= 0.7 * cm

    # ── Certificate Details Box ───────────────────────────────────────────────
    box_top    = height - 16.0 * cm
    box_bottom = height - 19.5 * cm
    box_left   = 3.0 * cm
    box_right  = width - 3.0 * cm

    c.setFillColor(HexColor("#e8eaf6"))
    c.roundRect(box_left, box_bottom, box_right - box_left,
                box_top - box_bottom, radius=0.3 * cm, fill=1, stroke=0)
    c.setStrokeColor(DARK_BLUE)
    c.setLineWidth(1)
    c.roundRect(box_left, box_bottom, box_right - box_left,
                box_top - box_bottom, radius=0.3 * cm, fill=0, stroke=1)

    details = [
        ("Certificate ID", cert_id),
        ("Issue Date",     issue_date),
        ("Institution",    institution),
    ]
    dy = box_top - 0.8 * cm
    for label_text, value_text in details:
        c.setFillColor(MED_BLUE)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(box_left + 0.8 * cm, dy, f"{label_text}:")
        c.setFillColor(black)
        c.setFont("Helvetica", 11)
        c.drawString(box_left + 5.5 * cm, dy, value_text)
        dy -= 0.9 * cm

    # ── SHA-256 Hash (truncated) for visual reference ──────────────────────────
    if sha256_hash:
        c.setFillColor(HexColor("#546e7a"))
        c.setFont("Helvetica", 8)
        short_hash = sha256_hash[:32] + "..."
        c.drawString(box_left + 0.8 * cm, dy, f"Data Fingerprint (SHA-256): {short_hash}")
        dy -= 0.6 * cm

    # ── Companion JSON reference ───────────────────────────────────────────────
    if canonical_json_ref:
        c.setFont("Helvetica-Oblique", 8)
        c.setFillColor(HexColor("#37474f"))
        c.drawString(box_left + 0.8 * cm, dy,
                     f"Signed data file: {canonical_json_ref}")

    # ── Verification instruction ───────────────────────────────────────────────
    c.setFillColor(HexColor("#4a148c"))
    c.setFont("Helvetica-Bold", 9)
    c.drawCentredString(
        width / 2,
        height - 20.5 * cm,
        "To verify this certificate, upload the companion JSON file at the verification portal.",
    )

    # ── Signature lines ────────────────────────────────────────────────────────
    sig_y = height - 23.0 * cm
    sig_positions = [4.0 * cm, width / 2, width - 6.0 * cm]
    sig_labels    = ["Principal", "Head of Department", "Registrar"]

    for sx, slabel in zip(sig_positions, sig_labels):
        c.setStrokeColor(DARK_BLUE)
        c.setLineWidth(1)
        c.line(sx, sig_y, sx + 4.5 * cm, sig_y)
        c.setFillColor(MED_BLUE)
        c.setFont("Helvetica", 9)
        c.drawCentredString(sx + 2.25 * cm, sig_y - 0.5 * cm, slabel)

    # ── Footer ────────────────────────────────────────────────────────────────
    c.setFillColor(DARK_BLUE)
    c.rect(margin, margin, width - 2 * margin, 1.2 * cm, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica", 8)
    footer = (
        "VTU Information and Network Security (INS) — BIS 703 | "
        "Digital Certificate Verification System | Educational Demo"
    )
    c.drawCentredString(width / 2, margin + 0.4 * cm, footer)

    # ── Finalise ──────────────────────────────────────────────────────────────
    c.save()
    print(f"[pdf_generator] PDF saved → {output_path}")
    return output_path

