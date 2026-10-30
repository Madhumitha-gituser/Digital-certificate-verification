"""
pdf_generator.py — Generate Academic Certificates using ReportLab (Landscape A4)
"""

from pathlib import Path
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.colors import HexColor, white
from reportlab.pdfgen import canvas as pdf_canvas


# ─── Color Palette ────────────────────────────────────────────────────────────
NAVY_PRIMARY   = HexColor("#0b192c")   # Deep navy for institutional text
NAVY_ACCENT    = HexColor("#1e3e62")   # Secondary navy for titles & courses
GOLD_METALLIC  = HexColor("#c5a059")   # Antique gold for formal borders & seals
TEXT_DARK      = HexColor("#1e293b")   # Body text dark slate
TEXT_MUTED     = HexColor("#64748b")   # Secondary muted text
BG_PARCHMENT   = HexColor("#fdfdfb")   # Crisp subtle parchment ivory


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
) -> Path:
    """
    Generate a professional, perfectly aligned landscape academic certificate.

    Layout:
      - Orientation: Landscape A4 (841.89 x 595.28 pt)
      - Hierarchy: College Name -> Department -> Degree Award -> Recipient -> Signatures -> Security Seal
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    c = pdf_canvas.Canvas(str(output_path), pagesize=landscape(A4))
    width, height = landscape(A4)
    cx = width / 2.0  # Center X: 420.95 pt

    # 1. Background
    c.setFillColor(BG_PARCHMENT)
    c.rect(0, 0, width, height, fill=1, stroke=0)

    # 2. Triple Border (Navy outer, Gold middle, Navy inner)
    outer_m = 22.0
    c.setStrokeColor(NAVY_PRIMARY)
    c.setLineWidth(1.5)
    c.rect(outer_m, outer_m, width - 2 * outer_m, height - 2 * outer_m, fill=0, stroke=1)

    gold_m = outer_m + 4.0
    c.setStrokeColor(GOLD_METALLIC)
    c.setLineWidth(3.0)
    c.rect(gold_m, gold_m, width - 2 * gold_m, height - 2 * gold_m, fill=0, stroke=1)

    inner_m = gold_m + 4.0
    c.setStrokeColor(NAVY_PRIMARY)
    c.setLineWidth(0.75)
    c.rect(inner_m, inner_m, width - 2 * inner_m, height - 2 * inner_m, fill=0, stroke=1)

    # Corner Accents (Small gold squares in the 4 corners)
    corner_size = 6.0
    c.setFillColor(GOLD_METALLIC)
    corners = [
        (inner_m + 2, inner_m + 2),
        (width - inner_m - corner_size - 2, inner_m + 2),
        (inner_m + 2, height - inner_m - corner_size - 2),
        (width - inner_m - corner_size - 2, height - inner_m - corner_size - 2),
    ]
    for x, y in corners:
        c.rect(x, y, corner_size, corner_size, fill=1, stroke=0)

    # 3. Top Institution Header
    inst_name = (institution or "Vemana Institute of Technology").strip()

    c.setFillColor(TEXT_MUTED)
    c.setFont("Helvetica-Bold", 8)
    c.drawCentredString(cx, 532, "KRISHNA CHETHANA EDUCATION TRUST ®")

    c.setFillColor(NAVY_PRIMARY)
    c.setFont("Times-Bold", 24)
    c.drawCentredString(cx, 506, inst_name.upper())

    c.setFillColor(TEXT_MUTED)
    c.setFont("Times-Roman", 10)
    c.drawCentredString(cx, 490, "Approved by AICTE, New Delhi & Affiliated to VTU, Belagavi")
    c.setFont("Times-Roman", 9)
    c.drawCentredString(cx, 477, "Koramangala, Bengaluru - 560034, Karnataka, India")

    # Thin decorative divider line under header
    c.setStrokeColor(GOLD_METALLIC)
    c.setLineWidth(1.0)
    c.line(cx - 160, 466, cx + 160, 466)
    c.circle(cx, 466, 2.5, fill=1, stroke=0)

    # 4. Department
    c.setFillColor(NAVY_ACCENT)
    c.setFont("Helvetica-Bold", 10.5)
    c.drawCentredString(cx, 448, "DEPARTMENT OF INFORMATION SCIENCE & ENGINEERING")

    # 5. Certificate Title
    c.setFillColor(NAVY_PRIMARY)
    c.setFont("Times-BoldItalic", 22)
    c.drawCentredString(cx, 416, "Certificate of Academic Excellence")

    # 6. Preamble text
    c.setFillColor(TEXT_DARK)
    c.setFont("Times-Italic", 12.5)
    c.drawCentredString(cx, 386, "This is to certify that")

    # 7. Student Name
    c.setFillColor(NAVY_PRIMARY)
    c.setFont("Times-Bold", 26)
    c.drawCentredString(cx, 350, student_name)

    # Refined underline below student name
    name_w = c.stringWidth(student_name, "Times-Bold", 26)
    c.setStrokeColor(GOLD_METALLIC)
    c.setLineWidth(1.5)
    c.line(cx - name_w / 2 - 15, 344, cx + name_w / 2 + 15, 344)

    # 8. Body Award Text
    c.setFillColor(TEXT_DARK)
    c.setFont("Times-Roman", 12)
    c.drawCentredString(cx, 318, "has successfully completed the prescribed curriculum and fulfilled the requirements for the award of")

    # 9. Course / Degree Name
    c.setFillColor(NAVY_ACCENT)
    c.setFont("Times-Bold", 15)
    c.drawCentredString(cx, 294, course)

    # 10. Completion sentence
    c.setFillColor(TEXT_DARK)
    c.setFont("Times-Roman", 11.5)
    date_text = f"and has been awarded this credential on {issue_date} with First Class Distinction."
    c.drawCentredString(cx, 270, date_text)

    # 11. Institutional Seal (Center at cx, y=165)
    seal_y = 175
    c.setStrokeColor(GOLD_METALLIC)
    c.setLineWidth(1.8)
    c.circle(cx, seal_y, 30, fill=0, stroke=1)
    c.setLineWidth(0.8)
    c.circle(cx, seal_y, 26, fill=0, stroke=1)

    c.setFillColor(GOLD_METALLIC)
    c.setFont("Helvetica-Bold", 6.5)
    c.drawCentredString(cx, seal_y + 11, "VEMANA IT")
    c.setFont("Times-Bold", 7.5)
    c.drawCentredString(cx, seal_y - 1, "★ SEAL ★")
    c.setFont("Helvetica-Bold", 6.5)
    c.drawCentredString(cx, seal_y - 13, "VERIFIED")

    # 12. Signatures (Left: HOD, Right: Principal)
    sig_line_y = 160
    sig_w = 150.0

    # Left Signature: Head of Department
    left_cx = 180.0
    c.setStrokeColor(NAVY_PRIMARY)
    c.setLineWidth(1.0)
    c.line(left_cx - sig_w / 2, sig_line_y, left_cx + sig_w / 2, sig_line_y)

    c.setFillColor(NAVY_PRIMARY)
    c.setFont("Times-Bold", 11)
    c.drawCentredString(left_cx, sig_line_y - 16, "Dr. H. N. Suresh")
    c.setFillColor(TEXT_MUTED)
    c.setFont("Times-Roman", 9)
    c.drawCentredString(left_cx, sig_line_y - 28, "Head of Department (ISE)")

    # Right Signature: Principal
    right_cx = width - 180.0
    c.setStrokeColor(NAVY_PRIMARY)
    c.setLineWidth(1.0)
    c.line(right_cx - sig_w / 2, sig_line_y, right_cx + sig_w / 2, sig_line_y)

    c.setFillColor(NAVY_PRIMARY)
    c.setFont("Times-Bold", 11)
    c.drawCentredString(right_cx, sig_line_y - 16, "Dr. Vijayasimha Reddy")
    c.setFillColor(TEXT_MUTED)
    c.setFont("Times-Roman", 9)
    c.drawCentredString(right_cx, sig_line_y - 28, "Principal")

    # 13. Security & Verification Footer Strip
    footer_divider_y = 74
    c.setStrokeColor(HexColor("#e2e8f0"))
    c.setLineWidth(0.8)
    c.line(inner_m + 10, footer_divider_y, width - inner_m - 10, footer_divider_y)

    c.setFillColor(TEXT_MUTED)
    c.setFont("Helvetica-Bold", 8)
    security_text = f"Certificate ID: {cert_id}   |   Digital Signature: RSA-2048 / SHA-256 PSS   |   Issuer: Vemana-IT-CA"
    c.drawCentredString(cx, 56, security_text)

    if sha256_hash:
        c.setFont("Courier", 7)
        c.setFillColor(HexColor("#94a3b8"))
        digest_preview = f"Cryptographic Fingerprint: {sha256_hash[:40]}..."
        c.drawCentredString(cx, 44, digest_preview)

    c.save()
    print(f"[pdf_generator] Landscape PDF generated -> {output_path}")
    return output_path
