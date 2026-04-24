"""
Sentinel AI — PDF Report Generator (ReportLab)
Generates comprehensive security assessment reports.
"""

import io
import logging
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from app.db import get_findings, get_risk_score, get_chain_edges
from app.engine import map_owasp_findings, OWASP_CATEGORIES

logger = logging.getLogger("sentinel.reporting")

# ─── Color palette ────────────────────────────────────────────
COLOR_CRITICAL = colors.HexColor("#DC2626")
COLOR_HIGH = colors.HexColor("#EA580C")
COLOR_MEDIUM = colors.HexColor("#CA8A04")
COLOR_LOW = colors.HexColor("#16A34A")
COLOR_DARK = colors.HexColor("#1E293B")
COLOR_ACCENT = colors.HexColor("#6366F1")
COLOR_LIGHT_BG = colors.HexColor("#F1F5F9")


def _severity_color(severity: str) -> colors.Color:
    return {
        "critical": COLOR_CRITICAL,
        "high": COLOR_HIGH,
        "medium": COLOR_MEDIUM,
        "low": COLOR_LOW,
        "info": colors.HexColor("#6B7280"),
    }.get(severity, colors.gray)


def _score_band(score: int) -> tuple[str, colors.Color]:
    if score <= 30:
        return "CRITICAL", COLOR_CRITICAL
    elif score <= 60:
        return "HIGH", COLOR_HIGH
    elif score <= 80:
        return "MEDIUM", COLOR_MEDIUM
    else:
        return "LOW", COLOR_LOW


def generate_pdf(scan_id: str, target: str, scan_session: dict = None) -> bytes:
    """Generate a complete PDF security report. Returns bytes."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=30*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    elements = []

    # Custom styles
    title_style = ParagraphStyle("CustomTitle", parent=styles["Title"],
                                  fontSize=28, textColor=COLOR_DARK, spaceAfter=12)
    heading_style = ParagraphStyle("CustomH1", parent=styles["Heading1"],
                                    fontSize=18, textColor=COLOR_ACCENT, spaceBefore=20, spaceAfter=10)
    subheading_style = ParagraphStyle("CustomH2", parent=styles["Heading2"],
                                       fontSize=14, textColor=COLOR_DARK, spaceBefore=12, spaceAfter=6)
    body_style = ParagraphStyle("CustomBody", parent=styles["Normal"],
                                 fontSize=10, textColor=COLOR_DARK, spaceAfter=6)
    center_style = ParagraphStyle("Center", parent=styles["Normal"],
                                    alignment=TA_CENTER, fontSize=12)

    # Load data
    findings = get_findings(scan_id)
    risk_data = get_risk_score(scan_id)
    chain_edges = get_chain_edges(scan_id)

    scan_time = scan_session.get("created_at", datetime.now().isoformat()) if scan_session else datetime.now().isoformat()
    completed = scan_session.get("completed_at", "") if scan_session else ""

    # ═══════════════════════════════════════════════════════
    # Page 1: Cover
    # ═══════════════════════════════════════════════════════
    elements.append(Spacer(1, 80))
    elements.append(Paragraph("SENTINEL AI", title_style))
    elements.append(Paragraph("Security Intelligence Report", ParagraphStyle(
        "Subtitle", parent=styles["Normal"], fontSize=16, textColor=COLOR_ACCENT, alignment=TA_CENTER
    )))
    elements.append(Spacer(1, 40))
    elements.append(HRFlowable(width="80%", color=COLOR_ACCENT, thickness=2))
    elements.append(Spacer(1, 20))

    cover_data = [
        ["Target:", target],
        ["Scan Date:", scan_time[:19] if scan_time else "N/A"],
        ["Completed:", completed[:19] if completed else "N/A"],
        ["Findings:", str(len(findings))],
    ]
    cover_table = Table(cover_data, colWidths=[120, 300])
    cover_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("TEXTCOLOR", (0, 0), (0, -1), COLOR_ACCENT),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(cover_table)
    elements.append(PageBreak())

    # ═══════════════════════════════════════════════════════
    # Page 2: Risk Score
    # ═══════════════════════════════════════════════════════
    elements.append(Paragraph("Risk Score", heading_style))
    score = risk_data["score"] if risk_data else 50
    breakdown = risk_data.get("breakdown", {}) if risk_data else {}
    band_label, band_color = _score_band(score)

    score_text = f'<font size="48" color="{band_color.hexval()}">{score}</font>'
    elements.append(Paragraph(score_text, center_style))
    elements.append(Paragraph(f'<font size="14" color="{band_color.hexval()}">{band_label} RISK</font>', center_style))
    elements.append(Spacer(1, 20))

    if breakdown:
        bd_data = [["Category", "Count", "Deduction"]]
        for key in ("critical", "high", "medium", "low"):
            count = breakdown.get(f"{key}_count", 0)
            ded = breakdown.get(f"{key}_deduction", 0)
            bd_data.append([key.capitalize(), str(count), f"-{ded}"])
        if breakdown.get("chain_deduction"):
            bd_data.append(["Chain (≥3 steps)", "—", f"-{breakdown['chain_deduction']}"])
        if breakdown.get("secret_deduction"):
            bd_data.append(["Leaked Secrets", "—", f"-{breakdown['secret_deduction']}"])

        bd_table = Table(bd_data, colWidths=[200, 80, 80])
        bd_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_ACCENT),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 1), (-1, -1), COLOR_LIGHT_BG),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.white),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(bd_table)

    # ═══════════════════════════════════════════════════════
    # Severity Breakdown
    # ═══════════════════════════════════════════════════════
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("Severity Breakdown", heading_style))

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1

    sev_data = [["Severity", "Count"]]
    for sev in ("critical", "high", "medium", "low", "info"):
        sev_data.append([sev.capitalize(), str(counts[sev])])

    sev_table = Table(sev_data, colWidths=[200, 80])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(sev_table)
    elements.append(PageBreak())

    # ═══════════════════════════════════════════════════════
    # Findings by Layer
    # ═══════════════════════════════════════════════════════
    elements.append(Paragraph("Findings by Layer", heading_style))

    layers = {"network": [], "web": [], "code": [], "iot": []}
    for f in findings:
        layer = f.get("layer", "network")
        if layer in layers:
            layers[layer].append(f)

    for layer_name, layer_findings in layers.items():
        if not layer_findings:
            continue
        elements.append(Paragraph(f"{layer_name.upper()} Layer ({len(layer_findings)} findings)", subheading_style))

        f_data = [["#", "Severity", "Title", "CVE"]]
        for i, f in enumerate(layer_findings, 1):
            f_data.append([
                str(i),
                f.get("severity", "info").upper(),
                Paragraph(f.get("title", "")[:60], body_style),
                f.get("cve_id", "—") or "—",
            ])

        f_table = Table(f_data, colWidths=[30, 70, 280, 100])
        f_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(f_table)
        elements.append(Spacer(1, 10))

    elements.append(PageBreak())

    # ═══════════════════════════════════════════════════════
    # Attack Chain
    # ═══════════════════════════════════════════════════════
    elements.append(Paragraph("Attack Chain", heading_style))

    if chain_edges:
        findings_map = {f["id"]: f for f in findings}
        for edge in chain_edges:
            from_f = findings_map.get(edge.get("from_finding"), {})
            to_f = findings_map.get(edge.get("to_finding"), {})
            from_title = from_f.get("title", "Unknown")[:40]
            to_title = to_f.get("title", "Unknown")[:40]
            elements.append(Paragraph(
                f'<font color="{COLOR_CRITICAL.hexval()}">[{from_title}]</font>'
                f' → <font color="{COLOR_CRITICAL.hexval()}">[{to_title}]</font>',
                body_style
            ))
            elements.append(Paragraph(f'  Reason: {edge.get("reason", "N/A")[:80]}', body_style))
            elements.append(Spacer(1, 4))
    else:
        elements.append(Paragraph("No attack chains detected.", body_style))

    # ═══════════════════════════════════════════════════════
    # OWASP Top 10 Mapping
    # ═══════════════════════════════════════════════════════
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("OWASP Top 10 (2021) Assessment", heading_style))

    owasp_map = map_owasp_findings(scan_id)
    owasp_data = [["Category", "Status"]]
    for cat in OWASP_CATEGORIES:
        status = owasp_map.get(cat, "pass")
        owasp_data.append([cat, status.upper()])

    owasp_table = Table(owasp_data, colWidths=[350, 80])
    owasp_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(owasp_table)

    # Build PDF
    doc.build(elements)
    return buffer.getvalue()
