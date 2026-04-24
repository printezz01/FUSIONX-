"""
Sentinel AI — Premium PDF Report (ReportLab)
Professional security report with remediation guidance.
"""
import io, logging
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)
from app.db import get_findings, get_risk_score, get_chain_edges
from app.engine import map_owasp_findings, OWASP_CATEGORIES

logger = logging.getLogger("sentinel.reporting")

# ─── Palette ──────────────────────────────────────────────────
C_DARK    = colors.HexColor("#0F172A")
C_NAVY    = colors.HexColor("#1E293B")
C_ACCENT  = colors.HexColor("#4F46E5")
C_CRIT    = colors.HexColor("#DC2626")
C_HIGH    = colors.HexColor("#EA580C")
C_MED     = colors.HexColor("#CA8A04")
C_LOW     = colors.HexColor("#16A34A")
C_INFO    = colors.HexColor("#64748B")
C_WHITE   = colors.white
C_LIGHT   = colors.HexColor("#F8FAFC")
C_BORDER  = colors.HexColor("#E2E8F0")
C_MUTED   = colors.HexColor("#94A3B8")

SEV_COLOR = {"critical": C_CRIT, "high": C_HIGH, "medium": C_MED,
             "low": C_LOW, "info": C_INFO}

# ─── Remediation lookup ───────────────────────────────────────
FIXES = {
    "hardcoded": [
        "Move credentials to environment variables (.env) immediately.",
        "Use a secrets manager (HashiCorp Vault, AWS Secrets Manager).",
        "Add a pre-commit hook (detect-secrets) to block future commits.",
        "Rotate ALL exposed credentials — assume they are already compromised.",
        "Purge from git history using: git filter-branch or BFG Repo Cleaner.",
    ],
    "sql injection": [
        "Use parameterized queries / prepared statements everywhere.",
        "Never concatenate user input directly into SQL strings.",
        "Adopt an ORM (SQLAlchemy, Django ORM) which handles this automatically.",
        "Add Bandit rule B608 to your CI gate to catch future regressions.",
    ],
    "eval": [
        "Remove eval() — use ast.literal_eval() for safe literal parsing.",
        "Replace dynamic dispatch with a lookup dict.",
        "Add Bandit rule B307 to your CI pipeline.",
    ],
    "md5": [
        "Replace MD5 with bcrypt, Argon2id, or scrypt for passwords.",
        "MD5 is cryptographically broken — never use for security operations.",
        "Migrate existing hashed passwords on next user login.",
    ],
    "debug": [
        "Set DEBUG=False in all production config — read from environment variable.",
        "Return generic 500 error pages — never expose stack traces to users.",
        "Use environment-specific config files (settings_prod.py).",
    ],
    "leaked": [
        "Revoke and rotate the secret immediately.",
        "Scan all branches with trufflehog / gitleaks.",
        "Purge from git history. Enable GitHub secret scanning.",
        "Add .env to .gitignore. Use pre-commit hooks.",
    ],
    "secret": [
        "Revoke and rotate the exposed secret immediately.",
        "Move to a dedicated secrets manager or CI/CD secret store.",
        "Store only references/names in code, never actual values.",
    ],
    "port 5432": [
        "Block port 5432 — allow only from app server IPs via firewall.",
        "Move database to a private subnet with no internet exposure.",
        "Enable SSL/TLS on all database connections.",
    ],
    "port 22": [
        "Disable password auth on SSH — use key pairs only.",
        "Restrict SSH to specific IPs via security groups / firewall.",
        "Upgrade OpenSSH to latest stable. Enable fail2ban.",
    ],
    "port 21": [
        "Disable FTP entirely. Replace with SFTP or FTPS.",
        "If unavoidable, disable anonymous access and restrict by IP.",
        "Patch vsftpd 2.3.4 backdoor (CVE-2011-2523) immediately.",
    ],
    "port 3306": [
        "Block port 3306 from all external access.",
        "Move MySQL to a private network segment.",
        "Disable remote root login in MySQL configuration.",
    ],
    "telnet": [
        "Disable Telnet immediately — it transmits data in plaintext.",
        "Replace with SSH. Remove the telnet daemon package.",
    ],
    "cve-2021-36260": [
        "Apply official Hikvision firmware patch (v5.5.800+).",
        "Isolate camera from internet-facing networks.",
        "Change all default credentials on IoT/camera devices.",
        "Segment IoT devices on a dedicated VLAN.",
    ],
}

def _get_fixes(finding: dict) -> list:
    text = f"{finding.get('title','')} {finding.get('description','')}".lower()
    cve  = (finding.get("cve_id") or "").lower()
    for key, steps in FIXES.items():
        if key.startswith("cve") and key in cve:
            return steps
    for key, steps in FIXES.items():
        if not key.startswith("cve") and key in text:
            return steps
    sev = finding.get("severity","info")
    defaults = {
        "critical": ["Treat as P0 emergency — escalate to security team now.",
                     "Isolate the affected component until patched.",
                     "Review access logs for signs of exploitation.",
                     "Apply vendor patch or configuration mitigation."],
        "high":     ["Schedule remediation within 7 days.",
                     "Apply recommended patch or configuration change.",
                     "Monitor for anomalous activity."],
        "medium":   ["Schedule remediation within 30 days.",
                     "Apply security hardening per vendor guidelines."],
    }
    return defaults.get(sev, ["Address in the next maintenance window."])

def _score_band(score):
    if score <= 30: return "CRITICAL RISK", C_CRIT
    if score <= 50: return "HIGH RISK",     C_HIGH
    if score <= 75: return "MEDIUM RISK",   C_MED
    return "LOW RISK", C_LOW

# ─── Page header/footer ───────────────────────────────────────
class _Decorator:
    def __init__(self, target, date):
        self.target = target; self.date = date; self._n = 0
    def __call__(self, canvas, doc):
        self._n += 1
        W, H = A4
        canvas.saveState()
        # Header
        canvas.setFillColor(C_DARK); canvas.rect(0, H-26, W, 26, fill=1, stroke=0)
        canvas.setFillColor(C_ACCENT); canvas.rect(0, H-28, W, 2, fill=1, stroke=0)
        canvas.setFillColor(C_WHITE); canvas.setFont("Helvetica-Bold", 8.5)
        canvas.drawString(16, H-17, "SENTINEL AI  |  Security Intelligence Report")
        canvas.setFont("Helvetica", 8); canvas.setFillColor(C_MUTED)
        canvas.drawRightString(W-16, H-17, self.target[:60])
        # Footer
        canvas.setFillColor(C_NAVY); canvas.rect(0, 0, W, 20, fill=1, stroke=0)
        canvas.setFillColor(C_MUTED); canvas.setFont("Helvetica", 7.5)
        canvas.drawString(16, 6, f"Generated: {self.date}  |  CONFIDENTIAL")
        canvas.drawRightString(W-16, 6, f"Page {self._n}")
        canvas.restoreState()

def generate_pdf(scan_id: str, target: str, scan_session: dict = None) -> bytes:
    buf = io.BytesIO()
    W, H = A4
    M = 18*mm
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    dec = _Decorator(target, date_str)

    doc = SimpleDocTemplate(buf, pagesize=A4,
        topMargin=M+6, bottomMargin=M,
        leftMargin=M, rightMargin=M,
        onFirstPage=dec, onLaterPages=dec)

    styles = getSampleStyleSheet()
    def S(name, **kw): return ParagraphStyle(name, parent=styles["Normal"], **kw)

    sTitle   = S("sT", fontSize=13, fontName="Helvetica-Bold", textColor=C_WHITE)
    sBody    = S("sB", fontSize=9.5, textColor=C_NAVY, leading=14, spaceAfter=4, alignment=TA_JUSTIFY)
    sBold    = S("sBo", fontSize=9.5, fontName="Helvetica-Bold", textColor=C_NAVY, spaceAfter=3)
    sSmall   = S("sSm", fontSize=8, textColor=C_INFO, spaceAfter=2)
    sBullet  = S("sBu", fontSize=9, textColor=C_NAVY, leading=13, leftIndent=8, spaceAfter=1)
    sCenter  = S("sCe", fontSize=10, alignment=TA_CENTER)
    sMono    = S("sMo", fontSize=8, fontName="Helvetica-Oblique", textColor=C_INFO, leading=11)

    CWIDTH = W - 2*M

    def banner(title, color=C_ACCENT):
        t = Table([[Paragraph(f"&nbsp;&nbsp;{title}", sTitle)]], colWidths=[CWIDTH])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0),(-1,-1), color),
            ("TOPPADDING", (0,0),(-1,-1), 7),
            ("BOTTOMPADDING", (0,0),(-1,-1), 7),
        ]))
        return t

    def divider(): return HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8, spaceBefore=8)

    elems = []

    # ── Load data ──────────────────────────────────────────────
    findings   = get_findings(scan_id)
    risk_data  = get_risk_score(scan_id)
    edges      = get_chain_edges(scan_id)
    owasp      = map_owasp_findings(scan_id)

    score     = risk_data["score"] if risk_data else 50
    breakdown = (risk_data or {}).get("breakdown", {})
    band, bcolor = _score_band(score)

    counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for f in findings:
        counts[f.get("severity","info")] = counts.get(f.get("severity","info"),0)+1

    scan_time = ""
    if scan_session:
        scan_time = (scan_session.get("created_at") or "")[:19]
    if not scan_time:
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ═══════════════════════════════════════════════════════════
    # PAGE 1 — COVER
    # ═══════════════════════════════════════════════════════════
    elems += [Spacer(1, 50)]
    elems += [Paragraph("SENTINEL AI", S("ct", fontSize=38, fontName="Helvetica-Bold", textColor=C_DARK))]
    elems += [Paragraph("Autonomous Security Intelligence Report",
                         S("cs", fontSize=14, textColor=C_ACCENT, spaceAfter=20))]
    elems += [HRFlowable(width="100%", thickness=3, color=C_ACCENT, spaceAfter=22)]

    cover_data = [
        ["Target",             target],
        ["Scan Date",          scan_time],
        ["Report Generated",   date_str],
        ["Total Findings",     str(len(findings))],
        ["Risk Band",          band],
    ]
    ct = Table(cover_data, colWidths=[110, CWIDTH-110])
    ct.setStyle(TableStyle([
        ("FONTNAME",  (0,0),(0,-1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0,0),(0,-1), C_ACCENT),
        ("FONTSIZE",  (0,0),(-1,-1), 10),
        ("TEXTCOLOR", (1,0),(1,-1), C_DARK),
        ("LINEBELOW", (0,0),(-1,-2), 0.4, C_BORDER),
        ("TOPPADDING",(0,0),(-1,-1), 7),
        ("BOTTOMPADDING",(0,0),(-1,-1), 7),
    ]))
    elems.append(ct)
    elems.append(Spacer(1,26))

    # Risk box
    score_hex = bcolor.hexval()
    rb = Table([[
        Paragraph(f'<font size="46" color="{score_hex}"><b>{score}</b></font>', sCenter),
        Table([[
            Paragraph(f'<font size="16" color="{score_hex}"><b>{band}</b></font>', sCenter),
            Paragraph('<font size="8" color="#94A3B8">Score /100 — Lower = More Risk</font>', sCenter),
        ]], colWidths=[170])
    ]], colWidths=[90, 170])
    rb.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1), C_LIGHT),
        ("BOX",(0,0),(-1,-1), 2, bcolor),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("TOPPADDING",(0,0),(-1,-1),14),
        ("BOTTOMPADDING",(0,0),(-1,-1),14),
        ("LEFTPADDING",(0,0),(-1,-1),14),
    ]))
    elems.append(rb)
    elems.append(Spacer(1,20))
    elems.append(Paragraph(
        "CONFIDENTIAL — Handle per your data classification policy.",
        S("conf", fontSize=8, textColor=C_INFO, alignment=TA_CENTER)))
    elems.append(PageBreak())

    # ═══════════════════════════════════════════════════════════
    # PAGE 2 — EXECUTIVE SUMMARY
    # ═══════════════════════════════════════════════════════════
    elems.append(banner("EXECUTIVE SUMMARY"))
    elems.append(Spacer(1,12))

    crit_list = [f for f in findings if f.get("severity")=="critical"]
    summary = (
        f"A security assessment of <b>{target}</b> identified <b>{len(findings)} findings</b> "
        f"— <b>{counts['critical']} critical</b>, <b>{counts['high']} high</b>, "
        f"<b>{counts['medium']} medium</b>. "
        f"Overall risk score: <b>{score}/100</b> ({band}). "
    )
    if counts["critical"]:
        summary += ("Critical vulnerabilities were detected that could allow an attacker to "
                    "gain unauthorised access to data or system resources. "
                    "<b>Immediate remediation is required.</b>")
    else:
        summary += "No critical issues detected. Address high-severity findings within 7 days."
    elems.append(Paragraph(summary, sBody))
    elems.append(Spacer(1,10))

    sev_hdr = ["Severity","Count","Action Timeline","Risk"]
    sev_rows = [
        ["CRITICAL", counts["critical"], "Fix within 24 hours",   "System compromise possible"],
        ["HIGH",     counts["high"],     "Fix within 7 days",     "Significant risk"],
        ["MEDIUM",   counts["medium"],   "Fix within 30 days",    "Moderate exposure"],
        ["LOW",      counts["low"],      "Next maintenance cycle", "Minimal impact"],
        ["INFO",     counts["info"],     "Review & document",     "Informational only"],
    ]
    sev_colors_list = [C_CRIT, C_HIGH, C_MED, C_LOW, C_INFO]

    st = Table([sev_hdr]+[[str(c) if isinstance(c,int) else c for c in r] for r in sev_rows],
               colWidths=[65,45,130,CWIDTH-240])
    sev_style = [
        ("BACKGROUND",(0,0),(-1,0), C_DARK),
        ("TEXTCOLOR",(0,0),(-1,0), C_WHITE),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),9),
        ("GRID",(0,0),(-1,-1),0.4,C_BORDER),
        ("TOPPADDING",(0,0),(-1,-1),6),
        ("BOTTOMPADDING",(0,0),(-1,-1),6),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
    ]
    for i, sc in enumerate(sev_colors_list, 1):
        sev_style.append(("TEXTCOLOR",(0,i),(0,i), sc))
        sev_style.append(("FONTNAME",(0,i),(0,i),"Helvetica-Bold"))
    st.setStyle(TableStyle(sev_style))
    elems.append(st)
    elems.append(PageBreak())

    # ═══════════════════════════════════════════════════════════
    # PAGE 3+ — DETAILED FINDINGS WITH REMEDIATION
    # ═══════════════════════════════════════════════════════════
    elems.append(banner("DETAILED FINDINGS & REMEDIATION GUIDE"))
    elems.append(Spacer(1,12))

    layers = {}
    for f in findings:
        l = f.get("layer","unknown")
        layers.setdefault(l,[]).append(f)

    for layer_name, layer_findings in layers.items():
        elems.append(Paragraph(
            f"Layer: {layer_name.upper()} ({len(layer_findings)} findings)",
            S(f"lh{layer_name}", fontSize=11, fontName="Helvetica-Bold",
              textColor=C_ACCENT, spaceBefore=14, spaceAfter=6)))

        for idx, f in enumerate(layer_findings, 1):
            sev   = f.get("severity","info")
            sc    = SEV_COLOR.get(sev, C_INFO)
            sc_hex = sc.hexval()
            title  = f.get("title","Unknown")
            desc   = f.get("description","")
            cve    = f.get("cve_id") or "—"
            gives  = f.get("gives","—")
            reqs   = f.get("requires","—")
            fixes  = _get_fixes(f)

            # Finding card header
            hdr = Table([[
                Paragraph(f'<font color="#FFFFFF"><b>[{sev.upper()}] Finding #{idx} — {title}</b></font>', sTitle),
            ]], colWidths=[CWIDTH])
            hdr.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,-1), sc),
                ("TOPPADDING",(0,0),(-1,-1),7),
                ("BOTTOMPADDING",(0,0),(-1,-1),7),
                ("LEFTPADDING",(0,0),(-1,-1),10),
            ]))

            # Meta row
            meta = Table([[
                Paragraph(f"<b>Layer:</b> {layer_name.upper()}", sSmall),
                Paragraph(f"<b>CVE:</b> {cve}", sSmall),
                Paragraph(f"<b>Gives attacker:</b> {gives}", sSmall),
                Paragraph(f"<b>Requires:</b> {reqs}", sSmall),
            ]], colWidths=[55,75,CWIDTH-255,125])
            meta.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,-1), C_LIGHT),
                ("GRID",(0,0),(-1,-1),0.4,C_BORDER),
                ("TOPPADDING",(0,0),(-1,-1),5),
                ("BOTTOMPADDING",(0,0),(-1,-1),5),
                ("LEFTPADDING",(0,0),(-1,-1),6),
                ("FONTSIZE",(0,0),(-1,-1),8),
            ]))

            # Description
            desc_block = Paragraph(desc, sBody)

            # Remediation
            fix_hdr = Paragraph("WHAT NEEDS TO BE FIXED", S(
                f"fh{idx}", fontSize=9, fontName="Helvetica-Bold",
                textColor=C_ACCENT, spaceBefore=8, spaceAfter=4))
            fix_items = [Paragraph(f"  {i+1}.  {step}", sBullet) for i,step in enumerate(fixes)]

            card_content = [Spacer(1,4), desc_block, Spacer(1,4),
                            fix_hdr] + fix_items + [Spacer(1,10)]

            card = Table([[hdr], [meta],
                          [Table([[Paragraph("", sSmall)]+card_content],
                                 colWidths=[CWIDTH])]],
                         colWidths=[CWIDTH])
            card.setStyle(TableStyle([
                ("BOX",(0,0),(-1,-1),1,sc),
                ("LEFTPADDING",(0,1),(0,-1),10),
                ("RIGHTPADDING",(0,1),(0,-1),10),
                ("TOPPADDING",(0,1),(0,-1),0),
                ("BOTTOMPADDING",(0,1),(0,-1),0),
            ]))

            elems.append(KeepTogether([hdr, meta, desc_block,
                                        fix_hdr] + fix_items + [Spacer(1,12)]))

    elems.append(PageBreak())

    # ═══════════════════════════════════════════════════════════
    # ATTACK CHAIN PAGE
    # ═══════════════════════════════════════════════════════════
    elems.append(banner("ATTACK CHAIN ANALYSIS", C_CRIT))
    elems.append(Spacer(1,10))
    elems.append(Paragraph(
        "The following chains show how vulnerabilities can be combined to escalate an attack. "
        "Each arrow shows how one vulnerability provides access needed by the next.",
        sBody))
    elems.append(Spacer(1,8))

    if edges:
        fmap = {f["id"]: f for f in findings}
        for i, e in enumerate(edges, 1):
            src = fmap.get(e.get("from_finding"), {})
            tgt = fmap.get(e.get("to_finding"), {})
            s_sev = src.get("severity","info").upper()
            t_sev = tgt.get("severity","info").upper()
            s_col = SEV_COLOR.get(src.get("severity","info"), C_INFO).hexval()
            t_col = SEV_COLOR.get(tgt.get("severity","info"), C_INFO).hexval()
            reason = e.get("reason","")

            chain_rows = [
                [Paragraph(f'<font color="{s_col}"><b>STEP 1 [{s_sev}]</b></font>  {src.get("title","?")}', sBold)],
                [Paragraph(f'  &nbsp;&nbsp; &#9660;  <i>{reason}</i>', sMono)],
                [Paragraph(f'<font color="{t_col}"><b>STEP 2 [{t_sev}]</b></font>  {tgt.get("title","?")}', sBold)],
            ]
            ct2 = Table(chain_rows, colWidths=[CWIDTH])
            ct2.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,-1), C_LIGHT),
                ("BOX",(0,0),(-1,-1),1,C_BORDER),
                ("LEFTPADDING",(0,0),(-1,-1),10),
                ("TOPPADDING",(0,0),(-1,-1),5),
                ("BOTTOMPADDING",(0,0),(-1,-1),5),
            ]))
            elems.append(Paragraph(f"Chain #{i}", S(f"cn{i}", fontSize=9, fontName="Helvetica-Bold",
                                                     textColor=C_ACCENT, spaceBefore=8, spaceAfter=3)))
            elems.append(ct2)
            elems.append(Spacer(1,8))
    else:
        elems.append(Paragraph("No exploitable attack chains detected in this scan.", sBody))

    elems.append(PageBreak())

    # ═══════════════════════════════════════════════════════════
    # OWASP TOP 10 PAGE
    # ═══════════════════════════════════════════════════════════
    elems.append(banner("OWASP TOP 10 (2021) COMPLIANCE MAP"))
    elems.append(Spacer(1,10))

    owasp_hdr = [["OWASP Category", "Status", "Affected Findings"]]
    owasp_rows = []
    for cat in OWASP_CATEGORIES:
        status = owasp.get(cat, "pass")
        affected = [f["title"][:50] for f in findings if
                    f.get("id") and status == "fail"][:2]
        affected_txt = "; ".join(affected) if affected else "—"
        owasp_rows.append([cat, status.upper(), affected_txt])

    ot = Table(owasp_hdr + owasp_rows,
               colWidths=[200, 55, CWIDTH-255])
    ot_style = [
        ("BACKGROUND",(0,0),(-1,0), C_DARK),
        ("TEXTCOLOR",(0,0),(-1,0), C_WHITE),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),8.5),
        ("GRID",(0,0),(-1,-1),0.4,C_BORDER),
        ("TOPPADDING",(0,0),(-1,-1),6),
        ("BOTTOMPADDING",(0,0),(-1,-1),6),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
    ]
    for i, row in enumerate(owasp_rows, 1):
        if row[1] == "FAIL":
            ot_style += [
                ("TEXTCOLOR",(1,i),(1,i), C_CRIT),
                ("FONTNAME",(1,i),(1,i),"Helvetica-Bold"),
                ("BACKGROUND",(0,i),(-1,i), colors.HexColor("#FEF2F2")),
            ]
        else:
            ot_style += [
                ("TEXTCOLOR",(1,i),(1,i), C_LOW),
                ("FONTNAME",(1,i),(1,i),"Helvetica-Bold"),
            ]
    ot.setStyle(TableStyle(ot_style))
    elems.append(ot)
    elems.append(Spacer(1,18))

    # Risk breakdown table
    elems.append(banner("RISK SCORE BREAKDOWN", C_NAVY))
    elems.append(Spacer(1,10))
    if breakdown:
        bd_data = [["Category","Count","Score Deduction"]]
        for key in ("critical","high","medium","low"):
            cnt = breakdown.get(f"{key}_count",0)
            ded = breakdown.get(f"{key}_deduction",0)
            bd_data.append([key.capitalize(), str(cnt), f"-{ded}"])
        if breakdown.get("chain_deduction"):
            bd_data.append(["Attack Chain (>=3 steps)","—",f"-{breakdown['chain_deduction']}"])
        if breakdown.get("secret_deduction"):
            bd_data.append(["Leaked Secrets","—",f"-{breakdown['secret_deduction']}"])
        bd_data.append(["FINAL SCORE","—", str(score)])

        bt = Table(bd_data, colWidths=[200,80,CWIDTH-280])
        bt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0), C_NAVY),
            ("TEXTCOLOR",(0,0),(-1,0), C_WHITE),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("FONTNAME",(0,-1),(-1,-1),"Helvetica-Bold"),
            ("BACKGROUND",(0,-1),(-1,-1), C_LIGHT),
            ("FONTSIZE",(0,0),(-1,-1),9),
            ("GRID",(0,0),(-1,-1),0.4,C_BORDER),
            ("TOPPADDING",(0,0),(-1,-1),6),
            ("BOTTOMPADDING",(0,0),(-1,-1),6),
        ]))
        elems.append(bt)

    doc.build(elems)
    return buf.getvalue()
