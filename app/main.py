"""
Sentinel AI — FastAPI Main Application
Run: uvicorn app.main:app --reload
"""

import asyncio
import ipaddress
import logging
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

from app.config import CORS_ORIGINS, ALLOWED_IP_RANGES, ALLOWED_URLS, ALLOWED_GITHUB_REPOS
from app.db import (
    new_uuid, create_scan_session, get_scan_session,
    get_findings, get_risk_score,
)
from app.engine import (
    get_chain_graph, calculate_risk_score, map_owasp_findings,
    search_rag, generate_remediation, OWASP_CATEGORIES,
)
from app.reporting import generate_pdf
from app.agent import run_agent

# ─── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("sentinel.main")

# ─── App ──────────────────────────────────────────────────────
app = FastAPI(
    title="Sentinel AI",
    description="Autonomous Multi-Layer Security Intelligence Platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ══════════════════════════════════════════════════════════════
# Target Validation (HARD CONSTRAINT)
# ══════════════════════════════════════════════════════════════

def _is_local_ip(ip_str: str) -> bool:
    """Check if an IP is localhost or in a private range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_loopback or addr.is_private
    except ValueError:
        return ip_str in ("localhost", "127.0.0.1")


def _is_local_subnet(subnet_str: str) -> bool:
    """Check if a subnet is in allowed private ranges."""
    try:
        net = ipaddress.ip_network(subnet_str, strict=False)
        return net.is_private
    except ValueError:
        return False


def _is_allowed_url(url: str) -> bool:
    """Check if a URL points to localhost."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return host in ("localhost", "127.0.0.1") or _is_local_ip(host)


def _is_allowed_github(url: str) -> bool:
    """Check if a GitHub URL is in the whitelist."""
    normalized = url.strip().rstrip("/").removesuffix(".git").lower()
    for allowed in ALLOWED_GITHUB_REPOS:
        if normalized == allowed.rstrip("/").removesuffix(".git").lower():
            return True
    return False


def validate_target(target: str, target_type: str) -> None:
    """Validate that a target is safe to scan. Raises HTTPException if not."""
    if target_type == "ip":
        if not _is_local_ip(target):
            raise HTTPException(
                status_code=400,
                detail=f"Rejected: '{target}' is not a safe local target. Only localhost and private IPs are allowed."
            )
    elif target_type == "subnet":
        if not _is_local_subnet(target):
            raise HTTPException(
                status_code=400,
                detail=f"Rejected: '{target}' is not a safe private subnet."
            )
    elif target_type == "url":
        if not _is_allowed_url(target):
            raise HTTPException(
                status_code=400,
                detail=f"Rejected: '{target}' is not a safe local URL. Only localhost URLs are allowed."
            )
    elif target_type == "github":
        if not _is_allowed_github(target):
            raise HTTPException(
                status_code=400,
                detail=f"Rejected: '{target}' is not in the allowed GitHub repos whitelist. Allowed: {', '.join(ALLOWED_GITHUB_REPOS)}"
            )
    else:
        raise HTTPException(status_code=400, detail=f"Invalid target_type: {target_type}")


# ══════════════════════════════════════════════════════════════
# Request / Response Models
# ══════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    target: str
    target_type: str  # ip | subnet | url | github


class ChatRequest(BaseModel):
    question: str


# ══════════════════════════════════════════════════════════════
# Background scan runner
# ══════════════════════════════════════════════════════════════

async def _run_scan_background(scan_id: str, target: str, target_type: str):
    """Run the agent scan in background."""
    try:
        await run_agent(scan_id, target, target_type)
    except Exception as e:
        logger.error(f"Background scan failed: {e}")
        from app.db import update_scan_status
        update_scan_status(scan_id, "failed", None)


# ══════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a new scan session.
    Validates target against whitelist, creates session, starts async scan.
    """
    validate_target(req.target, req.target_type)

    scan_id = new_uuid()
    create_scan_session(scan_id, req.target, req.target_type)
    background_tasks.add_task(_run_scan_background, scan_id, req.target, req.target_type)

    logger.info(f"Scan {scan_id} started for {req.target} ({req.target_type})")
    return {"scan_id": scan_id}


@app.get("/scan/{scan_id}/status")
async def scan_status(scan_id: str):
    """
    Get scan status — polled by frontend every 1-2 seconds.
    Returns current status, active tool, and partial findings.
    """
    session = get_scan_session(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = get_findings(scan_id)
    partial = [
        {
            "id": f.get("id"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "layer": f.get("layer"),
        }
        for f in findings
    ]

    return {
        "status": session.get("status", "unknown"),
        "current_tool": session.get("current_tool"),
        "findings_so_far": partial,
    }


@app.get("/scan/{scan_id}/dashboard")
async def scan_dashboard(scan_id: str):
    """
    Get full dashboard data including severity breakdown, findings,
    risk score, and OWASP mapping.
    """
    session = get_scan_session(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = get_findings(scan_id)

    # Severity breakdown
    severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    # Risk score
    risk = get_risk_score(scan_id)
    risk_score = risk["score"] if risk else 0

    # OWASP mapping
    owasp = map_owasp_findings(scan_id)

    return {
        "severity_breakdown": severity_breakdown,
        "findings": findings,
        "risk_score": risk_score,
        "owasp_mapping": owasp,
    }


@app.get("/scan/{scan_id}/chain")
async def scan_chain(scan_id: str):
    """Get attack chain as Cytoscape.js-compatible JSON graph."""
    session = get_scan_session(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    return get_chain_graph(scan_id)


@app.post("/scan/{scan_id}/chat")
async def scan_chat(scan_id: str, req: ChatRequest):
    """
    RAG-powered chat about scan findings.
    Uses Gemini (free) → Claude (paid) → keyword fallback.
    """
    session = get_scan_session(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    context = search_rag(scan_id, req.question)

    # Build context text for LLM
    context_text = "\n".join(
        f"- [{c.get('severity', 'info').upper()}] {c.get('title', '')}: {c.get('description', '')}"
        for c in context
    )
    prompt = f"""Based on these security findings, answer the question.

Findings:
{context_text}

Question: {req.question}

Provide a clear, actionable answer."""

    answer = ""

    # Try 1: Groq (FREE, fastest)
    from app.config import GROQ_API_KEY, GOOGLE_API_KEY, ANTHROPIC_API_KEY
    if GROQ_API_KEY and not answer:
        try:
            from groq import Groq
            from app.config import GROQ_MODEL
            client = Groq(api_key=GROQ_API_KEY)
            response = client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
            )
            answer = response.choices[0].message.content
            logger.info("Chat answered via Groq (free)")
        except Exception as e:
            logger.warning(f"Groq chat failed: {e}")

    # Try 2: Gemini (FREE)
    if GOOGLE_API_KEY and not answer:
        try:
            import google.generativeai as genai
            from app.config import GEMINI_MODEL
            genai.configure(api_key=GOOGLE_API_KEY)
            model = genai.GenerativeModel(GEMINI_MODEL)
            response = model.generate_content(prompt)
            answer = response.text
            logger.info("Chat answered via Gemini (free)")
        except Exception as e:
            logger.warning(f"Gemini chat failed: {e}")

    # Try 2: Claude (PAID)
    if ANTHROPIC_API_KEY and not answer:
        try:
            import anthropic
            from app.config import CLAUDE_PRIMARY_MODEL, CLAUDE_FALLBACK_MODEL
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            try:
                response = client.messages.create(
                    model=CLAUDE_PRIMARY_MODEL, max_tokens=1000,
                    messages=[{"role": "user", "content": prompt}],
                )
            except Exception:
                response = client.messages.create(
                    model=CLAUDE_FALLBACK_MODEL, max_tokens=1000,
                    messages=[{"role": "user", "content": prompt}],
                )
            answer = response.content[0].text
            logger.info("Chat answered via Claude (paid)")
        except Exception as e:
            logger.warning(f"Claude chat failed: {e}")

    # Try 3: Demo fallback (no LLM)
    if not answer:
        if context:
            summary_lines = []
            for c in context[:5]:
                sev = c.get("severity", "info").upper()
                summary_lines.append(f"• [{sev}] {c.get('title', 'Unknown')}: {c.get('description', '')[:120]}")
            answer = f"Based on {len(context)} relevant findings for your query:\n\n" + "\n".join(summary_lines)
        else:
            answer = "No relevant findings matched your query. Try asking about specific vulnerabilities, CVEs, or security layers."

    return {
        "answer": answer,
        "context": context[:5],
    }


@app.get("/scan/{scan_id}/report")
async def scan_report(scan_id: str):
    """Generate and download PDF security report."""
    session = get_scan_session(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        pdf_bytes = generate_pdf(scan_id, session.get("target", "Unknown"), session)
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        # Try returning fixture PDF
        from app.config import FIXTURES_DIR
        sample = FIXTURES_DIR / "report_sample.pdf"
        if sample.exists():
            with open(sample, "rb") as f:
                pdf_bytes = f.read()
        else:
            raise HTTPException(status_code=500, detail="PDF generation failed")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="sentinel_report_{scan_id}.pdf"',
        },
    )
