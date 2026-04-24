"""
Sentinel AI — Database Module
Supports two modes:
  1. Supabase Mode — stores data in Supabase PostgreSQL (requires SUPABASE_URL + KEY)
  2. In-Memory Mode — stores data in dictionaries (free, no setup needed)
"""

import uuid
import logging
from typing import Any, Optional

from app.config import SUPABASE_URL, SUPABASE_SERVICE_KEY

logger = logging.getLogger("sentinel.db")

# ─── Mode Detection ──────────────────────────────────────────
USE_SUPABASE = bool(SUPABASE_URL and SUPABASE_SERVICE_KEY)

# ─── In-Memory Storage (demo fallback) ───────────────────────
_mem_sessions: dict[str, dict] = {}
_mem_findings: dict[str, list[dict]] = {}
_mem_chain_edges: dict[str, list[dict]] = {}
_mem_risk_scores: dict[str, dict] = {}
_mem_owasp_mappings: dict[str, list[dict]] = {}

# ─── Supabase Client ─────────────────────────────────────────
_client = None


def get_supabase():
    """Get or create the Supabase client singleton."""
    global _client
    if _client is None:
        if not USE_SUPABASE:
            raise RuntimeError("Supabase not configured — using in-memory mode")
        from supabase import create_client
        _client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    return _client


def new_uuid() -> str:
    """Generate a new UUID string."""
    return str(uuid.uuid4())


# ══════════════════════════════════════════════════════════════
# Scan Sessions
# ══════════════════════════════════════════════════════════════

def create_scan_session(scan_id: str, target: str, target_type: str) -> dict:
    data = {
        "id": scan_id,
        "target": target,
        "target_type": target_type,
        "status": "queued",
        "current_tool": None,
        "created_at": None,
        "completed_at": None,
    }
    if USE_SUPABASE:
        try:
            sb = get_supabase()
            result = sb.table("scan_sessions").insert({
                "id": scan_id, "target": target,
                "target_type": target_type, "status": "queued"
            }).execute()
            return result.data[0] if result.data else data
        except Exception as e:
            logger.error(f"Supabase create_scan_session failed: {e}")
    _mem_sessions[scan_id] = data
    return data


def update_scan_status(scan_id: str, status: str, current_tool: str = None) -> None:
    if USE_SUPABASE:
        try:
            from datetime import datetime, timezone
            sb = get_supabase()
            update_data: dict[str, Any] = {"status": status}
            if current_tool is not None:
                update_data["current_tool"] = current_tool
            if status in ("complete", "failed"):
                update_data["completed_at"] = datetime.now(timezone.utc).isoformat()
            sb.table("scan_sessions").update(update_data).eq("id", scan_id).execute()
            return
        except Exception as e:
            logger.error(f"Supabase update failed: {e}")
    # In-memory fallback
    if scan_id in _mem_sessions:
        _mem_sessions[scan_id]["status"] = status
        _mem_sessions[scan_id]["current_tool"] = current_tool


def get_scan_session(scan_id: str) -> Optional[dict]:
    if USE_SUPABASE:
        try:
            sb = get_supabase()
            result = sb.table("scan_sessions").select("*").eq("id", scan_id).execute()
            return result.data[0] if result.data else None
        except Exception as e:
            logger.error(f"Supabase get_scan_session failed: {e}")
    return _mem_sessions.get(scan_id)


# ══════════════════════════════════════════════════════════════
# Findings
# ══════════════════════════════════════════════════════════════

def insert_finding(finding: dict) -> dict:
    if "id" not in finding:
        finding["id"] = new_uuid()
    if USE_SUPABASE:
        try:
            sb = get_supabase()
            finding_data = {k: v for k, v in finding.items() if k != "embedding"}
            result = sb.table("findings").insert(finding_data).execute()
            return result.data[0] if result.data else finding
        except Exception as e:
            logger.error(f"Supabase insert_finding failed: {e}")
    # In-memory
    scan_id = finding.get("scan_id", "unknown")
    if scan_id not in _mem_findings:
        _mem_findings[scan_id] = []
    _mem_findings[scan_id].append(finding)
    return finding


def insert_findings(findings: list[dict], scan_id: str) -> list[dict]:
    results = []
    for f in findings:
        f["scan_id"] = scan_id
        if "id" not in f:
            f["id"] = new_uuid()
        results.append(insert_finding(f))
    return results


def get_findings(scan_id: str) -> list[dict]:
    if USE_SUPABASE:
        try:
            sb = get_supabase()
            result = sb.table("findings").select("*").eq("scan_id", scan_id).execute()
            return result.data or []
        except Exception as e:
            logger.error(f"Supabase get_findings failed: {e}")
    return _mem_findings.get(scan_id, [])


# ══════════════════════════════════════════════════════════════
# Chain Edges
# ══════════════════════════════════════════════════════════════

def insert_chain_edge(scan_id: str, from_finding: str, to_finding: str, reason: str) -> dict:
    data = {
        "id": new_uuid(),
        "scan_id": scan_id,
        "from_finding": from_finding,
        "to_finding": to_finding,
        "reason": reason,
    }
    if USE_SUPABASE:
        try:
            sb = get_supabase()
            result = sb.table("chain_edges").insert(data).execute()
            return result.data[0] if result.data else data
        except Exception as e:
            logger.error(f"Supabase insert_chain_edge failed: {e}")
    if scan_id not in _mem_chain_edges:
        _mem_chain_edges[scan_id] = []
    _mem_chain_edges[scan_id].append(data)
    return data


def get_chain_edges(scan_id: str) -> list[dict]:
    if USE_SUPABASE:
        try:
            sb = get_supabase()
            result = sb.table("chain_edges").select("*").eq("scan_id", scan_id).execute()
            return result.data or []
        except Exception as e:
            logger.error(f"Supabase get_chain_edges failed: {e}")
    return _mem_chain_edges.get(scan_id, [])


# ══════════════════════════════════════════════════════════════
# Risk Scores
# ══════════════════════════════════════════════════════════════

def upsert_risk_score(scan_id: str, score: int, breakdown: dict) -> dict:
    data = {"scan_id": scan_id, "score": score, "breakdown": breakdown}
    if USE_SUPABASE:
        try:
            sb = get_supabase()
            result = sb.table("risk_scores").upsert(data).execute()
            return result.data[0] if result.data else data
        except Exception as e:
            logger.error(f"Supabase upsert_risk_score failed: {e}")
    _mem_risk_scores[scan_id] = data
    return data


def get_risk_score(scan_id: str) -> Optional[dict]:
    if USE_SUPABASE:
        try:
            sb = get_supabase()
            result = sb.table("risk_scores").select("*").eq("scan_id", scan_id).execute()
            return result.data[0] if result.data else None
        except Exception as e:
            logger.error(f"Supabase get_risk_score failed: {e}")
    return _mem_risk_scores.get(scan_id)


# ══════════════════════════════════════════════════════════════
# OWASP Mappings
# ══════════════════════════════════════════════════════════════

def insert_owasp_mapping(finding_id: str, owasp_category: str) -> dict:
    data = {"id": new_uuid(), "finding_id": finding_id, "owasp_category": owasp_category}
    if USE_SUPABASE:
        try:
            sb = get_supabase()
            result = sb.table("owasp_mappings").insert(data).execute()
            return result.data[0] if result.data else data
        except Exception as e:
            logger.error(f"Supabase insert_owasp_mapping failed: {e}")
    if finding_id not in _mem_owasp_mappings:
        _mem_owasp_mappings[finding_id] = []
    _mem_owasp_mappings[finding_id].append(data)
    return data


def get_owasp_mappings(scan_id: str) -> list[dict]:
    if USE_SUPABASE:
        try:
            sb = get_supabase()
            findings = get_findings(scan_id)
            finding_ids = [f["id"] for f in findings]
            if not finding_ids:
                return []
            result = sb.table("owasp_mappings").select("*").in_("finding_id", finding_ids).execute()
            return result.data or []
        except Exception as e:
            logger.error(f"Supabase get_owasp_mappings failed: {e}")
    # In-memory
    findings = get_findings(scan_id)
    result = []
    for f in findings:
        result.extend(_mem_owasp_mappings.get(f["id"], []))
    return result
