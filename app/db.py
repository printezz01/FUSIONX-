"""
Sentinel AI — Database Module
Supabase client initialization and helper functions.
"""

import uuid
import logging
from typing import Any, Optional

from supabase import create_client, Client

from app.config import SUPABASE_URL, SUPABASE_SERVICE_KEY

logger = logging.getLogger("sentinel.db")

# ─── Supabase Client ─────────────────────────────────────────
_client: Optional[Client] = None


def get_supabase() -> Client:
    """Get or create the Supabase client singleton."""
    global _client
    if _client is None:
        if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
            logger.warning("Supabase credentials not configured — DB operations will fail gracefully")
            raise RuntimeError("Supabase not configured")
        _client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    return _client


def new_uuid() -> str:
    """Generate a new UUID string."""
    return str(uuid.uuid4())


# ──────────────────────────────────────────────────────────────
# Scan Sessions
# ──────────────────────────────────────────────────────────────

def create_scan_session(scan_id: str, target: str, target_type: str) -> dict:
    """Create a new scan session record."""
    try:
        sb = get_supabase()
        data = {
            "id": scan_id,
            "target": target,
            "target_type": target_type,
            "status": "queued",
        }
        result = sb.table("scan_sessions").insert(data).execute()
        return result.data[0] if result.data else data
    except Exception as e:
        logger.error(f"Failed to create scan session: {e}")
        return {"id": scan_id, "target": target, "target_type": target_type, "status": "queued"}


def update_scan_status(scan_id: str, status: str, current_tool: str = None) -> None:
    """Update scan session status and current tool."""
    try:
        sb = get_supabase()
        update_data: dict[str, Any] = {"status": status}
        if current_tool is not None:
            update_data["current_tool"] = current_tool
        if status in ("complete", "failed"):
            update_data["completed_at"] = "now()"
        sb.table("scan_sessions").update(update_data).eq("id", scan_id).execute()
    except Exception as e:
        logger.error(f"Failed to update scan status: {e}")


def get_scan_session(scan_id: str) -> Optional[dict]:
    """Get a scan session by ID."""
    try:
        sb = get_supabase()
        result = sb.table("scan_sessions").select("*").eq("id", scan_id).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        logger.error(f"Failed to get scan session: {e}")
        return None


# ──────────────────────────────────────────────────────────────
# Findings
# ──────────────────────────────────────────────────────────────

def insert_finding(finding: dict) -> dict:
    """Insert a single finding into the findings table."""
    try:
        sb = get_supabase()
        # Don't insert embedding via normal insert — handle separately
        finding_data = {k: v for k, v in finding.items() if k != "embedding"}
        if "id" not in finding_data:
            finding_data["id"] = new_uuid()
        result = sb.table("findings").insert(finding_data).execute()
        return result.data[0] if result.data else finding_data
    except Exception as e:
        logger.error(f"Failed to insert finding: {e}")
        finding.setdefault("id", new_uuid())
        return finding


def insert_findings(findings: list[dict], scan_id: str) -> list[dict]:
    """Insert multiple findings for a scan."""
    results = []
    for f in findings:
        f["scan_id"] = scan_id
        if "id" not in f:
            f["id"] = new_uuid()
        results.append(insert_finding(f))
    return results


def get_findings(scan_id: str) -> list[dict]:
    """Get all findings for a scan session."""
    try:
        sb = get_supabase()
        result = sb.table("findings").select("*").eq("scan_id", scan_id).execute()
        return result.data or []
    except Exception as e:
        logger.error(f"Failed to get findings: {e}")
        return []


# ──────────────────────────────────────────────────────────────
# Chain Edges
# ──────────────────────────────────────────────────────────────

def insert_chain_edge(scan_id: str, from_finding: str, to_finding: str, reason: str) -> dict:
    """Insert a chain edge."""
    try:
        sb = get_supabase()
        data = {
            "id": new_uuid(),
            "scan_id": scan_id,
            "from_finding": from_finding,
            "to_finding": to_finding,
            "reason": reason,
        }
        result = sb.table("chain_edges").insert(data).execute()
        return result.data[0] if result.data else data
    except Exception as e:
        logger.error(f"Failed to insert chain edge: {e}")
        return {"id": new_uuid(), "scan_id": scan_id, "from_finding": from_finding, "to_finding": to_finding, "reason": reason}


def get_chain_edges(scan_id: str) -> list[dict]:
    """Get all chain edges for a scan."""
    try:
        sb = get_supabase()
        result = sb.table("chain_edges").select("*").eq("scan_id", scan_id).execute()
        return result.data or []
    except Exception as e:
        logger.error(f"Failed to get chain edges: {e}")
        return []


# ──────────────────────────────────────────────────────────────
# Risk Scores
# ──────────────────────────────────────────────────────────────

def upsert_risk_score(scan_id: str, score: int, breakdown: dict) -> dict:
    """Insert or update risk score for a scan."""
    try:
        sb = get_supabase()
        data = {"scan_id": scan_id, "score": score, "breakdown": breakdown}
        result = sb.table("risk_scores").upsert(data).execute()
        return result.data[0] if result.data else data
    except Exception as e:
        logger.error(f"Failed to upsert risk score: {e}")
        return {"scan_id": scan_id, "score": score, "breakdown": breakdown}


def get_risk_score(scan_id: str) -> Optional[dict]:
    """Get risk score for a scan."""
    try:
        sb = get_supabase()
        result = sb.table("risk_scores").select("*").eq("scan_id", scan_id).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        logger.error(f"Failed to get risk score: {e}")
        return None


# ──────────────────────────────────────────────────────────────
# OWASP Mappings
# ──────────────────────────────────────────────────────────────

def insert_owasp_mapping(finding_id: str, owasp_category: str) -> dict:
    """Insert an OWASP mapping."""
    try:
        sb = get_supabase()
        data = {"id": new_uuid(), "finding_id": finding_id, "owasp_category": owasp_category}
        result = sb.table("owasp_mappings").insert(data).execute()
        return result.data[0] if result.data else data
    except Exception as e:
        logger.error(f"Failed to insert OWASP mapping: {e}")
        return {"id": new_uuid(), "finding_id": finding_id, "owasp_category": owasp_category}


def get_owasp_mappings(scan_id: str) -> list[dict]:
    """Get OWASP mappings for all findings in a scan."""
    try:
        sb = get_supabase()
        # Join through findings to get mappings for a scan
        findings = get_findings(scan_id)
        finding_ids = [f["id"] for f in findings]
        if not finding_ids:
            return []
        result = sb.table("owasp_mappings").select("*").in_("finding_id", finding_ids).execute()
        return result.data or []
    except Exception as e:
        logger.error(f"Failed to get OWASP mappings: {e}")
        return []
