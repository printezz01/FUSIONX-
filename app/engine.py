"""
Sentinel AI — Engine Module
Attack chain building, risk scoring, OWASP mapping, RAG search, remediation.
"""

import json
import logging
from typing import Optional

import networkx as nx

from app.config import (
    FIXTURES_DIR, GROQ_API_KEY, GOOGLE_API_KEY, ANTHROPIC_API_KEY,
    GROQ_MODEL, GEMINI_MODEL, CLAUDE_PRIMARY_MODEL, CLAUDE_FALLBACK_MODEL,
    VOYAGE_API_KEY, OPENAI_API_KEY,
)
from app.db import (
    get_findings, insert_chain_edge, get_chain_edges,
    upsert_risk_score, insert_owasp_mapping, new_uuid,
)

logger = logging.getLogger("sentinel.engine")


# ══════════════════════════════════════════════════════════════
# Attack Chain Builder (NetworkX)
# ══════════════════════════════════════════════════════════════

def _tokenize(text: str) -> set[str]:
    """Split a gives/requires string into normalized tokens."""
    return {t.strip().lower() for t in text.split(",") if t.strip()}


def build_attack_chain(scan_id: str) -> dict:
    """
    Build a NetworkX DiGraph from findings.
    Edge A→B exists when tokens in A.gives overlap with tokens in B.requires.
    Returns Cytoscape.js-compatible JSON.
    """
    try:
        findings = get_findings(scan_id)
        if not findings:
            raise ValueError("No findings to chain")

        G = nx.DiGraph()

        # Add nodes
        for f in findings:
            G.add_node(f["id"], **{
                "label": f["title"],
                "severity": f.get("severity", "info"),
                "layer": f.get("layer", "unknown"),
                "gives": f.get("gives", ""),
                "requires": f.get("requires", ""),
            })

        # Add edges: A→B if A.gives overlaps B.requires
        for a in findings:
            a_gives = _tokenize(a.get("gives", ""))
            for b in findings:
                if a["id"] == b["id"]:
                    continue
                b_requires = _tokenize(b.get("requires", ""))
                overlap = a_gives & b_requires
                if overlap:
                    reason = f"{a['title']} provides {', '.join(overlap)} needed by {b['title']}"
                    G.add_edge(a["id"], b["id"], reason=reason)
                    insert_chain_edge(scan_id, a["id"], b["id"], reason)

        # Build Cytoscape.js JSON
        nodes = []
        for node_id, data in G.nodes(data=True):
            nodes.append({
                "data": {
                    "id": node_id,
                    "label": data.get("label", ""),
                    "severity": data.get("severity", "info"),
                    "layer": data.get("layer", "unknown"),
                }
            })

        edges = []
        for source, target, data in G.edges(data=True):
            edges.append({
                "data": {
                    "source": source,
                    "target": target,
                    "reason": data.get("reason", ""),
                }
            })

        return {"nodes": nodes, "edges": edges}
    except Exception as e:
        logger.warning(f"build_attack_chain failed ({e}), using fixture")
        fixture_path = FIXTURES_DIR / "attack_chain.json"
        if fixture_path.exists():
            with open(fixture_path) as f:
                return json.load(f)
        return {"nodes": [], "edges": []}


def get_chain_graph(scan_id: str) -> dict:
    """Get the chain graph — build if edges don't exist yet."""
    edges = get_chain_edges(scan_id)
    if not edges:
        return build_attack_chain(scan_id)

    findings = get_findings(scan_id)
    findings_map = {f["id"]: f for f in findings}

    nodes = []
    for f in findings:
        nodes.append({
            "data": {
                "id": f["id"],
                "label": f["title"],
                "severity": f.get("severity", "info"),
                "layer": f.get("layer", "unknown"),
            }
        })

    edge_list = []
    for e in edges:
        edge_list.append({
            "data": {
                "source": e["from_finding"],
                "target": e["to_finding"],
                "reason": e.get("reason", ""),
            }
        })

    return {"nodes": nodes, "edges": edge_list}


# ══════════════════════════════════════════════════════════════
# Risk Score Calculator (Section 6)
# ══════════════════════════════════════════════════════════════

def calculate_risk_score(scan_id: str) -> dict:
    """
    Calculate risk score starting at 100, subtracting per severity.
    Clamp to [0, 100].
    """
    findings = get_findings(scan_id)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    has_secret = False

    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
        title_lower = f.get("title", "").lower()
        if "secret" in title_lower or "leaked" in title_lower or "credential" in title_lower:
            has_secret = True

    score = 100
    score -= counts["critical"] * 15
    score -= counts["high"] * 8
    score -= counts["medium"] * 3
    score -= counts["low"] * 1

    # Check for attack chain length >= 3
    chain_deduction = 0
    try:
        chain = get_chain_edges(scan_id)
        if len(chain) >= 3:
            chain_deduction = 10
    except Exception:
        pass
    score -= chain_deduction

    secret_deduction = 5 if has_secret else 0
    score -= secret_deduction

    score = max(0, min(100, score))

    breakdown = {
        "starting_score": 100,
        "critical_count": counts["critical"],
        "critical_deduction": counts["critical"] * 15,
        "high_count": counts["high"],
        "high_deduction": counts["high"] * 8,
        "medium_count": counts["medium"],
        "medium_deduction": counts["medium"] * 3,
        "low_count": counts["low"],
        "low_deduction": counts["low"] * 1,
        "info_count": counts["info"],
        "chain_deduction": chain_deduction,
        "secret_deduction": secret_deduction,
        "final_score": score,
    }

    upsert_risk_score(scan_id, score, breakdown)
    return {"score": score, "breakdown": breakdown}


# ══════════════════════════════════════════════════════════════
# OWASP Top 10 (2021) Mapping (Section 7)
# ══════════════════════════════════════════════════════════════

OWASP_CATEGORIES = [
    "A01:2021 Broken Access Control",
    "A02:2021 Cryptographic Failures",
    "A03:2021 Injection",
    "A04:2021 Insecure Design",
    "A05:2021 Security Misconfiguration",
    "A06:2021 Vulnerable & Outdated Components",
    "A07:2021 Identification & Auth Failures",
    "A08:2021 Software & Data Integrity Failures",
    "A09:2021 Security Logging & Monitoring Failures",
    "A10:2021 Server-Side Request Forgery",
]


def _classify_owasp(finding: dict) -> str:
    """Map a finding to an OWASP 2021 category via keyword matching."""
    text = f"{finding.get('title', '')} {finding.get('description', '')}".lower()

    if any(k in text for k in ("injection", "sql", "sqli", "xss", "script", "command injection")):
        return "A03:2021 Injection"
    if any(k in text for k in ("broken access", "authorization", "privilege")):
        return "A01:2021 Broken Access Control"
    if any(k in text for k in ("cryptographic", "md5", "sha1", "weak hash", "encryption")):
        return "A02:2021 Cryptographic Failures"
    if any(k in text for k in ("secret", "credential", "password", "api key", "token", "leaked")):
        return "A02:2021 Cryptographic Failures"
    if any(k in text for k in ("default password", "default cred", "authentication", "brute")):
        return "A07:2021 Identification & Auth Failures"
    if any(k in text for k in ("misconfiguration", "open port", "directory listing", "debug", "header")):
        return "A05:2021 Security Misconfiguration"
    if any(k in text for k in ("cve", "outdated", "vulnerable component", "version")):
        return "A06:2021 Vulnerable & Outdated Components"
    if finding.get("cve_id"):
        return "A06:2021 Vulnerable & Outdated Components"

    return "A05:2021 Security Misconfiguration"


def map_owasp_findings(scan_id: str) -> dict:
    """Map all findings to OWASP categories and return pass/fail per category."""
    findings = get_findings(scan_id)
    category_findings: dict[str, list] = {cat: [] for cat in OWASP_CATEGORIES}

    for f in findings:
        category = _classify_owasp(f)
        if category in category_findings:
            category_findings[category].append(f["id"])
        insert_owasp_mapping(f.get("id", new_uuid()), category)

    result = {}
    for cat in OWASP_CATEGORIES:
        result[cat] = "fail" if category_findings[cat] else "pass"
    return result


# ══════════════════════════════════════════════════════════════
# RAG Search (Voyage AI / OpenAI embeddings + pgvector)
# ══════════════════════════════════════════════════════════════

def _embed_text(text: str) -> Optional[list[float]]:
    """Generate embedding using Voyage AI (primary) or OpenAI (fallback)."""
    res = _embed_texts([text])
    return res[0] if res else None

def _embed_texts(texts: list[str]) -> Optional[list[list[float]]]:
    """Generate embeddings in batch to avoid Voyage AI free tier rate limits (3 RPM)."""
    if not texts:
        return []
    if VOYAGE_API_KEY:
        try:
            import voyageai
            client = voyageai.Client(api_key=VOYAGE_API_KEY)
            # Voyage AI handles batching automatically when passing a list
            result = client.embed(texts, model="voyage-2")
            
            padded_vecs = []
            for vec in result.embeddings:
                # Pad to 1536 to match Supabase pgvector schema
                if len(vec) < 1536:
                    vec.extend([0.0] * (1536 - len(vec)))
                padded_vecs.append(vec)
            return padded_vecs
        except Exception as e:
            logger.warning(f"Voyage AI embedding failed: {e}")

    if OPENAI_API_KEY:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=OPENAI_API_KEY)
            result = client.embeddings.create(input=text, model="text-embedding-3-small")
            return result.data[0].embedding
        except Exception as e:
            logger.warning(f"OpenAI embedding failed: {e}")

    return None


def search_rag(scan_id: str, query: str) -> list[dict]:
    """
    Embed query and search findings via pgvector cosine similarity.
    Falls back to keyword search if embeddings unavailable.
    """
    try:
        query_embedding = _embed_text(query)
        if query_embedding:
            from app.db import get_supabase
            sb = get_supabase()
            result = sb.rpc("match_findings", {
                "query_embedding": query_embedding,
                "match_threshold": 0.5,
                "match_count": 5,
                "p_scan_id": scan_id,
            }).execute()
            if result.data:
                return result.data
    except Exception as e:
        logger.warning(f"RAG search failed ({e}), falling back to keyword search")

    # Fallback: simple keyword search
    findings = get_findings(scan_id)
    query_lower = query.lower()
    scored = []
    for f in findings:
        text = f"{f.get('title', '')} {f.get('description', '')}".lower()
        score = sum(1 for word in query_lower.split() if word in text)
        if score > 0:
            scored.append((score, f))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [f for _, f in scored[:5]]


# ══════════════════════════════════════════════════════════════
# Remediation Generator (Claude API)
# ══════════════════════════════════════════════════════════════

def generate_remediation(cve_list: list[str], findings: list[dict] = None) -> str:
    """Generate prioritized remediation steps. Uses Gemini (free) → Claude (paid) → default."""
    findings_context = ""
    if findings:
        for f in findings[:10]:
            findings_context += f"- [{f.get('severity', 'info').upper()}] {f.get('title', '')}: {f.get('description', '')}\n"

    prompt = f"""You are a cybersecurity expert. Based on the following vulnerability findings and CVEs,
provide prioritized, plain-English remediation steps. Be specific and actionable.

CVEs: {', '.join(cve_list) if cve_list else 'None identified'}

Findings:
{findings_context if findings_context else 'No detailed findings available'}

Provide remediation in this format:
1. [CRITICAL] ... (immediate action)
2. [HIGH] ... (urgent)
3. [MEDIUM] ... (planned fix)
etc.
"""

    # Try 1: Groq (FREE, fastest)
    if GROQ_API_KEY:
        try:
            from groq import Groq
            client = Groq(api_key=GROQ_API_KEY)
            response = client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1500,
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.warning(f"Groq remediation failed: {e}")

    # Try 2: Gemini (FREE)
    if GOOGLE_API_KEY:
        try:
            import google.generativeai as genai
            genai.configure(api_key=GOOGLE_API_KEY)
            model = genai.GenerativeModel(GEMINI_MODEL)
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.warning(f"Gemini remediation failed: {e}")

    # Try 2: Claude (PAID)
    if ANTHROPIC_API_KEY:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            try:
                response = client.messages.create(
                    model=CLAUDE_PRIMARY_MODEL, max_tokens=1500,
                    messages=[{"role": "user", "content": prompt}],
                )
            except Exception:
                response = client.messages.create(
                    model=CLAUDE_FALLBACK_MODEL, max_tokens=1500,
                    messages=[{"role": "user", "content": prompt}],
                )
            return response.content[0].text
        except Exception as e:
            logger.warning(f"Claude remediation failed: {e}")

    # Fallback: static default
    logger.info("Using default remediation (no LLM available)")
    return (
        "1. [CRITICAL] Patch all identified CVEs immediately\n"
        "2. [CRITICAL] Remove hardcoded credentials from source code\n"
        "3. [HIGH] Implement network segmentation and firewall rules\n"
        "4. [HIGH] Enable parameterized queries to prevent SQL injection\n"
        "5. [MEDIUM] Add security headers (X-Frame-Options, CSP, etc.)\n"
        "6. [MEDIUM] Disable directory listing on web servers\n"
        "7. [LOW] Update all services to latest stable versions\n"
    )
