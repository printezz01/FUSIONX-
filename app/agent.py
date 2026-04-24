"""
Sentinel AI — Agent Module
Supports four modes (auto-selected based on API keys):
  1. Groq Mode   — Llama 3.3 70B via Groq Cloud (FREE, fastest)
  2. Gemini Mode  — Google Gemini 2.0 Flash via LangChain (FREE)
  3. Claude Mode  — Anthropic Claude via LangChain (PAID)
  4. Demo Mode    — Runs all tools in sequence without LLM (no API key needed)
"""

import logging

from app.config import GROQ_API_KEY, GOOGLE_API_KEY, ANTHROPIC_API_KEY
from app.db import update_scan_status, get_findings
from app.tools import (
    scan_network, scan_code, scan_secrets, scan_web, scan_cctv, lookup_cve,
)
from app.engine import build_attack_chain, calculate_risk_score, map_owasp_findings

logger = logging.getLogger("sentinel.agent")


def _detect_mode() -> str:
    """Detect which LLM mode to use based on available API keys."""
    if GROQ_API_KEY and GROQ_API_KEY.strip():
        return "groq"
    if GOOGLE_API_KEY and GOOGLE_API_KEY.strip():
        return "gemini"
    if ANTHROPIC_API_KEY and ANTHROPIC_API_KEY.strip():
        return "claude"
    return "demo"


AGENT_MODE = _detect_mode()


# ══════════════════════════════════════════════════════════════
# Shared: LangChain tool wrappers (used by Groq, Gemini & Claude)
# ══════════════════════════════════════════════════════════════

def _create_langchain_tools(scan_id: str):
    """Create LangChain tool wrappers for the agent."""
    from langchain_core.tools import tool

    @tool
    def tool_scan_network(ip_range: str) -> str:
        """Scan a network IP range using nmap for open ports and services."""
        update_scan_status(scan_id, "running", "scan_network")
        results = scan_network(ip_range, scan_id)
        return f"Found {len(results)} network findings: " + "; ".join(
            f"{r['title']} ({r['severity']})" for r in results
        )

    @tool
    def tool_scan_code(github_url: str) -> str:
        """Scan source code from a GitHub repository using bandit and semgrep."""
        update_scan_status(scan_id, "running", "scan_code")
        results = scan_code(github_url, scan_id)
        return f"Found {len(results)} code findings: " + "; ".join(
            f"{r['title']} ({r['severity']})" for r in results
        )

    @tool
    def tool_scan_secrets(github_url: str) -> str:
        """Scan a GitHub repository for leaked secrets using trufflehog."""
        update_scan_status(scan_id, "running", "scan_secrets")
        results = scan_secrets(github_url, scan_id)
        return f"Found {len(results)} leaked secrets: " + "; ".join(
            f"{r['title']} ({r['severity']})" for r in results
        )

    @tool
    def tool_scan_web(url: str) -> str:
        """Scan a web application URL using nikto for web vulnerabilities."""
        update_scan_status(scan_id, "running", "scan_web")
        results = scan_web(url, scan_id)
        return f"Found {len(results)} web findings: " + "; ".join(
            f"{r['title']} ({r['severity']})" for r in results
        )

    @tool
    def tool_scan_cctv(ip: str) -> str:
        """Scan an IP for CCTV/IP camera vulnerabilities."""
        update_scan_status(scan_id, "running", "scan_cctv")
        results = scan_cctv(ip, scan_id)
        return f"Found {len(results)} IoT findings: " + "; ".join(
            f"{r['title']} ({r['severity']})" for r in results
        )

    @tool
    def tool_lookup_cve(service: str, version: str) -> str:
        """Look up known CVEs for a service and version from NVD."""
        update_scan_status(scan_id, "running", "lookup_cve")
        results = lookup_cve(service, version)
        if results:
            return f"Found {len(results)} CVEs: " + "; ".join(
                f"{r['cve_id']} (CVSS {r['cvss_score']})" for r in results
            )
        return "No CVEs found."

    @tool
    def tool_build_attack_chain() -> str:
        """Build attack chain graph from all findings. Call after all scans."""
        update_scan_status(scan_id, "running", "build_attack_chain")
        result = build_attack_chain(scan_id)
        return f"Attack chain: {len(result.get('nodes', []))} nodes, {len(result.get('edges', []))} edges."

    return [
        tool_scan_network, tool_scan_code, tool_scan_secrets,
        tool_scan_web, tool_scan_cctv, tool_lookup_cve, tool_build_attack_chain,
    ]


# ══════════════════════════════════════════════════════════════
# Demo Mode Runner (FREE — no API keys needed)
# ══════════════════════════════════════════════════════════════

async def _run_demo_mode(scan_id: str, target: str, target_type: str):
    """Run all relevant tools in sequence based on target_type. No LLM needed."""
    logger.info(f"[DEMO MODE] Running scan {scan_id} for {target} ({target_type})")
    update_scan_status(scan_id, "running", "initializing")

    try:
        if target_type == "ip":
            update_scan_status(scan_id, "running", "scan_network")
            network_findings = scan_network(target, scan_id)
            logger.info(f"Network scan: {len(network_findings)} findings")

            # Lookup CVEs for discovered services
            update_scan_status(scan_id, "running", "lookup_cve")
            for f in network_findings:
                raw = f.get("raw_output", {})
                service = raw.get("service", raw.get("product", ""))
                version = raw.get("version", "")
                if service and version:
                    cves = lookup_cve(service, version)
                    logger.info(f"CVE lookup for {service} {version}: {len(cves)} CVEs")

            # Try CCTV scan
            update_scan_status(scan_id, "running", "scan_cctv")
            cctv_findings = scan_cctv(target, scan_id)
            logger.info(f"CCTV scan: {len(cctv_findings)} findings")

        elif target_type == "subnet":
            update_scan_status(scan_id, "running", "scan_network")
            network_findings = scan_network(target, scan_id)
            logger.info(f"Network scan: {len(network_findings)} findings")

        elif target_type == "url":
            update_scan_status(scan_id, "running", "scan_web")
            web_findings = scan_web(target, scan_id)
            logger.info(f"Web scan: {len(web_findings)} findings")

        elif target_type == "github":
            update_scan_status(scan_id, "running", "scan_code")
            code_findings = scan_code(target, scan_id)
            logger.info(f"Code scan: {len(code_findings)} findings")

            update_scan_status(scan_id, "running", "scan_secrets")
            secret_findings = scan_secrets(target, scan_id)
            logger.info(f"Secrets scan: {len(secret_findings)} findings")

        # Post-processing (always runs)
        update_scan_status(scan_id, "running", "build_attack_chain")
        chain = build_attack_chain(scan_id)
        logger.info(f"Attack chain: {len(chain.get('nodes', []))} nodes, {len(chain.get('edges', []))} edges")

        update_scan_status(scan_id, "running", "calculating_risk_score")
        risk = calculate_risk_score(scan_id)
        logger.info(f"Risk score: {risk['score']}")

        update_scan_status(scan_id, "running", "mapping_owasp")
        owasp = map_owasp_findings(scan_id)
        logger.info(f"OWASP mapping complete")

        update_scan_status(scan_id, "complete", None)
        logger.info(f"[DEMO MODE] Scan {scan_id} completed successfully")

    except Exception as e:
        logger.error(f"[DEMO MODE] Scan failed: {e}")
        try:
            build_attack_chain(scan_id)
            calculate_risk_score(scan_id)
            map_owasp_findings(scan_id)
        except Exception:
            pass
        update_scan_status(scan_id, "failed", None)


# ══════════════════════════════════════════════════════════════
# Groq Mode Runner (FREE — Llama 3.3 70B, fastest inference)
# ══════════════════════════════════════════════════════════════

async def _run_groq_mode(scan_id: str, target: str, target_type: str):
    """Run the LangGraph ReAct agent with Groq Cloud (FREE, Llama 3.3 70B)."""
    from langchain_groq import ChatGroq
    from langgraph.prebuilt import create_react_agent
    from langchain_core.messages import HumanMessage
    from app.config import GROQ_MODEL

    try:
        update_scan_status(scan_id, "running", "initializing")
        tools = _create_langchain_tools(scan_id)

        system_prompt = (
            f"You are Sentinel AI, an autonomous security scanning agent. "
            f"Target: {target} | Type: {target_type}. "
            "Rules: For IP targets use scan_network then lookup_cve then scan_cctv. "
            "For URL targets use scan_web. "
            "For GitHub targets use scan_code AND scan_secrets. "
            "For subnet targets use scan_network. "
            "ALWAYS call build_attack_chain after all scans are done. Be thorough."
        )

        llm = ChatGroq(
            model=GROQ_MODEL,
            api_key=GROQ_API_KEY,
            temperature=0,
            max_tokens=4096,
        )

        agent = create_react_agent(llm, tools, prompt=system_prompt)
        await agent.ainvoke({
            "messages": [HumanMessage(content="Begin scanning now. Use all relevant tools for this target.")]
        })

        # Post-processing
        update_scan_status(scan_id, "running", "calculating_risk_score")
        calculate_risk_score(scan_id)
        update_scan_status(scan_id, "running", "mapping_owasp")
        map_owasp_findings(scan_id)
        update_scan_status(scan_id, "complete", None)
        logger.info(f"[GROQ MODE] Scan {scan_id} completed successfully")

    except Exception as e:
        logger.error(f"[GROQ MODE] Agent failed: {e}")
        try:
            build_attack_chain(scan_id)
            calculate_risk_score(scan_id)
            map_owasp_findings(scan_id)
        except Exception:
            pass
        update_scan_status(scan_id, "failed", None)


# ══════════════════════════════════════════════════════════════
# Gemini Mode Runner (FREE — requires GOOGLE_API_KEY)
# ══════════════════════════════════════════════════════════════

async def _run_gemini_mode(scan_id: str, target: str, target_type: str):
    """Run the LangGraph ReAct agent with Google Gemini 2.0 Flash (FREE)."""
    from langchain_google_genai import ChatGoogleGenerativeAI
    from langgraph.prebuilt import create_react_agent
    from langchain_core.messages import HumanMessage
    from app.config import GEMINI_MODEL

    try:
        update_scan_status(scan_id, "running", "initializing")
        tools = _create_langchain_tools(scan_id)

        system_prompt = (
            f"You are Sentinel AI, an autonomous security scanning agent. "
            f"Target: {target} | Type: {target_type}. "
            "For GitHub targets use scan_code AND scan_secrets. "
            "For IP targets use scan_network then lookup_cve then scan_cctv. "
            "For URL targets use scan_web. "
            "ALWAYS call build_attack_chain after all scans."
        )

        llm = ChatGoogleGenerativeAI(
            model=GEMINI_MODEL,
            google_api_key=GOOGLE_API_KEY,
            temperature=0,
            max_output_tokens=4096,
        )

        agent = create_react_agent(llm, tools, prompt=system_prompt)
        await agent.ainvoke({
            "messages": [HumanMessage(content="Begin scanning now. Use all relevant tools for this target.")]
        })

        # Post-processing
        update_scan_status(scan_id, "running", "calculating_risk_score")
        calculate_risk_score(scan_id)
        update_scan_status(scan_id, "running", "mapping_owasp")
        map_owasp_findings(scan_id)
        update_scan_status(scan_id, "complete", None)
        logger.info(f"[GEMINI MODE] Scan {scan_id} completed successfully")

    except Exception as e:
        logger.error(f"[GEMINI MODE] Agent failed: {e}")
        try:
            build_attack_chain(scan_id)
            calculate_risk_score(scan_id)
            map_owasp_findings(scan_id)
        except Exception:
            pass
        update_scan_status(scan_id, "failed", None)


# ══════════════════════════════════════════════════════════════
# Claude Mode Runner (PAID — requires ANTHROPIC_API_KEY)
# ══════════════════════════════════════════════════════════════

async def _run_claude_mode(scan_id: str, target: str, target_type: str):
    """Run the LangGraph ReAct agent with Claude (PAID fallback)."""
    from langchain_anthropic import ChatAnthropic
    from langgraph.prebuilt import create_react_agent
    from langchain_core.messages import HumanMessage
    from app.config import CLAUDE_PRIMARY_MODEL, CLAUDE_FALLBACK_MODEL

    try:
        update_scan_status(scan_id, "running", "initializing")
        tools = _create_langchain_tools(scan_id)

        system_prompt = (
            f"You are Sentinel AI, an autonomous security agent. "
            f"Target: {target} | Type: {target_type}. "
            "Scan the target thoroughly using all relevant tools, then build the attack chain."
        )

        try:
            llm = ChatAnthropic(model=CLAUDE_PRIMARY_MODEL, api_key=ANTHROPIC_API_KEY, max_tokens=4096, temperature=0)
        except Exception:
            llm = ChatAnthropic(model=CLAUDE_FALLBACK_MODEL, api_key=ANTHROPIC_API_KEY, max_tokens=4096, temperature=0)

        agent = create_react_agent(llm, tools, prompt=system_prompt)
        await agent.ainvoke({
            "messages": [HumanMessage(content="Begin scanning. Use all relevant tools.")]
        })

        # Post-processing
        update_scan_status(scan_id, "running", "calculating_risk_score")
        calculate_risk_score(scan_id)
        update_scan_status(scan_id, "running", "mapping_owasp")
        map_owasp_findings(scan_id)
        update_scan_status(scan_id, "complete", None)
        logger.info(f"[CLAUDE MODE] Scan {scan_id} completed successfully")

    except Exception as e:
        logger.error(f"[CLAUDE MODE] Agent failed: {e}")
        try:
            build_attack_chain(scan_id)
            calculate_risk_score(scan_id)
            map_owasp_findings(scan_id)
        except Exception:
            pass
        update_scan_status(scan_id, "failed", None)


# ══════════════════════════════════════════════════════════════
# Main Entry Point
# ══════════════════════════════════════════════════════════════

async def run_agent(scan_id: str, target: str, target_type: str) -> None:
    """Run the scan — auto-selects Groq → Gemini → Claude → Demo based on API keys."""
    mode = _detect_mode()

    if mode == "groq":
        logger.info("🟢 GROQ_API_KEY found — running in GROQ MODE (free, Llama 3.3 70B)")
        await _run_groq_mode(scan_id, target, target_type)
    elif mode == "gemini":
        logger.info("🟢 GOOGLE_API_KEY found — running in GEMINI MODE (free)")
        await _run_gemini_mode(scan_id, target, target_type)
    elif mode == "claude":
        logger.info("🔵 ANTHROPIC_API_KEY found — running in CLAUDE MODE (paid)")
        await _run_claude_mode(scan_id, target, target_type)
    else:
        logger.info("⚪ No API keys found — running in DEMO MODE (fixture data)")
        await _run_demo_mode(scan_id, target, target_type)
