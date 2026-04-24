"""
Sentinel AI — LangChain ReAct Agent
Autonomous security scanning agent that decides which tools to use.
"""

import logging
from typing import Optional

from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
from langchain.agents import AgentExecutor, create_tool_use_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

from app.config import ANTHROPIC_API_KEY, PRIMARY_MODEL, FALLBACK_MODEL
from app.db import update_scan_status
from app.tools import (
    scan_network, scan_code, scan_secrets, scan_web, scan_cctv, lookup_cve,
)
from app.engine import build_attack_chain, search_rag, generate_remediation

logger = logging.getLogger("sentinel.agent")


# ══════════════════════════════════════════════════════════════
# LangChain Tool Wrappers
# ══════════════════════════════════════════════════════════════

def _make_tools(scan_id: str):
    """Create LangChain tools bound to a specific scan_id."""

    @tool
    def tool_scan_network(ip_range: str) -> str:
        """Scan a network IP range using nmap for open ports and services.
        Use this when the target is an IP address or subnet.
        Returns a list of open ports, services, and their versions."""
        update_scan_status(scan_id, "running", "scan_network")
        results = scan_network(ip_range, scan_id)
        return f"Found {len(results)} network findings: " + "; ".join(
            f"{r['title']} ({r['severity']})" for r in results
        )

    @tool
    def tool_scan_code(github_url: str) -> str:
        """Scan source code from a GitHub repository using bandit and semgrep.
        Use this when the target is a GitHub URL to find code vulnerabilities
        like hardcoded passwords, SQL injection, and insecure functions."""
        update_scan_status(scan_id, "running", "scan_code")
        results = scan_code(github_url, scan_id)
        return f"Found {len(results)} code findings: " + "; ".join(
            f"{r['title']} ({r['severity']})" for r in results
        )

    @tool
    def tool_scan_secrets(github_url: str) -> str:
        """Scan a GitHub repository for leaked secrets, API keys, and credentials
        using trufflehog. Use this when you want to find accidentally committed secrets."""
        update_scan_status(scan_id, "running", "scan_secrets")
        results = scan_secrets(github_url, scan_id)
        return f"Found {len(results)} leaked secrets: " + "; ".join(
            f"{r['title']} ({r['severity']})" for r in results
        )

    @tool
    def tool_scan_web(url: str) -> str:
        """Scan a web application URL using nikto for web vulnerabilities.
        Use this when the target is a web URL to find SQL injection, XSS,
        misconfiguration, and other web security issues."""
        update_scan_status(scan_id, "running", "scan_web")
        results = scan_web(url, scan_id)
        return f"Found {len(results)} web findings: " + "; ".join(
            f"{r['title']} ({r['severity']})" for r in results
        )

    @tool
    def tool_scan_cctv(ip: str) -> str:
        """Scan an IP address for CCTV/IP camera vulnerabilities.
        Checks for Hikvision and Dahua camera fingerprints and known CVEs.
        Use this for IoT/camera targets."""
        update_scan_status(scan_id, "running", "scan_cctv")
        results = scan_cctv(ip, scan_id)
        return f"Found {len(results)} IoT findings: " + "; ".join(
            f"{r['title']} ({r['severity']})" for r in results
        )

    @tool
    def tool_lookup_cve(service: str, version: str) -> str:
        """Look up known CVEs for a specific service and version from NVD.
        Use this after finding open services to check for known vulnerabilities.
        Results are cached locally to avoid duplicate API calls."""
        update_scan_status(scan_id, "running", "lookup_cve")
        results = lookup_cve(service, version)
        if results:
            return f"Found {len(results)} CVEs: " + "; ".join(
                f"{r['cve_id']} (CVSS {r['cvss_score']})" for r in results
            )
        return "No CVEs found for this service version."

    @tool
    def tool_build_attack_chain() -> str:
        """Build an attack chain graph from all findings found so far.
        This connects vulnerabilities across layers (network, web, code, IoT)
        to show how an attacker could chain them together.
        Call this AFTER all scanning tools have completed."""
        update_scan_status(scan_id, "running", "build_attack_chain")
        result = build_attack_chain(scan_id)
        nodes = len(result.get("nodes", []))
        edges = len(result.get("edges", []))
        return f"Attack chain built: {nodes} nodes, {edges} edges."

    @tool
    def tool_generate_remediation(cve_list: str) -> str:
        """Generate prioritized remediation steps for discovered vulnerabilities.
        Pass a comma-separated list of CVE IDs. Call this as the final step."""
        update_scan_status(scan_id, "running", "generate_remediation")
        cves = [c.strip() for c in cve_list.split(",") if c.strip()]
        from app.db import get_findings
        findings = get_findings(scan_id)
        result = generate_remediation(cves, findings)
        return result

    return [
        tool_scan_network,
        tool_scan_code,
        tool_scan_secrets,
        tool_scan_web,
        tool_scan_cctv,
        tool_lookup_cve,
        tool_build_attack_chain,
        tool_generate_remediation,
    ]


# ══════════════════════════════════════════════════════════════
# Agent System Prompt
# ══════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are Sentinel AI, an autonomous security intelligence agent.
Your job is to thoroughly scan a target and build a complete threat picture.

RULES:
1. Analyze the target type and decide which tools to run
2. For IP/subnet targets: run scan_network, then lookup_cve for discovered services
3. For URL targets: run scan_web
4. For GitHub targets: run scan_code AND scan_secrets
5. If an IP is provided, also try scan_cctv to check for IoT devices
6. ALWAYS call build_attack_chain after all scans complete
7. ALWAYS call generate_remediation as your final action
8. Think step by step about what the attacker could do with each finding
9. Be thorough — run every relevant tool for the target type

You have these tools: scan_network, scan_code, scan_secrets, scan_web,
scan_cctv, lookup_cve, build_attack_chain, generate_remediation.

Current target: {target}
Target type: {target_type}

Analyze the target and run all relevant security scans."""


# ══════════════════════════════════════════════════════════════
# Agent Runner
# ══════════════════════════════════════════════════════════════

async def run_agent(scan_id: str, target: str, target_type: str) -> None:
    """Run the LangChain ReAct agent for a scan session."""
    try:
        update_scan_status(scan_id, "running", "initializing")

        # Initialize LLM with fallback
        try:
            llm = ChatAnthropic(
                model=PRIMARY_MODEL,
                api_key=ANTHROPIC_API_KEY,
                max_tokens=4096,
                temperature=0,
            )
        except Exception:
            llm = ChatAnthropic(
                model=FALLBACK_MODEL,
                api_key=ANTHROPIC_API_KEY,
                max_tokens=4096,
                temperature=0,
            )

        tools = _make_tools(scan_id)

        prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_PROMPT),
            ("human", "Begin scanning target: {target} (type: {target_type}). Use all relevant tools to build a complete security assessment."),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])

        agent = create_tool_use_agent(llm, tools, prompt)
        executor = AgentExecutor(
            agent=agent,
            tools=tools,
            verbose=True,
            max_iterations=15,
            handle_parsing_errors=True,
        )

        await executor.ainvoke({
            "target": target,
            "target_type": target_type,
        })

        # Post-processing
        from app.engine import calculate_risk_score, map_owasp_findings
        update_scan_status(scan_id, "running", "calculating_risk_score")
        calculate_risk_score(scan_id)

        update_scan_status(scan_id, "running", "mapping_owasp")
        map_owasp_findings(scan_id)

        update_scan_status(scan_id, "complete", None)
        logger.info(f"Scan {scan_id} completed successfully")

    except Exception as e:
        logger.error(f"Agent failed for scan {scan_id}: {e}")
        # Even on failure, try to process whatever findings we have
        try:
            from app.engine import calculate_risk_score, map_owasp_findings, build_attack_chain
            build_attack_chain(scan_id)
            calculate_risk_score(scan_id)
            map_owasp_findings(scan_id)
        except Exception as post_err:
            logger.error(f"Post-processing also failed: {post_err}")
        update_scan_status(scan_id, "failed", None)
