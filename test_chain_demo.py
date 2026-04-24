"""
Demo: Cross-layer attack chain -- code bug + open port = hacker path
Shows tree/graph output from /scan/{id}/chain
"""
import httpx
import time
import json

base = "http://127.0.0.1:8000"

# --- Start a GitHub scan (loads both code_scan + secrets fixtures) ---
r = httpx.post(f"{base}/scan",
    json={"target": "https://github.com/OWASP/PyGoat", "target_type": "github"},
    timeout=10)
scan_id = r.json()["scan_id"]
print(f"Scan ID: {scan_id}\n")

# Poll to completion
for i in range(30):
    time.sleep(2)
    s = httpx.get(f"{base}/scan/{scan_id}/status", timeout=10).json()
    if s["status"] in ("complete", "failed"):
        print(f"Scan {s['status']} with {len(s['findings_so_far'])} findings\n")
        break

# --- Get the attack CHAIN graph ---
chain = httpx.get(f"{base}/scan/{scan_id}/chain", timeout=10).json()
nodes = chain["nodes"]
edges = chain["edges"]

# Build a lookup map
node_map = {n["data"]["id"]: n["data"] for n in nodes}

print("=" * 65)
print("  ATTACK CHAIN -- How a hacker can chain vulnerabilities")
print("=" * 65)

if not edges:
    print("  No chains detected in this scan.\n")
else:
    for i, edge in enumerate(edges, 1):
        src = node_map.get(edge["data"]["source"], {})
        tgt = node_map.get(edge["data"]["target"], {})
        reason = edge["data"]["reason"]

        src_sev = src.get("severity", "?").upper()
        tgt_sev = tgt.get("severity", "?").upper()
        src_layer = src.get("layer", "?").upper()
        tgt_layer = tgt.get("layer", "?").upper()

        print(f"\n  Chain #{i}")
        print(f"  +-- [{src_sev}] [{src_layer}]  {src.get('label', '?')}")
        print(f"  |        >>  {reason}")
        print(f"  +-- [{tgt_sev}] [{tgt_layer}]  {tgt.get('label', '?')}")

# --- Full tree view of all findings ---
print("\n\n" + "=" * 65)
print("  FULL FINDINGS TREE")
print("=" * 65)

dashboard = httpx.get(f"{base}/scan/{scan_id}/dashboard", timeout=10).json()
findings = dashboard["findings"]

# Group by layer
from collections import defaultdict
by_layer = defaultdict(list)
for f in findings:
    by_layer[f.get("layer", "unknown")].append(f)

for layer, layer_findings in by_layer.items():
    print(f"\n  [LAYER: {layer.upper()}]  ({len(layer_findings)} findings)")
    for f in layer_findings:
        sev = f.get("severity", "info").upper()
        sev_tag = {"CRITICAL": "[!!!]", "HIGH": "[!! ]", "MEDIUM": "[ ! ]", "LOW": "[   ]", "INFO": "[inf]"}.get(sev, "[?]")
        print(f"  |-- {sev_tag} [{sev:8s}]  {f['title']}")
        if f.get("gives"):
            print(f"  |       gives    ->  {f['gives']}")
        if f.get("requires"):
            print(f"  |       requires <-  {f['requires']}")
        if f.get("cve_id"):
            print(f"  |       CVE      :   {f['cve_id']}")

# --- Risk Score ---
print(f"\n\n  Risk Score : {dashboard['risk_score']} / 100")
print(f"  Breakdown  : critical={dashboard['severity_breakdown']['critical']} "
      f"high={dashboard['severity_breakdown']['high']} "
      f"medium={dashboard['severity_breakdown']['medium']}")

# --- OWASP ---
print("\n  OWASP Top 10 (2021):")
for cat, status in dashboard["owasp_mapping"].items():
    icon = "[FAIL]" if status == "fail" else "[ OK ]"
    print(f"    {icon}  {cat}")
