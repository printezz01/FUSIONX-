import httpx, time

base = "http://127.0.0.1:8000"

# 1. Health check
r = httpx.get(f"{base}/health")
print(f"[1] Health: {r.json()}")

# 2. Start a scan
r = httpx.post(f"{base}/scan",
    json={"target": "https://github.com/OWASP/PyGoat", "target_type": "github"},
    timeout=10)
data = r.json()
scan_id = data["scan_id"]
print(f"[2] Scan started: {scan_id}")

# 3. Poll status for up to 60s
print("[3] Polling status...")
final = {}
for i in range(30):
    time.sleep(2)
    r = httpx.get(f"{base}/scan/{scan_id}/status", timeout=10)
    s = r.json()
    status = s["status"]
    tool = s["current_tool"]
    count = len(s["findings_so_far"])
    print(f"    [{i*2}s] status={status} tool={tool} findings={count}")
    final = s
    if status in ("complete", "failed"):
        break

print(f"\n[4] Final status: {final.get('status')}")

# 4. Get dashboard
r = httpx.get(f"{base}/scan/{scan_id}/dashboard", timeout=10)
dash = r.json()
print(f"[5] Risk score: {dash.get('risk_score')}")
print(f"[5] Severity breakdown: {dash.get('severity_breakdown')}")
print(f"[5] Total findings: {len(dash.get('findings', []))}")

# 5. Test chat
r = httpx.post(f"{base}/scan/{scan_id}/chat",
    json={"question": "What is the most critical vulnerability?"},
    timeout=30)
chat = r.json()
print(f"\n[6] Chat answer (first 200 chars):")
print(f"    {chat.get('answer', '')[:200]}")
