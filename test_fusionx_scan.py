import httpx, time

base = "http://127.0.0.1:8000"

# Scan FUSIONX repo
r = httpx.post(f"{base}/scan",
    json={"target": "https://github.com/printezz01/FUSIONX-", "target_type": "github"},
    timeout=10)
print("Response:", r.status_code, r.text[:200])
scan_id = r.json()["scan_id"]
print(f"Scan ID: {scan_id}")

for i in range(40):
    time.sleep(3)
    s = httpx.get(f"{base}/scan/{scan_id}/status", timeout=10).json()
    print(f"  [{i*3}s] {s['status']} / {s['current_tool']} / {len(s['findings_so_far'])} findings")
    if s["status"] in ("complete", "failed"):
        break

r = httpx.get(f"{base}/scan/{scan_id}/report", timeout=30)
print(f"\nPDF: {r.status_code} / {len(r.content)} bytes / {r.headers.get('content-type')}")
with open("fusionx_security_report.pdf", "wb") as f:
    f.write(r.content)
print("Saved: fusionx_security_report.pdf")
