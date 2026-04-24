import httpx
import time

base = "http://127.0.0.1:8000"

# Health check
r = httpx.get(f"{base}/health")
print("Server:", r.json())

# Start a fresh scan
r = httpx.post(
    f"{base}/scan",
    json={"target": "https://github.com/OWASP/PyGoat", "target_type": "github"},
    timeout=10
)
scan_id = r.json()["scan_id"]
print("Scan ID:", scan_id)

# Poll until complete
for i in range(30):
    time.sleep(3)
    s = httpx.get(f"{base}/scan/{scan_id}/status", timeout=10).json()
    status = s["status"]
    tool = s["current_tool"]
    count = len(s["findings_so_far"])
    print(f"  [{i*3}s] status={status} tool={tool} findings={count}")
    if status in ("complete", "failed"):
        break

# Download the PDF report
print("\nDownloading PDF report...")
r = httpx.get(f"{base}/scan/{scan_id}/report", timeout=30)
print("HTTP status    :", r.status_code)
print("Content-Type   :", r.headers.get("content-type"))
print("File size      :", len(r.content), "bytes")

# Save it
out = "demo_report.pdf"
with open(out, "wb") as f:
    f.write(r.content)
print(f"Saved to       : {out}")
