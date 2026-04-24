# 🛡️ Sentinel AI — Autonomous Security Intelligence Platform

> **Hackathon Demo** | Multi-layer vulnerability scanning, attack chain analysis, and AI-powered remediation.

---

## 🏗️ Architecture

Sentinel AI uses a **LangChain ReAct agent** powered by **Claude Sonnet** to autonomously scan targets across four layers:

| Layer      | Tool          | What it Scans                    |
| ---------- | ------------- | -------------------------------- |
| 🌐 Network | python-nmap   | Open ports, services, versions   |
| 🔒 Web     | nikto         | SQL injection, XSS, misconfig   |
| 💻 Code    | bandit+semgrep| Hardcoded secrets, bad patterns  |
| 📹 IoT     | HTTP fingerprint | Camera CVEs (Hikvision/Dahua) |

The agent chains findings together using **NetworkX** to discover multi-step attack paths.

---

## 📋 Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Git
- API Keys: Anthropic, Supabase, NVD (free), Voyage AI or OpenAI

---

## 🚀 Setup

### 1. Install System Dependencies

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env and fill in your API keys
```

### 3. Start Docker Targets

```bash
docker-compose up -d
```

### 4. Run Database Migrations

Run the SQL in `migrations/001_create_tables.sql` against your Supabase project via the SQL Editor.

### 5. Start the Server

```bash
uvicorn app.main:app --reload
```

Server runs at `http://localhost:8000`

---

## 🎯 Demo Walkthrough

### Scan DVWA (Web)
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "http://localhost:4280", "target_type": "url"}'
```

### Scan OWASP PyGoat (Code)
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://github.com/OWASP/PyGoat", "target_type": "github"}'
```

### Scan Metasploitable (Network)
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "target_type": "ip"}'
```

### Check Status (poll every 1-2s)
```bash
curl http://localhost:8000/scan/{scan_id}/status
```

### View Dashboard
```bash
curl http://localhost:8000/scan/{scan_id}/dashboard
```

### View Attack Chain
```bash
curl http://localhost:8000/scan/{scan_id}/chain
```

### Chat with Findings
```bash
curl -X POST http://localhost:8000/scan/{scan_id}/chat \
  -H "Content-Type: application/json" \
  -d '{"question": "What is the most critical vulnerability?"}'
```

### Download PDF Report
```bash
curl -o report.pdf http://localhost:8000/scan/{scan_id}/report
```

---

## 📁 Project Structure

```
FUSIONX/
├── app/
│   ├── __init__.py        # Package init
│   ├── main.py            # FastAPI endpoints
│   ├── agent.py           # LangChain ReAct agent
│   ├── tools.py           # Scanner tool implementations
│   ├── engine.py          # Attack chain, risk score, OWASP
│   ├── reporting.py       # PDF report generator
│   ├── config.py          # Configuration & whitelist
│   └── db.py              # Supabase database layer
├── fixtures/              # Fallback JSON for offline mode
├── migrations/            # Supabase SQL migrations
├── scripts/               # Setup automation
├── docker-compose.yml     # Demo target containers
├── requirements.txt       # Pinned Python dependencies
├── .env.example           # Environment variable template
└── README.md
```

---

## 🔐 Safety Constraints

This tool **ONLY** scans safe, local targets:
- ✅ DVWA (Docker, localhost)
- ✅ Metasploitable (Docker, localhost)
- ✅ Whitelisted OWASP GitHub repos
- ❌ All other targets → HTTP 400

---

## 📊 API Endpoints

| Method | Path                      | Description              |
| ------ | ------------------------- | ------------------------ |
| GET    | `/health`                 | Health check             |
| POST   | `/scan`                   | Start new scan           |
| GET    | `/scan/{id}/status`       | Live scan status         |
| GET    | `/scan/{id}/dashboard`    | Full dashboard data      |
| GET    | `/scan/{id}/chain`        | Attack chain graph       |
| POST   | `/scan/{id}/chat`         | RAG-powered Q&A          |
| GET    | `/scan/{id}/report`       | Download PDF report      |

---

**Built for hackathon demo purposes only. Not a production security tool.**
