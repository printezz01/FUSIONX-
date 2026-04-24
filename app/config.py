"""
Sentinel AI — Configuration Module
Loads environment variables and defines application settings.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")

# ─── API Keys ────────────────────────────────────────────────
ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
VOYAGE_API_KEY: str = os.getenv("VOYAGE_API_KEY", "")
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")

# ─── Supabase ────────────────────────────────────────────────
SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY: str = os.getenv("SUPABASE_SERVICE_KEY", "")

# ─── LLM Models ──────────────────────────────────────────────
PRIMARY_MODEL: str = "claude-sonnet-4-5"
FALLBACK_MODEL: str = "claude-3-5-sonnet-latest"

# ─── Embedding Config ────────────────────────────────────────
EMBEDDING_DIM: int = 1536  # dimension for pgvector column

# ─── Paths ───────────────────────────────────────────────────
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
FIXTURES_DIR: Path = PROJECT_ROOT / "fixtures"
TEMPCLONES_DIR: Path = PROJECT_ROOT / "tempclones"
NVD_CACHE_PATH: Path = PROJECT_ROOT / "nvd_cache.sqlite"

# ─── Timeouts ────────────────────────────────────────────────
NMAP_TIMEOUT: int = 60   # seconds
NIKTO_TIMEOUT: int = 90  # seconds

# ─── Whitelist (HARD CONSTRAINT) ─────────────────────────────
ALLOWED_IP_RANGES: list[str] = [
    "127.0.0.1",
    "localhost",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

ALLOWED_URLS: list[str] = [
    "http://localhost",
    "http://127.0.0.1",
    "https://localhost",
    "https://127.0.0.1",
]

ALLOWED_GITHUB_REPOS: list[str] = [
    "https://github.com/OWASP/NodeGoat",
    "https://github.com/OWASP/PyGoat",
    "https://github.com/OWASP/railsgoat",
]

# ─── CORS Origins ────────────────────────────────────────────
CORS_ORIGINS: list[str] = [
    "http://localhost:5173",
    "http://localhost:3000",
]
