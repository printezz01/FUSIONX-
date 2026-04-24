#!/usr/bin/env bash
# ═══════════════════════════════════════════════════
# Sentinel AI — System Setup Script
# Run once to install all external tool dependencies
# ═══════════════════════════════════════════════════
set -euo pipefail

echo "╔═══════════════════════════════════════════╗"
echo "║   Sentinel AI — Environment Setup         ║"
echo "╚═══════════════════════════════════════════╝"

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "[*] Detected Linux"
    sudo apt-get update -qq

    # nmap
    echo "[+] Installing nmap..."
    sudo apt-get install -y -qq nmap

    # nikto
    echo "[+] Installing nikto..."
    sudo apt-get install -y -qq nikto

    # git (usually pre-installed)
    echo "[+] Installing git..."
    sudo apt-get install -y -qq git

    # pip tools
    echo "[+] Installing bandit..."
    pip install bandit==1.7.10 --quiet

    echo "[+] Installing semgrep..."
    pip install semgrep==1.96.0 --quiet

    echo "[+] Installing trufflehog..."
    # trufflehog is a Go binary — install via pip wrapper or download
    pip install trufflehog==2.2.1 --quiet 2>/dev/null || {
        echo "[!] pip trufflehog failed — trying binary install..."
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
    }

elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "[*] Detected macOS"

    # Homebrew installs
    brew install nmap nikto git 2>/dev/null || true

    pip install bandit==1.7.10 --quiet
    pip install semgrep==1.96.0 --quiet
    brew install trufflehog 2>/dev/null || pip install trufflehog==2.2.1 --quiet

else
    echo "[!] Unsupported OS: $OSTYPE"
    echo "[!] Please install nmap, nikto, git, bandit, semgrep, trufflehog manually."
fi

# Download semgrep rule packs for offline use
echo "[+] Downloading semgrep rule packs..."
mkdir -p ./semgrep-rules
semgrep --config=auto --generate-config 2>/dev/null || true
# Download common rule packs
semgrep --config "p/python" --dry-run --quiet 2>/dev/null || true
semgrep --config "p/javascript" --dry-run --quiet 2>/dev/null || true
semgrep --config "p/security-audit" --dry-run --quiet 2>/dev/null || true

# Install Python dependencies
echo "[+] Installing Python dependencies..."
pip install -r requirements.txt --quiet

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║   Setup Complete!                         ║"
echo "║   Next: cp .env.example .env              ║"
echo "║         Fill in your API keys             ║"
echo "║         docker-compose up -d              ║"
echo "║         uvicorn app.main:app --reload     ║"
echo "╚═══════════════════════════════════════════╝"
