#!/usr/bin/env bash
# access.sh installer
set -euo pipefail

BANNER="
  ╔═╗╔═╗╔═╗╔═╗╔═╗╔═╗
  ╠═╣║  ║  ║╣ ╚═╗╚═╗
  ╩ ╩╚═╝╚═╝╚═╝╚═╝╚═╝  Access Discovery
  install.sh
"
echo "$BANNER"

if command -v apt-get &>/dev/null; then
    echo "[*] Detected apt (Debian/Ubuntu/Kali/Parrot)"
    sudo apt-get update -qq
    sudo apt-get install -y curl jq git python3 python3-pip nmap golang 2>/dev/null || true
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true
    sudo apt-get install -y ffuf gobuster feroxbuster sqlmap hydra 2>/dev/null || true
elif command -v pacman &>/dev/null; then
    echo "[*] Detected pacman (Arch/BlackArch)"
    sudo pacman -Sy --noconfirm curl jq git python go nmap 2>/dev/null || true
    sudo pacman -Sy --noconfirm httpx nuclei ffuf gobuster sqlmap hydra 2>/dev/null || true
elif command -v dnf &>/dev/null; then
    echo "[*] Detected dnf (Fedora/RHEL)"
    sudo dnf install -y curl jq git python3 nmap golang 2>/dev/null || true
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true
elif command -v brew &>/dev/null; then
    echo "[*] Detected Homebrew (macOS)"
    brew install curl jq git python3 nmap go 2>/dev/null || true
    brew tap projectdiscovery/tap && brew install httpx nuclei 2>/dev/null || true
    brew install ffuf sqlmap 2>/dev/null || true
else
    echo "[!] Unknown package manager. Install manually: curl jq git python3 nmap"
fi

INSTALL_DIR="/usr/local/share/access"
BIN="/usr/local/bin/access"
sudo mkdir -p "$INSTALL_DIR"
sudo cp -r . "$INSTALL_DIR/"
sudo ln -sf "$INSTALL_DIR/access.sh" "$BIN"
sudo chmod +x "$BIN" "$INSTALL_DIR/access.sh"

echo ""
echo "[+] Installed! Run with: access --help"
