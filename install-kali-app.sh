#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# VulnTriage — one-shot desktop-app installer for Kali / Debian.
#
# Sets up a Python venv (with access to the system GTK/WebKit bindings that
# pywebview needs), installs dependencies, ensures the React UI is built, and
# registers "VulnTriage" in the applications menu so it launches like ZAP.
#
#   ./install-kali-app.sh
#
# Then find "VulnTriage" in your menu, or run ./bin/vulntriage-app
# Default login: admin / admin
# ─────────────────────────────────────────────────────────────────────────────
set -e

ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
echo "[*] Project root: $ROOT"

# 1. System packages: venv + GTK/WebKit2 bindings for pywebview.
echo "[*] Installing system packages (sudo password may be required)…"
sudo apt update
sudo apt install -y \
    python3-venv python3-pip \
    python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1 \
  || sudo apt install -y \
    python3-venv python3-pip \
    python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.0
# (newer Kali ships WebKit2 4.1; the fallback line covers older 4.0.)

# 2. Virtualenv WITH access to system gi/GTK (pywebview can't pip-install those).
echo "[*] Creating virtualenv (--system-site-packages)…"
python3 -m venv "$ROOT/backend/.venv" --system-site-packages
# shellcheck disable=SC1091
source "$ROOT/backend/.venv/bin/activate"
pip install --upgrade pip
pip install -r "$ROOT/backend/requirements.txt"
pip install -r "$ROOT/backend/requirements-desktop.txt"

# 3. Ensure the frontend is built.
if [ ! -d "$ROOT/frontend/dist" ]; then
  echo "[!] frontend/dist not found."
  if command -v npm >/dev/null 2>&1; then
    echo "[*] Building the frontend with npm…"
    ( cd "$ROOT/frontend" && npm install && npm run build )
  else
    echo "[X] No frontend/dist and npm is not installed."
    echo "    Either build it on your dev machine (cd frontend && npm run build)"
    echo "    and include frontend/dist in the transfer, or:"
    echo "        sudo apt install -y nodejs npm   &&   ./install-kali-app.sh"
    exit 1
  fi
fi

# 4. Make launchers executable.
echo "[*] Making launchers executable…"
chmod +x "$ROOT/bin/vulntriage-app" 2>/dev/null || true
chmod +x "$ROOT/bin/vulntriage"     2>/dev/null || true

# 5. Register the applications-menu entry with absolute paths.
echo "[*] Registering the applications-menu entry…"
APPS="$HOME/.local/share/applications"
mkdir -p "$APPS"
cat > "$APPS/vulntriage.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=VulnTriage
GenericName=Vulnerability Triage
Comment=AI-Assisted Vulnerability Triage and Confirmation System
Exec=$ROOT/bin/vulntriage-app
Icon=$ROOT/assets/vulntriage.svg
Terminal=false
Categories=Security;Network;Utility;
StartupNotify=true
EOF
chmod +x "$APPS/vulntriage.desktop"
update-desktop-database "$APPS" 2>/dev/null || true

echo
echo "[✓] Installed."
echo "    • Launch from the Kali menu: search 'VulnTriage'"
echo "    • Or run now:                $ROOT/bin/vulntriage-app"
echo "    • Default login:             admin / admin"
echo "    (If the menu icon doesn't appear immediately, log out/in or run:"
echo "     update-desktop-database ~/.local/share/applications)"
