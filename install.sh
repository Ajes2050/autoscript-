#!/bin/bash
# Dajohn panel installer — pulls the license-gated binary from GitHub and runs it.
#   apt update && apt install -y wget && wget -qO install.sh https://raw.githubusercontent.com/Ajes2050/autoscript-/main/install.sh && chmod +x install.sh && ./install.sh
# The binary itself enforces a node-locked license (REQ code -> activation key).

set -e

# --- must be root (parts write /etc, run systemctl, etc.) ---
if [ "$(id -u)" != "0" ]; then
    echo "This installer must run as root. Try: sudo ./install.sh" >&2
    exit 1
fi

# --- fetch the binary (curl preferred, fall back to wget) ---
BIN="dajohn-public"
URL="https://raw.githubusercontent.com/Ajes2050/autoscript-/main/dajohn-public"
DEST="/root/dajohn-public"

echo "[*] Downloading Dajohn panel..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "$DEST"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$DEST" "$URL"
else
    echo "Error: need curl or wget" >&2
    exit 1
fi
chmod +x "$DEST"

echo "[*] Running Dajohn installer..."
echo "    (if activation is required, you'll see a REQ-... code —"
echo "     send it to the owner, paste the DAJOHN-... key they return)"
# The activation key is read from the terminal, not stdin, so this works
# even when install.sh itself was piped in (curl ... | bash).
exec < /dev/tty
"$DEST"
