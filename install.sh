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
EXPECTED_SHA256="25832915408acb40efc5175366364d209ea60cb850c4e0d75c6d1d00a19952dd"

case "$(uname -m)" in
    x86_64|amd64) ;;
    *)
        echo "Error: this encrypted installer currently supports x86_64/amd64 only." >&2
        exit 1
        ;;
esac

echo "[*] Downloading Dajohn panel..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "$DEST"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$DEST" "$URL"
else
    echo "Error: need curl or wget" >&2
    exit 1
fi
ACTUAL_SHA256=$(sha256sum "$DEST" | awk '{print $1}')
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    rm -f -- "$DEST"
    echo "Error: downloaded installer checksum mismatch; file removed." >&2
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
