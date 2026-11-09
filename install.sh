#!/bin/bash
# Signed Dajohn bootstrap installer for Debian/Ubuntu AMD64 and ARM64.
set -euo pipefail
umask 077

LATEST_REF_URL=https://raw.githubusercontent.com/Ajes2050/autoscript-/main/release.latest
DEST=/root/dajohn-public
TMP=""

cleanup(){
    local rc=$?
    trap - EXIT HUP INT TERM
    case "$TMP" in /tmp/dajohn-bootstrap.[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9])
        [ ! -d "$TMP" ] || rm -rf -- "$TMP" ;;
    esac
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
fail(){ echo "Error: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "this installer must run as root"
[ -r /etc/os-release ] || fail "/etc/os-release is missing"
. /etc/os-release
case "${ID:-}" in
  ubuntu) dpkg --compare-versions "${VERSION_ID:-0}" ge 20.04 || fail "Ubuntu 20.04 or newer is required" ;;
  debian) dpkg --compare-versions "${VERSION_ID:-0}" ge 11 || fail "Debian 11 or newer is required" ;;
  *) fail "supported systems are Ubuntu 20.04+ and Debian 11+ (found ${ID:-unknown})" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) fail "supported architectures are amd64 and arm64" ;;
esac

if ! command -v curl >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q ca-certificates curl openssl coreutils
fi
for cmd in curl openssl base64 sha256sum stat awk; do command -v "$cmd" >/dev/null 2>&1 || fail "$cmd is required"; done

TMP=$(mktemp -d /tmp/dajohn-bootstrap.XXXXXX) || fail "cannot create temporary directory"
chmod 700 "$TMP"
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
    -H 'Cache-Control: no-cache' -o "$TMP/release.latest" "$LATEST_REF_URL?ts=$(date +%s)"
RELEASE_REF=$(tr -d '\r\n' < "$TMP/release.latest")
[[ "$RELEASE_REF" =~ ^v[0-9]+([.][0-9]+){1,3}$ ]] || fail "latest release reference is malformed"
RELEASE_BASE="https://raw.githubusercontent.com/Ajes2050/autoscript-/$RELEASE_REF"
MANIFEST_URL="$RELEASE_BASE/release.manifest"
SIGNATURE_URL="$RELEASE_BASE/release.manifest.sig"
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 15 --max-time 120 -o "$TMP/release.manifest" "$MANIFEST_URL"
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 15 --max-time 120 -o "$TMP/release.manifest.sig.b64" "$SIGNATURE_URL"
cat > "$TMP/release-public.pem" <<'EOF_PUB'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAa7N6UN7g7DxIZKq2ubhOIQeqzGlYxSDB8hKunVjqiAI=
-----END PUBLIC KEY-----
EOF_PUB
base64 -d "$TMP/release.manifest.sig.b64" > "$TMP/release.sig" 2>/dev/null || fail "release signature encoding is invalid"
[ "$(stat -c '%s' "$TMP/release.sig")" = 64 ] || fail "release signature length is invalid"
openssl pkeyutl -verify -pubin -inkey "$TMP/release-public.pem" -rawin \
    -in "$TMP/release.manifest" -sigfile "$TMP/release.sig" >/dev/null 2>&1 || fail "release signature is invalid"

manifest_value(){
    local key="$1" path="$2" count value
    count=$(awk -F= -v k="$key" '$1==k{n++} END{print n+0}' "$path")
    [ "$count" = 1 ] || return 1
    value=$(awk -F= -v k="$key" '$1==k{sub(/^[^=]*=/,""); print; exit}' "$path")
    [ -n "$value" ] || return 1
    printf '%s\n' "$value"
}

[ "$(manifest_value format "$TMP/release.manifest")" = 1 ] || fail "unsupported release manifest"
VERSION=$(manifest_value version "$TMP/release.manifest") || fail "release version is missing"
URL=$(manifest_value "${ARCH}_url" "$TMP/release.manifest") || fail "release URL for $ARCH is missing"
EXPECTED_SHA256=$(manifest_value "${ARCH}_sha256" "$TMP/release.manifest") || fail "release checksum is missing"
EXPECTED_SIZE=$(manifest_value "${ARCH}_size" "$TMP/release.manifest") || fail "release size is missing"
[[ "$VERSION" =~ ^[0-9]+([.][0-9]+){1,3}$ ]] || fail "release version is malformed"
[[ "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail "release checksum is malformed"
[[ "$EXPECTED_SIZE" =~ ^[0-9]+$ ]] || fail "release size is malformed"
[ "$URL" = "$RELEASE_BASE/dajohn-public" ] || [ "$URL" = "$RELEASE_BASE/dajohn-public-arm64" ] \
    || fail "release manifest contains an unapproved URL"

echo "[*] Downloading signed Dajohn $VERSION for $ARCH..."
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 15 --max-time 300 -o "$TMP/dajohn-public" "$URL"
ACTUAL_SHA256=$(sha256sum "$TMP/dajohn-public" | awk '{print $1}')
ACTUAL_SIZE=$(stat -c '%s' "$TMP/dajohn-public")
[ "$ACTUAL_SHA256" = "$EXPECTED_SHA256" ] && [ "$ACTUAL_SIZE" = "$EXPECTED_SIZE" ] \
    || fail "downloaded release checksum or size mismatch"
if [ "${DAJOHN_BOOTSTRAP_VERIFY_ONLY:-0}" = 1 ]; then
    echo "[OK] Signed Dajohn $VERSION for $ARCH verified successfully."
    exit 0
fi
command -v systemctl >/dev/null 2>&1 || fail "systemd/systemctl is required for installation"
install -o root -g root -m 700 "$TMP/dajohn-public" "$DEST"

echo "[*] Running Dajohn installer..."
echo "    If activation is required, send the REQ code to the owner and paste the returned key."
exec < /dev/tty
"$DEST"
install -d -o root -g root -m 700 /etc/dajohn/core
printf '%s\n' "$VERSION" > /etc/dajohn/core/panel_version
chown root:root /etc/dajohn/core/panel_version
chmod 600 /etc/dajohn/core/panel_version
