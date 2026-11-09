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

if ! command -v curl >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q ca-certificates curl python3 coreutils
fi
for cmd in curl python3 sha256sum stat awk; do command -v "$cmd" >/dev/null 2>&1 || fail "$cmd is required"; done

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
python3 - "$TMP/release.manifest" "$TMP/release.manifest.sig.b64" <<'PY_VERIFY' \
    || fail "release signature is invalid"
import base64, hashlib, sys
q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
def inv(x): return pow(x, q - 2, q)
d = -121665 * inv(121666) % q
I = pow(2, (q - 1) // 4, q)
def xrecover(y):
    xx = (y*y - 1) * inv(d*y*y + 1) % q
    x = pow(xx, (q + 3) // 8, q)
    if (x*x - xx) % q: x = x * I % q
    if x & 1: x = q - x
    return x
By = 4 * inv(5) % q
B = (xrecover(By), By)
def edwards(P, Q):
    x1,y1=P; x2,y2=Q
    return ((x1*y2+x2*y1)*inv(1+d*x1*x2*y1*y2)%q,
            (y1*y2+x1*x2)*inv(1-d*x1*x2*y1*y2)%q)
def scalarmult(P, e):
    if e == 0: return (0,1)
    Q = scalarmult(P, e//2); Q = edwards(Q,Q)
    return edwards(Q,P) if e & 1 else Q
def decodepoint(s):
    if len(s) != 32: raise ValueError()
    y = int.from_bytes(s, 'little') & ((1<<255)-1)
    if y >= q: raise ValueError()
    x = xrecover(y)
    if (x & 1) != (s[31] >> 7): x = q-x
    if (-x*x + y*y - 1 - d*x*x*y*y) % q: raise ValueError()
    return (x,y)
def hint(m): return int.from_bytes(hashlib.sha512(m).digest(), 'little')
try:
    pub = bytes.fromhex('6bb37a50dee0ec3c4864aab6b9b84e2107aacc6958c520c1f212ae9d58ea8802')
    msg = open(sys.argv[1], 'rb').read()
    sig = base64.b64decode(open(sys.argv[2], 'rb').read().strip(), validate=True)
    if len(sig) != 64: raise ValueError()
    R=decodepoint(sig[:32]); A=decodepoint(pub); S=int.from_bytes(sig[32:], 'little')
    if S >= L: raise ValueError()
    left=scalarmult(B,S); right=edwards(R,scalarmult(A,hint(sig[:32]+pub+msg)))
    if left != right: raise ValueError()
except Exception:
    sys.exit(1)
PY_VERIFY

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
