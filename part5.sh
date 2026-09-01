#!/bin/bash
# ==========================================================
# ITZDAJOHN v5.4 TITAN EDITION - PART 5: SLOWDNS-V2RAY & UDP
# ==========================================================
# Features: 1. SlowDNS -> dajohn-mux (SSH *and* V2Ray/VMess-WS in one DNS tunnel)
#           2. (removed - the Reality-on-443 split; see section 2 for why)
#           3. Hysteria 2 salamander obfs + Reality dest/shortIds hardening
#           4. UDP-Custom (ZIVPN-style) standalone UDP protocol
#
# Safe to re-run. Everything here is idempotent.
#
# RE-RUN ORDER (same trap as part 4): part 2 regenerates the Nginx config,
# dajohn-iptables and the Hysteria/Xray configs; part 3 regenerates
# /usr/local/bin/menu. Both clobber what part 5 patches. ALWAYS re-run part 4
# and then part 5 after re-running part 2 or 3.
#
# Everything part 5 owns lives in its own files where possible:
#   /usr/local/bin/dajohn-slowdns-mode     SlowDNS target switcher
#   /usr/local/bin/dajohn-nginx-restore    rewrite a broken Nginx config
#   /usr/local/bin/dajohn-udp-build        UDP-Custom config from the user DB
#   /usr/local/bin/dajohn-udp-expire       UDP-Custom expiry sweep
#   /etc/dajohn/data/udp_users.txt         UDP-Custom user database
#   /usr/local/bin/dajohn-mux              the DNS-tunnel SSH/HTTP muxer
# ==========================================================

BRed='\033[1;31m'; BGreen='\033[1;32m'; BYellow='\033[1;33m'; BCyan='\033[1;36m'; BPurple='\033[1;35m'; NC='\033[0m'
source /etc/dajohn/core/env.conf 2>/dev/null

if [ "${EUID}" -ne 0 ]; then
    echo -e "${BRed}[CRITICAL ERROR] You must run this script as root!${NC}"
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
WARNINGS=""
warn(){ echo -e "${BYellow}[!] $1${NC}"; WARNINGS="${WARNINGS}\n  - $1"; }

# Parts 1-3 must have run: we patch their files and reuse their helpers.
if [ ! -d /etc/dajohn/core ]; then
    echo -e "${BRed}[ERROR] /etc/dajohn/core missing - run parts 1-3 first.${NC}"
    exit 1
fi
if [ -z "$DOMAIN" ]; then
    echo -e "${BRed}[ERROR] DOMAIN is empty in /etc/dajohn/core/env.conf.${NC}"
    exit 1
fi
mkdir -p /etc/dajohn/data /etc/dajohn/core

command -v jq >/dev/null 2>&1 || apt-get install -y -q jq >/dev/null 2>&1
if ! command -v jq >/dev/null 2>&1; then
    echo -e "${BRed}[ERROR] jq is required and could not be installed.${NC}"
    exit 1
fi

# Same arch gate as part 4 - udp-custom ships per-arch binaries and a wrong
# guess only surfaces later as a bare "Exec format error" from systemd.
case "$(uname -m)" in
    x86_64|amd64)  DEB_ARCH=amd64;  RAW_ARCH=x86_64;  ELF_MACH=3e00 ;;
    aarch64|arm64) DEB_ARCH=arm64;  RAW_ARCH=aarch64; ELF_MACH=b700 ;;
    *) echo -e "${BRed}[ERROR] Unsupported architecture: $(uname -m)${NC}"; exit 1 ;;
esac

XCFG=/usr/local/etc/xray/config.json

clear
echo -e "${BCyan}======================================================${NC}"
echo -e "${BPurple}   PART 5: SLOWDNS-V2RAY, 443 REALITY & UDP CUSTOM    ${NC}"
echo -e "${BCyan}======================================================${NC}"
echo -e "  Domain       : ${BCyan}${DOMAIN}${NC}"
echo -e "  Nameserver   : ${BCyan}${NS_DOMAIN:-NOT SET}${NC}"
echo -e "  Architecture : ${BCyan}${RAW_ARCH}${NC}"

# ==========================================================================
# 1. SLOWDNS -> DAJOHN-MUX  (SSH *and* V2Ray/VMess-WS in one DNS tunnel)
# ==========================================================================
# Part 2 hardcodes dnstt's target as 127.0.0.1:22, so a DNS tunnel can only
# ever reach SSH. Only one process can bind UDP 53, so a second dnstt for
# V2Ray is not an option. Instead dnstt now hands off to dajohn-mux, which peeks
# the first bytes of each stream and routes it:
#
#   UDP 53 --dnstt--> 127.0.0.1:2222 --mux--+-- "SSH-" ------> 127.0.0.1:109
#                                           |                  (Dropbear)
#                                           +-- HTTP -------> 127.0.0.1:80
#                                                              (Nginx, plain HTTP)
#
# The non-SSH branch MUST go to Nginx :80, not to 8880. 8880 is part 2's
# ws-proxy.py, which hardcodes connect(('127.0.0.1',109)) and forwards
# everything to Dropbear no matter what path was requested - so it can never
# reach Xray. Nginx is what does path routing:
#     /api/vmess -> 10002 (Xray VMess-WS)   <- this is the V2Ray path
#     /vless     -> 10000 (Xray VLESS-WS)
#     /          -> 8880  (ws-proxy -> Dropbear, i.e. SSH-over-WS still works)
# Plain HTTP, not HTTPS: the DNS tunnel is already the transport, so clients
# set TLS=none and skip a redundant handshake inside it.
#
# Existing SSH-over-SlowDNS clients keep working untouched, and the SlowDNS
# public key does not change, so nobody has to re-import anything.
#
# 2222 not 22: the mux must not point at the real sshd port or a client that
# fails the SSH probe gets bounced into sshd anyway. 109 is Dropbear, which
# is what part 2 already serves SSH tunnels on.
echo -e "\n${BYellow}[*] Wiring SlowDNS through dajohn-mux (SSH + V2Ray)...${NC}"

if [ ! -x /usr/local/bin/dnstt-server ]; then
    warn "dnstt-server missing - SlowDNS was never built. Re-run part 2; skipping section 1."
elif [ -z "$NS_DOMAIN" ]; then
    warn "NS_DOMAIN is empty in env.conf - skipping the SlowDNS mux (set it with menu option 24)."
else

# WHY NOT sslh: its accepted flags and its default config path differ between
# builds. Part 3's own comment notes /etc/sslh/sslh.cfg is "the path sslh reads
# by default on current builds", so -F is not reliably honoured - the binary can
# fall back to that shared file (which part 3 owns for the FTP muxer, or which
# ships stock binding 443) and then die on a bind conflict whose message points
# nowhere near the real cause. That is exactly what killed sslh-slowdns.
#
# dajohn-mux does this one job in ~90 lines of Python: no config file to
# inherit, no version drift, and part 2 already proves python3 + a socket
# forwarder work on this box (ws-proxy.py). Routing is unit-tested.
echo -e "${BYellow}[*] Installing dajohn-mux (replaces sslh for the DNS tunnel)...${NC}"

# Retire the sslh-based unit if an earlier part 5 run installed one, or two
# services race for 2222 and the loser restarts forever under Restart=always.
if systemctl cat sslh-slowdns >/dev/null 2>&1; then
    systemctl disable --now sslh-slowdns >/dev/null 2>&1
    rm -f /etc/systemd/system/sslh-slowdns.service /etc/sslh/sslh-slowdns.cfg
    systemctl daemon-reload
    echo -e "${BYellow}[*] Retired the old sslh-slowdns unit (dajohn-mux serves the tunnel now).${NC}"
fi

command -v python3 >/dev/null 2>&1 || apt-get install -y -q python3 >/dev/null 2>&1
if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 unavailable - SlowDNS stays SSH-only."
else

cat << 'EOF_MUX' > /usr/local/bin/dajohn-mux
#!/usr/bin/env python3
# dajohn-mux : minimal SSH / HTTP multiplexer for the SlowDNS tunnel.
#
# dnstt-server hands every tunnelled stream to 127.0.0.1:2222. The first bytes
# are peeked WITHOUT being consumed (MSG_PEEK), so the stream is passed through
# byte-for-byte:
#   "SSH-..."      -> Dropbear 127.0.0.1:109
#   HTTP request   -> Nginx    127.0.0.1:80  (path-routes to Xray VMess-WS)
#   nothing (idle) -> Dropbear (some SSH clients wait for the server banner;
#                              this mirrors sslh's --on-timeout ssh)
#   anything else  -> Nginx    (catch-all, like sslh's 'anyprot')
import os, socket, threading, select, time

LISTEN_HOST = os.environ.get("DAJOHN_MUX_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("DAJOHN_MUX_PORT", "2222"))
SSH_ADDR = ("127.0.0.1", int(os.environ.get("DAJOHN_MUX_SSH_PORT", "109")))
HTTP_ADDR = ("127.0.0.1", int(os.environ.get("DAJOHN_MUX_HTTP_PORT", "80")))
# How long to wait for the client's first byte before giving up entirely.
# Generous on purpose: DNS-tunnel round trips are slow and variable.
PEEK_TIMEOUT = float(os.environ.get("DAJOHN_MUX_TIMEOUT", "30"))
# How long a completely silent client waits before being handed to SSH.
#
# This CANNOT be short. A silent SSH client and a slow V2Ray client whose first
# bytes are still crossing the DNS tunnel look identical from here - the only
# difference is time. Setting this to ~2s misroutes every tunnelled WS client to
# Dropbear, which is the same hang as before, just from the other direction.
# 12s is comfortably longer than a DNS-tunnel round trip while still giving
# banner-first SSH clients a usable connection.
SSH_FALLBACK = float(os.environ.get("DAJOHN_MUX_SSH_FALLBACK", "12"))

# Decision log. This exists because the server side can pass every synthetic
# test while a real VPN app still fails: the app sends something the tests did
# not. Logging what actually arrived, and where it was routed, turns that from
# guesswork into a one-line answer. Set DAJOHN_MUX_LOG= (empty) to disable.
LOG_PATH = os.environ.get("DAJOHN_MUX_LOG", "/var/log/dajohn/mux.log")
LOG_MAX = 2000000


def logline(msg):
    if not LOG_PATH:
        return
    try:
        if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > LOG_MAX:
            os.replace(LOG_PATH, LOG_PATH + ".1")
        with open(LOG_PATH, "a") as fh:
            fh.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")
    except OSError:
        pass


def preview(data):
    """Printable rendering of the first bytes, safe for a log file."""
    if not data:
        return "<no bytes>"
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:8])


def request_line(data):
    """'GET /path' plus the Host header, for HTTP requests.

    The path is the whole point of logging: a VPN app configured for /wsvl on
    someone else's server will show up here asking for a path this Nginx does
    not serve, which is otherwise invisible - the mux routes it to Nginx either
    way and Nginx quietly answers 404.
    """
    try:
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
        lines = head.split("\r\n")
        req = lines[0][:80] if lines else "?"
        host = ""
        for ln in lines[1:]:
            if ln.lower().startswith("host:"):
                host = " host=" + ln.split(":", 1)[1].strip()[:60]
                break
        up = " [ws-upgrade]" if "upgrade: websocket" in head.lower() else ""
        return "%r%s%s" % (req, host, up)
    except (IndexError, UnicodeError):
        return preview(data)

HTTP_VERBS = (b"GET", b"POST", b"PUT", b"HEAD", b"OPTI", b"CONN",
              b"DELE", b"PATC", b"TRAC")


def pick_backend(sock):
    """Peek at the first bytes and choose a backend. Never consumes data.

    Over a DNS tunnel the backend connection opens as soon as the stream does,
    but the client's first bytes need a full tunnel round trip - frequently
    several seconds, and highly variable. A short fixed timeout therefore
    misroutes real V2Ray clients to Dropbear: the WS request lands on SSH,
    Dropbear answers with its banner and waits for SSH data, nothing ever
    closes, and the client hangs until it is killed. That is the exact
    'VMess-WS returned nothing' failure this replaced.

    So the wait is long (PEEK_TIMEOUT, default 30s) but it does NOT cost a
    silent SSH client anything: as soon as ANY byte arrives the decision is
    made, and a client that sends nothing at all is handed to SSH after
    SSH_FALLBACK seconds - which is what a real SSH client wanting the server
    banner first needs anyway.
    """
    deadline = time.monotonic() + PEEK_TIMEOUT
    ssh_deadline = time.monotonic() + SSH_FALLBACK
    t0 = time.monotonic()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            logline("no bytes within %.0fs -> SSH" % PEEK_TIMEOUT)
            return SSH_ADDR
        try:
            ready, _, _ = select.select([sock], [], [], min(0.25, remaining))
        except OSError:
            return SSH_ADDR
        if ready:
            break
        # Nothing yet. A genuinely silent client is waiting for the SSH banner,
        # so hand it to Dropbear rather than making it wait out the full window.
        if time.monotonic() >= ssh_deadline:
            logline("silent %.1fs -> SSH (fallback)" % (time.monotonic() - t0))
            return SSH_ADDR

    waited = time.monotonic() - t0
    try:
        # Peek generously, not 8 bytes: the decision only needs the first few,
        # but the request line is what tells you whether a VPN app asked for the
        # path this server actually serves. "GET /api" alone cannot distinguish
        # /api/vmess from a client asking for something that does not exist.
        data = sock.recv(512, socket.MSG_PEEK)
    except OSError:
        return SSH_ADDR
    if not data:
        # EOF: the peer hung up before sending anything. Returning SSH_ADDR here
        # was misleading in two ways - the log implied a routing decision that
        # never mattered, and handle() then opened a pointless Dropbear
        # connection for a client that is already gone. None means "just close".
        logline("peer closed before sending anything (no backend used)")
        return None
    if data.startswith(b"SSH-"):
        logline("first=%r after %.1fs -> SSH" % (preview(data), waited))
        return SSH_ADDR
    if data[:4].upper().startswith(HTTP_VERBS):
        logline("%s after %.1fs -> HTTP" % (request_line(data), waited))
        return HTTP_ADDR
    # Anything unrecognised still goes to Nginx, but it is logged loudly: this
    # is where a VPN app sending a custom payload or raw TLS shows up.
    logline("first=%r after %.1fs -> HTTP (UNRECOGNISED - not SSH, not HTTP verb)"
            % (preview(data), waited))
    return HTTP_ADDR


def pump(src, dst):
    try:
        while True:
            buf = src.recv(16384)
            if not buf:
                break
            dst.sendall(buf)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def handle(client):
    upstream = None
    try:
        backend = pick_backend(client)
        if backend is None:          # peer already gone; nothing to forward
            try:
                client.close()
            except OSError:
                pass
            return
        upstream = socket.create_connection(backend, timeout=10)
        upstream.settimeout(None)
        client.settimeout(None)
        threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
        pump(upstream, client)
    except OSError:
        for s in (client, upstream):
            if s:
                try:
                    s.close()
                except OSError:
                    pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(512)
    print(f"dajohn-mux listening on {LISTEN_HOST}:{LISTEN_PORT} "
          f"-> ssh {SSH_ADDR[1]} / http {HTTP_ADDR[1]}", flush=True)
    while True:
        try:
            client, _ = srv.accept()
        except OSError:
            continue
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
EOF_MUX
chmod +x /usr/local/bin/dajohn-mux
# /var/log/dajohn already exists from part 1, but create it defensively: the mux
# logs its routing decisions there and a missing dir would silently disable that.
mkdir -p /var/log/dajohn
touch /var/log/dajohn/mux.log 2>/dev/null

# Hardened like slowdns.service: StartLimitIntervalSec=0 so a brief crash-loop
# (2222 contention, a transient python hiccup on a burst) can't trip systemd's
# 5-in-10s limiter to failed(start-limit-hit) - which would make Restart=always
# give up and strand the whole DNS tunnel in SSH-only mode with no recovery.
# LimitNOFILE=infinity: the mux opens one fd per tunneled session, and the 1024
# default starved dnstt the same way. dajohn-watchdog also now covers this unit.
cat > /etc/systemd/system/dajohn-mux.service <<'EOF_MUXSVC'
[Unit]
Description=Itzdajohn SSH/WS multiplexer for the SlowDNS tunnel
After=network.target dropbear.service nginx.service
StartLimitIntervalSec=0
[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/dajohn-mux
Restart=always
RestartSec=3
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF_MUXSVC

systemctl daemon-reload
systemctl enable dajohn-mux >/dev/null 2>&1
systemctl restart dajohn-mux >/dev/null 2>&1
sleep 2

# Report the truth. An earlier version silenced this, so a dead mux looked like
# a clean install and only surfaced as "STOPPED" in the summary.
if ss -tln 2>/dev/null | grep -qE '[:.]2222([^0-9]|$)'; then
    echo -e "${BGreen}[ OK ] dajohn-mux listening on 127.0.0.1:2222.${NC}"
else
    warn "dajohn-mux did not bind 2222 - SlowDNS will be left in SSH-only mode."
    echo -e "${BYellow}      $(journalctl -u dajohn-mux -n 3 --no-pager 2>/dev/null | tail -n 2)${NC}"
fi
fi

# ------------------------------------------------------------------
# dajohn-slowdns-mode : switch what the DNS tunnel hands off to.
#   mux  (default) SSH + WS + TLS via dajohn-mux -> 127.0.0.1:2222
#   ssh            part 2's original behaviour   -> 127.0.0.1:22
#   ws             straight to Nginx plain HTTP  -> 127.0.0.1:80
#   ssl            straight to Nginx TLS         -> 127.0.0.1:443
# The unit is rewritten rather than edited so the mode is always exactly one
# of the four and never a half-applied sed.
#
# mux already handles TLS (part 6 added the 0x16 branch), so 'ssl' is not a new
# capability - it is for clients that ONLY ever speak TLS inside the tunnel and
# should skip protocol detection entirely. Everyone else wants mux.
# ------------------------------------------------------------------
cat << 'EOF_SDMODE' > /usr/local/bin/dajohn-slowdns-mode
#!/bin/bash
G='\033[1;32m'; R='\033[1;31m'; Y='\033[1;33m'; C='\033[1;36m'; N='\033[0m'
source /etc/dajohn/core/env.conf 2>/dev/null
MODE="$1"
STATE=/etc/dajohn/core/slowdns_mode.txt

if [ -z "$NS_DOMAIN" ]; then
    echo -e "${R}[!] NS_DOMAIN is not set in env.conf (menu option 24).${N}"; exit 1
fi
if [ -z "$MODE" ]; then
    echo -e "${C}Current SlowDNS mode:${N} ${G}$(cat "$STATE" 2>/dev/null || echo unknown)${N}"
    echo "Usage: dajohn-slowdns-mode [mux|ssh|ws|ssl]"
    echo "  mux  SSH + WS + TLS, auto-detected   (recommended)"
    echo "  ssh  SSH only"
    echo "  ws   plain HTTP / WS only  (no TLS)"
    echo "  ssl  TLS only              (ssldns clients)"
    exit 0
fi

case "$MODE" in
    mux) TARGET="127.0.0.1:2222"; DESC="SSH + WS + TLS (dajohn-mux)" ;;
    ssh) TARGET="127.0.0.1:22";   DESC="SSH only" ;;
    # :80 = Nginx, which path-routes to Xray. NOT 8880 (ws-proxy is SSH-only).
    ws)  TARGET="127.0.0.1:80";   DESC="V2Ray / WS only (plain HTTP)" ;;
    # :443 = Nginx TLS, which terminates the handshake and then path-routes
    # exactly as :80 does. Detected rather than hardcoded, because part 5's 443
    # split can move that listener to 127.0.0.1:8081 so Reality can hold public
    # 443 - pointing the tunnel at Reality would reject every client with no
    # useful error.
    ssl)
        NGCFG=/etc/nginx/sites-available/default
        if [ -f "$NGCFG" ] && awk '/listen[[:space:]]+127\.0\.0\.1:8081[[:space:]]+ssl/{f=1} END{exit !f}' "$NGCFG" 2>/dev/null; then
            TARGET="127.0.0.1:8081"; DESC="TLS only (Nginx TLS, 443 split active)"
        else
            TARGET="127.0.0.1:443";  DESC="TLS only (Nginx TLS)"
        fi
        ;;
    *)   echo -e "${R}[!] Unknown mode '$MODE'. Use: mux | ssh | ws | ssl${N}"; exit 1 ;;
esac

# mux mode is only safe if 2222 is REALLY accepting connections.
#
# is-active alone is not enough and is what let a broken mux through: with
# Restart=always the unit sits in "activating (auto-restart)" and flickers
# through "active" for an instant on each retry, so a single is-active check
# can win the race against a listener that never binds. The port is the only
# honest signal, so it is polled instead - and a failure leaves the tunnel on
# SSH rather than pointing it at nothing.
if [ "$MODE" = "mux" ]; then
    systemctl start dajohn-mux >/dev/null 2>&1
    UP=0
    for _ in 1 2 3 4 5 6 7 8; do
        if ss -tln 2>/dev/null | grep -qE '[:.]2222([^0-9]|$)'; then UP=1; break; fi
        sleep 1
    done
    if [ "$UP" != "1" ]; then
        echo -e "${R}[!] Nothing is listening on 127.0.0.1:2222 - refusing to point the DNS tunnel at a dead port.${N}"
        echo -e "${Y}    SlowDNS is being left in SSH-only mode so existing users keep working.${N}"
        echo -e "${Y}    Diagnose with: journalctl -u dajohn-mux -n 20${N}"
        # Only fall back if the tunnel is not already serving something valid.
        CUR=$(awk '/ExecStart/{print $NF}' /etc/systemd/system/slowdns.service 2>/dev/null)
        if [ "$CUR" = "127.0.0.1:2222" ]; then
            exec "$0" ssh
        fi
        exit 1
    fi
fi

cat > /etc/systemd/system/slowdns.service <<EOF
[Unit]
Description=SlowDNS Tunnel Server
After=network.target dajohn-mux.service
StartLimitIntervalSec=0
[Service]
Type=simple
User=root
WorkingDirectory=/etc/slowdns
ExecStart=/usr/local/bin/dnstt-server -udp :53 -privkey-file /etc/slowdns/server.key $NS_DOMAIN $TARGET
Restart=always
RestartSec=3
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# Option 34 can give port 53 to Hysteria. If it has, slowdns must stay stopped -
# otherwise both daemons crash-loop fighting over the port and Hysteria links work
# intermittently. Check config.yaml (the file that actually decides), not the service
# state, since both have Restart=always and the loser keeps trying.
if [ -f /etc/hysteria/config.yaml ] && grep -q "^listen: :53" /etc/hysteria/config.yaml 2>/dev/null; then
    echo -e "${Y}[ SKIP ] Hysteria owns port 53 (option 34). SlowDNS stays stopped.${N}"
else
    systemctl restart slowdns >/dev/null 2>&1
fi

echo "$MODE" > "$STATE"
sleep 1
if systemctl is-active --quiet slowdns; then
    echo -e "${G}[ OK ] SlowDNS mode: ${DESC}  ->  ${TARGET}${N}"
elif grep -q "^listen: :53" /etc/hysteria/config.yaml 2>/dev/null; then
    echo -e "${Y}[ OK ] Mode set to: ${DESC}  ->  ${TARGET}${N}"
    echo -e "${Y}       SlowDNS not started (Hysteria holds port 53).${N}"
else
    echo -e "${R}[!] slowdns failed to start. Check: journalctl -u slowdns -n 20${N}"
fi
EOF_SDMODE
chmod +x /usr/local/bin/dajohn-slowdns-mode

/usr/local/bin/dajohn-slowdns-mode mux

# ------------------------------------------------------------------
# dajohn-slowdns-test : prove the chain server-side, hop by hop.
# A DNS tunnel has too many moving parts to debug from the phone alone -
# this isolates which hop is broken before you touch a client.
# ------------------------------------------------------------------
cat << 'EOF_SDTEST' > /usr/local/bin/dajohn-slowdns-test
#!/bin/bash
G='\033[1;32m'; R='\033[1;31m'; Y='\033[1;33m'; C='\033[1;36m'; N='\033[0m'
source /etc/dajohn/core/env.conf 2>/dev/null
PASS=0; FAIL=0
ok(){   echo -e "  ${G}[PASS]${N} $1"; PASS=$((PASS+1)); }
bad(){  echo -e "  ${R}[FAIL]${N} $1"; [ -n "$2" ] && echo -e "         ${Y}$2${N}"; FAIL=$((FAIL+1)); }

echo -e "${C}=========== SLOWDNS + V2RAY SELF TEST ===========${N}"
echo -e "  Domain ${C}${DOMAIN}${N}   NS ${C}${NS_DOMAIN:-unset}${N}   Mode ${C}$(cat /etc/dajohn/core/slowdns_mode.txt 2>/dev/null || echo unknown)${N}"
echo ""

echo -e "${C}-- 1. services --${N}"
for s in slowdns dajohn-mux nginx xray dropbear; do
    systemctl is-active --quiet "$s" 2>/dev/null && ok "$s running" || bad "$s is not running" "journalctl -u $s -n 20"
done

echo -e "\n${C}-- 2. listeners --${N}"
ss -uln 2>/dev/null | grep -qE '[:.]53([^0-9]|$)'   && ok "udp/53 (dnstt) listening"      || bad "udp/53 not listening" "another resolver may hold it: menu option 34"
ss -tln 2>/dev/null | grep -qE '[:.]2222([^0-9]|$)' && ok "tcp/2222 (dajohn-mux) listening" || bad "tcp/2222 not listening" "systemctl status dajohn-mux"
ss -tln 2>/dev/null | grep -qE '[:.]80([^0-9]|$)'   && ok "tcp/80 (nginx) listening"      || bad "tcp/80 not listening"
ss -tln 2>/dev/null | grep -qE '[:.]10002([^0-9]|$)' && ok "tcp/10002 (Xray VMess-WS) listening" || bad "tcp/10002 not listening" "run: dajohn-xray-repair"

echo -e "\n${C}-- 3. dnstt target --${N}"
TGT=$(awk -F' ' '/ExecStart/{print $NF}' /etc/systemd/system/slowdns.service 2>/dev/null)
case "$TGT" in
    127.0.0.1:2222) ok "dnstt -> dajohn-mux ($TGT)" ;;
    127.0.0.1:80)   ok "dnstt -> nginx, plain HTTP only ($TGT)" ;;
    127.0.0.1:443|127.0.0.1:8081)
                    ok "dnstt -> nginx TLS, ssl mode ($TGT)" ;;
    127.0.0.1:22)   bad "dnstt -> sshd only ($TGT)" "V2Ray cannot work: dajohn-slowdns-mode mux" ;;
    *)              bad "unexpected dnstt target: ${TGT:-none}" ;;
esac

echo -e "\n${C}-- 4. mux routing (the part that actually breaks) --${N}"
# Send an SSH banner first, exactly like a real client (RFC 4253: both sides
# send their identification string immediately). This tests the mux's SSH PROBE.
# Do NOT stay silent here: a silent client is deliberately held for
# DAJOHN_MUX_SSH_FALLBACK (12s) before falling through to Dropbear, so a short
# timeout would report a failure that is really just the fallback window.
BAN=$(timeout 20 bash -c 'exec 3<>/dev/tcp/127.0.0.1/2222; printf "SSH-2.0-DajohnSelfTest\r\n" >&3; head -c 20 <&3' 2>/dev/null | tr -d '\0')
case "$BAN" in
    SSH-2.0*) ok "mux SSH branch -> Dropbear ($BAN)" ;;
    *)        bad "mux SSH branch gave no SSH banner" "got: '${BAN:-nothing}'" ;;
esac
# WS branch: read the status line off a raw socket rather than using curl.
# curl is the wrong tool for a 101: the connection stays open after the
# upgrade, so curl blocks until killed and never prints %{http_code} - which
# looked exactly like "no response from the server".
WSREQ='exec 3<>/dev/tcp/127.0.0.1/2222; printf "GET /api/vmess HTTP/1.1\r\nHost: DOMAINHERE\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" >&3; head -c 24 <&3'
WSRESP=$(timeout 20 bash -c "${WSREQ/DOMAINHERE/$DOMAIN}" 2>/dev/null | tr -d '\0')
case "$WSRESP" in
    *101*) ok "mux WS branch -> Xray VMess-WS (HTTP 101 on /api/vmess)" ;;
    SSH-*) bad "the mux sent this HTTP request to Dropbear" "got: '$WSRESP' - raise DAJOHN_MUX_SSH_FALLBACK" ;;
    *)     bad "no WebSocket upgrade on /api/vmess through the mux" "got: '${WSRESP:-nothing}' - check the Nginx /api/vmess location and that xray is up" ;;
esac

echo -e "\n${C}-- 5. accounts / keys --${N}"
[ -s /etc/dajohn/core/slowdns_pub.txt ] && ok "SlowDNS pubkey present" || bad "SlowDNS pubkey missing" "re-run part 2"
NU=$(jq '[.inbounds[]?|select(.tag=="vmess-ws")|.settings.clients[]?]|length' /usr/local/etc/xray/config.json 2>/dev/null)
if [ "${NU:-0}" -gt 0 ] 2>/dev/null; then ok "$NU VMess account(s) exist"
else bad "no VMess accounts" "create one: menu -> 2 -> [20]"; fi

echo ""
echo -e "${C}================================================${N}"
if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${G}All ${PASS} checks passed - the server side is ready.${N}"
    echo -e "  ${Y}Client setup: menu -> 10 -> 84${N}"
else
    echo -e "  ${R}${FAIL} check(s) failed${N}, ${G}${PASS} passed${N}."
    echo -e "  ${Y}Fix the failures above before blaming the client.${N}"
fi
echo -e "${C}================================================${N}"
[ "$FAIL" -eq 0 ]
EOF_SDTEST
chmod +x /usr/local/bin/dajohn-slowdns-test

# ------------------------------------------------------------------
# dajohn-slowdns-e2e : the definitive test. Runs a REAL dnstt-client on the
# server, pointed at this server's own dnstt-server, and pushes a real
# VMess-WS handshake through the finished tunnel.
#
# dajohn-slowdns-test checks each hop in isolation, which still leaves room to
# argue about the tunnel itself. This drives the entire chain -
# dnstt-client -> UDP 53 -> dnstt-server -> dajohn-mux -> Nginx -> Xray - with
# only the carrier network removed. If this passes, the server is provably
# correct and any remaining failure is client-side configuration.
# ------------------------------------------------------------------
cat << 'EOF_E2E' > /usr/local/bin/dajohn-slowdns-e2e
#!/bin/bash
G='\033[1;32m'; R='\033[1;31m'; Y='\033[1;33m'; C='\033[1;36m'; N='\033[0m'
source /etc/dajohn/core/env.conf 2>/dev/null
LPORT=${LPORT:-18080}

echo -e "${C}======== SLOWDNS END-TO-END TEST ========${N}"
if [ -z "$NS_DOMAIN" ]; then echo -e "${R}[!] NS_DOMAIN unset.${N}"; exit 1; fi

# dnstt-client is not shipped by part 2 (server only), so build it on demand.
#
# Part 2 already cloned the whole dnstt repo to /root/dnstt and built the SERVER
# from it, so the client source is almost always sitting there already - reuse it
# instead of re-cloning. Progress is printed rather than silenced: a Go build on
# a small VPS takes minutes, and a silent script is indistinguishable from a hang.
if [ ! -x /usr/local/bin/dnstt-client ]; then
    echo -e "${Y}[*] dnstt-client not installed - building it (one time).${N}"
    LOG=/tmp/e2e-build.log; : > "$LOG"

    SRC=""
    if [ -d /root/dnstt/dnstt-client ]; then
        SRC=/root/dnstt/dnstt-client
        echo -e "${C}    Using existing source from part 2: $SRC${N}"
    else
        echo -e "${C}    [1/3] Cloning dnstt...${N}"
        command -v git >/dev/null 2>&1 || apt-get install -y -q git >>"$LOG" 2>&1
        rm -rf /root/dnstt
        # NOTE: bamsoftware serves over DUMB HTTP - no shallow clones (a --depth 1
        # here dies with "dumb http transport does not support shallow capabilities").
        if git clone https://www.bamsoftware.com/git/dnstt.git /root/dnstt >>"$LOG" 2>&1 \
           && [ -d /root/dnstt/dnstt-client ]; then
            SRC=/root/dnstt/dnstt-client
        else
            echo -e "${R}[!] Clone failed.${N}"; tail -n 5 "$LOG"; exit 1
        fi
    fi

    echo -e "${C}    [2/3] Selecting a Go >= 1.20 (dnstt needs crypto/ecdh)...${N}"
    # dnstt imports crypto/ecdh, added to the Go stdlib in 1.20; an older Go dies
    # with 'cannot load crypto/ecdh: malformed module path'. And -mod=mod (used
    # below to let Go fix dnstt's stale go.mod) only exists from Go 1.14 - on an
    # ancient apt Go (Ubuntu 20.04 ships go1.13) it is itself fatal ('-mod=mod not
    # supported'). So do NOT just grab whatever 'go' is on PATH: require >= 1.20,
    # else install a modern Go from snap (the same source part 2 uses for the
    # server). This is exactly why the e2e client build failed on an older box
    # while the server built fine on snap Go.
    go_ge120(){ "$1" version 2>/dev/null | awk '{v=$3;sub(/^go/,"",v);split(v,a,".");if(a[1]>1||(a[1]==1&&a[2]>=20))exit 0;exit 1}'; }
    GOBIN=""
    command -v go >/dev/null 2>&1 && go_ge120 go && GOBIN=go
    if [ -z "$GOBIN" ] && [ -x /snap/bin/go ] && go_ge120 /snap/bin/go; then GOBIN=/snap/bin/go; fi
    if [ -z "$GOBIN" ]; then
        echo -e "${C}          no Go >= 1.20 present - installing one via snap (this is the slow part)...${N}"
        apt-get install -y -q snapd >>"$LOG" 2>&1
        systemctl enable --now snapd.socket >>"$LOG" 2>&1
        [ ! -L /snap ] && ln -s /var/lib/snapd/snap /snap 2>/dev/null
        snap install go --classic >>"$LOG" 2>&1
        [ -x /snap/bin/go ] && go_ge120 /snap/bin/go && GOBIN=/snap/bin/go
    fi
    if [ -z "$GOBIN" ]; then
        echo -e "${R}[!] Could not obtain a Go >= 1.20 - cannot build dnstt-client.${N}"
        echo -e "${Y}    Install a modern Go ('snap install go --classic') and retry.${N}"; tail -n 5 "$LOG"; exit 1
    fi
    echo -e "${C}          using $($GOBIN version 2>/dev/null | head -n1)${N}"

    # Match part 2's server-side idle-timeout bump on the client source too, so the
    # e2e self-test reflects the real 10min/20min windows, not dnstt's stock 2min.
    sed -i '/idleTimeout/s/2 \* time\.Minute/10 * time.Minute/' "$SRC/main.go" 2>/dev/null || true
    # Guard: unpinned clone -> if upstream retunes/renames idleTimeout this sed
    # silently no-ops. The client bump only affects self-test realism, but a miss
    # here is the EARLY WARNING that part 2's server-side bump (same sed) also missed
    # - and THIS test is admin-run, so surface it rather than let it pass quietly.
    if ! grep -Eq 'idleTimeout[[:space:]]*=[[:space:]]*10 \* time\.Minute' "$SRC/main.go" 2>/dev/null; then
        echo -e "${Y}    [!] idleTimeout patch did not apply to dnstt source - upstream main.go may${N}"
        echo -e "${Y}        have changed. The server-side bump (part2.sh:417) likely missed too, so${N}"
        echo -e "${Y}        SlowDNS may revert to a ~4min idle reaper. Re-check the sed vs current src.${N}"
    fi
    echo -e "${C}    [3/3] Compiling (1-3 min, no output is normal)...${N}"
    # GOCACHE/GOPATH pinned: under sudo an unwritable HOME makes the build fail
    # with a cache error that looks nothing like the real problem. -mod=mod + a
    # best-effort 'go mod tidy' let the modern Go rewrite dnstt's stale go.mod.
    if ( cd "$SRC" && export GOFLAGS=-mod=mod GOCACHE=/tmp/gocache GOPATH=/tmp/gopath \
         && { "$GOBIN" mod tidy >>"$LOG" 2>&1 || true; } \
         && "$GOBIN" build -o /tmp/dnstt-client-bin . >>"$LOG" 2>&1 ) \
       && [ -s /tmp/dnstt-client-bin ]; then
        install -m755 /tmp/dnstt-client-bin /usr/local/bin/dnstt-client
        rm -f /tmp/dnstt-client-bin
        echo -e "${G}[ OK ] dnstt-client built.${N}"
    else
        echo -e "${R}[!] Build failed. Last lines:${N}"; tail -n 12 "$LOG"; exit 1
    fi
fi

# Talk straight to our own dnstt-server on 127.0.0.1:53. This deliberately
# bypasses public DNS: we are testing the tunnel, not the delegation. (Use
# dajohn-slowdns-test plus a dig from outside to check delegation.)
echo -e "${Y}[*] Starting dnstt-client -> 127.0.0.1:53 (zone ${NS_DOMAIN})...${N}"
/usr/local/bin/dnstt-client -udp 127.0.0.1:53 \
    -pubkey-file /etc/slowdns/server.pub \
    "$NS_DOMAIN" "127.0.0.1:${LPORT}" >/tmp/e2e.log 2>&1 &
CPID=$!
trap 'kill $CPID 2>/dev/null' EXIT
sleep 4

if ! kill -0 $CPID 2>/dev/null; then
    echo -e "${R}[FAIL] dnstt-client exited immediately:${N}"; tail -n 5 /tmp/e2e.log; exit 1
fi
echo -e "${G}[ OK ] tunnel client up on 127.0.0.1:${LPORT}${N}"

RC=0
MODE=$(cat /etc/dajohn/core/slowdns_mode.txt 2>/dev/null || echo unknown)

# 1. SSH through the tunnel - works in mux and ssh modes.
# Skipped in ws and ssl: those point dnstt straight at Nginx, so there is no SSH
# on the other end and a failure here would be the mode working as configured.
if [ "$MODE" != "ws" ] && [ "$MODE" != "ssl" ]; then
    BAN=$(timeout 25 bash -c "exec 3<>/dev/tcp/127.0.0.1/${LPORT}; head -c 20 <&3" 2>/dev/null | tr -d '\0')
    case "$BAN" in
        SSH-2.0*) echo -e "${G}[PASS]${N} SSH through the DNS tunnel ($BAN)" ;;
        *)        echo -e "${R}[FAIL]${N} no SSH banner through the tunnel (got '${BAN:-nothing}')"; RC=1 ;;
    esac
fi

# 2. VMess-WS through the tunnel - the V2Ray path. Needs mux, ws, or ssl mode.
if [ "$MODE" = "ssh" ]; then
    echo -e "${Y}[SKIP]${N} V2Ray test: mode is 'ssh'. Switch with: dajohn-slowdns-mode mux|ws|ssl"
else
    # --max-time 60, not 30: the first request through a fresh DNS tunnel pays
    # both the mux peek wait and a slow tunnel round trip. A 30s cap expired
    # first and reported an empty code, which read as "no response" when the
    # handshake was simply still in flight.
    # Scheme follows the mode. In ssl mode dnstt hands off to Nginx's TLS
    # listener, so a plain http:// request there gets no reply at all and would
    # report "nothing (timed out)" - a real handshake failure looking like a dead
    # tunnel. -k because the cert may be self-signed, and the SNI is forced with
    # --resolve so it matches the certificate rather than 127.0.0.1.
    if [ "$MODE" = "ssl" ]; then
        CODE=$(timeout 75 curl -sk -o /dev/null -w '%{http_code}' --max-time 60 \
            --resolve "${DOMAIN}:${LPORT}:127.0.0.1" \
            -H 'Upgrade: websocket' -H 'Connection: Upgrade' \
            -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13' \
            "https://${DOMAIN}:${LPORT}/api/vmess" 2>/dev/null)
    else
        CODE=$(timeout 75 curl -s -o /dev/null -w '%{http_code}' --max-time 60 \
            -H "Host: ${DOMAIN}" -H 'Upgrade: websocket' -H 'Connection: Upgrade' \
            -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13' \
            "http://127.0.0.1:${LPORT}/api/vmess" 2>/dev/null)
    fi
    if [ "$CODE" = "101" ]; then
        echo -e "${G}[PASS]${N} VMess-WS through the DNS tunnel (HTTP 101)"
    else
        echo -e "${R}[FAIL]${N} VMess-WS through the tunnel returned '${CODE:-nothing (timed out)}'"
        # An SSH banner on the WS port means the mux mis-routed the stream,
        # which is a mux bug, not a client or Xray problem. Name it explicitly.
        PEEK=$(timeout 20 bash -c "exec 3<>/dev/tcp/127.0.0.1/${LPORT}; printf 'GET /api/vmess HTTP/1.1\r\nHost: ${DOMAIN}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n' >&3; head -c 24 <&3" 2>/dev/null | tr -d '\0')
        case "$PEEK" in
            SSH-*) echo -e "${Y}       CAUSE: the mux sent this HTTP request to Dropbear (got '${PEEK}').${N}"
                   echo -e "${Y}       The peek window is too short for this tunnel's latency. Raise it:${N}"
                   echo -e "${C}         systemctl edit --full dajohn-mux   # or set in the unit:${N}"
                   echo -e "${C}         Environment=DAJOHN_MUX_SSH_FALLBACK=25${N}"
                   echo -e "${C}         systemctl restart dajohn-mux${N}" ;;
            *)     echo -e "${Y}       Check Nginx /api/vmess and that xray is running.${N}" ;;
        esac
        RC=1
    fi
fi

kill $CPID 2>/dev/null
echo -e "${C}=========================================${N}"
if [ "$RC" = "0" ]; then
    echo -e "  ${G}Server chain is provably working end to end.${N}"
    echo -e "  ${Y}Any remaining failure is client-side config.${N}"
else
    echo -e "  ${R}The server chain itself is broken - fix this before the client.${N}"
    echo -e "  ${Y}Details: /tmp/e2e.log ; also run dajohn-slowdns-test${N}"
fi
exit $RC
EOF_E2E
chmod +x /usr/local/bin/dajohn-slowdns-e2e

fi

# ==========================================================================
# dajohn-nginx-restore : rewrite the stock Nginx config from scratch.
#
# The 443 split edits the listen line in place, and a config that drifts (a
# stray listen directive, a half-applied edit, a hand edit) takes Nginx down
# entirely - which takes WS, VMess, VLESS and the sub links with it. Re-running
# part 2 fixes it but also re-runs certbot, rebuilds dnstt and reinstalls Xray.
# This does only the one thing, so recovery is seconds instead of minutes.
#
# Byte-identical to the config part 2 writes.
# ==========================================================================
cat << 'EOF_NGXR' > /usr/local/bin/dajohn-nginx-restore
#!/bin/bash
G='\033[1;32m'; R='\033[1;31m'; Y='\033[1;33m'; C='\033[1;36m'; N='\033[0m'
source /etc/dajohn/core/env.conf 2>/dev/null
NGCFG=/etc/nginx/sites-available/default
if [ -z "$DOMAIN" ]; then echo -e "${R}[!] DOMAIN unset in env.conf.${N}"; exit 1; fi

if [ -f "$NGCFG" ]; then
    cp -f "$NGCFG" "${NGCFG}.broken.$(date +%Y%m%d-%H%M%S)" 2>/dev/null
    echo -e "${Y}[*] Existing config saved as ${NGCFG}.broken.*${N}"
    echo -e "${C}    Its listen lines were:${N}"
    grep -n 'listen' "$NGCFG" 2>/dev/null | sed 's/^/      /'
fi

cat > "$NGCFG" <<EOF
server {
    listen 80; listen 443 ssl http2; server_name _;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8880; proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host;
        proxy_buffering off; proxy_read_timeout 3600; proxy_send_timeout 3600;
    }

    location /vless {
        proxy_redirect off; proxy_pass http://127.0.0.1:10000; proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host;
        proxy_buffering off; proxy_read_timeout 3600; proxy_send_timeout 3600;
    }

    location /api/v1/connect {
        proxy_redirect off; proxy_pass http://127.0.0.1:10001; proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host;
        proxy_buffering off; proxy_read_timeout 3600; proxy_send_timeout 3600;
    }

    location /api/vmess {
        proxy_redirect off; proxy_pass http://127.0.0.1:10002; proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host;
        proxy_buffering off; proxy_read_timeout 3600; proxy_send_timeout 3600;
    }

    location /sub/ {
        alias /var/www/dajohn-sub/;
        default_type text/plain;
        autoindex off;
        access_log off;
        add_header Cache-Control "no-store";
    }

    location /xhttp {
        proxy_redirect off; proxy_pass http://127.0.0.1:10003; proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_buffering off; proxy_request_buffering off;
        proxy_read_timeout 3600; proxy_send_timeout 3600;
    }
}
EOF

# The 443 split must be off, or Nginx and dajohn-sni fight over the port.
if systemctl cat dajohn-sni >/dev/null 2>&1; then
    systemctl disable --now dajohn-sni >/dev/null 2>&1
    echo "off" > /etc/dajohn/core/split443.txt
    echo -e "${Y}[*] Disabled the 443 split (Nginx owns 443 again).${N}"
fi
for _ in 1 2 3 4 5 6; do
    ss -tln 2>/dev/null | grep -qE '[:.]443([^0-9]|$)' || break
    sleep 1
done

if ! nginx -t 2>&1 | tail -n 3; then :; fi
if nginx -t >/dev/null 2>&1 && systemctl restart nginx; then
    sleep 1
    if ss -tln 2>/dev/null | grep -qE '[:.]443([^0-9]|$)'; then
        echo -e "${G}[ OK ] Nginx restored and listening on 443.${N}"
    else
        echo -e "${R}[!] Nginx started but 443 is not listening.${N}"; exit 1
    fi
else
    echo -e "${R}[!] Nginx still will not start. Full error:${N}"
    nginx -t 2>&1 | sed 's/^/    /'
    systemctl status nginx --no-pager -n 8 2>/dev/null | sed 's/^/    /'
    exit 1
fi
EOF_NGXR
chmod +x /usr/local/bin/dajohn-nginx-restore

# ==========================================================================
# 2. REMOVED: REALITY ON 443 (the SNI split)
# ==========================================================================
# This section used to move Nginx to 127.0.0.1:8081 and put dajohn-sni in front
# of 443 so Reality and Nginx could share the port. It is gone.
#
# WHY: three separate enable attempts on a live box took HTTPS down, each for a
# different reason - a stale sslh -F unit, a backup taken of an already-broken
# config, then Nginx failing to bind at all. The last one stopped Nginx
# outright, which also killed WS, VMess, VLESS and the sub links. The payoff was
# cosmetic (Reality reachable on 443 instead of 4433) and nowhere near worth
# rewriting the listener of the one service everything else proxies through.
#
# Reality still works exactly as before on 4433/tcp - see menu option 11.
#
# dajohn-sni and dajohn-443-mode are removed below so a box that ran an earlier
# part 5 does not keep a disabled unit and a menu entry that leads nowhere.
# dajohn-nginx-restore stays: it is the recovery tool for a config already
# mangled by those attempts, and it is useful on its own.
echo -e "\n${BYellow}[*] Removing the Reality-on-443 split (option 81)...${NC}"

# Order matters: stop the unit BEFORE restoring the listener, or Nginx cannot
# bind 443 while dajohn-sni still holds it.
if systemctl cat dajohn-sni >/dev/null 2>&1; then
    systemctl disable --now dajohn-sni >/dev/null 2>&1
    rm -f /etc/systemd/system/dajohn-sni.service
    systemctl daemon-reload
    echo -e "${BYellow}[*] Stopped and removed the dajohn-sni unit.${NC}"
fi
rm -f /usr/local/bin/dajohn-sni /usr/local/bin/dajohn-443-mode

# If a failed attempt left Nginx on 8081 (or stopped), put 443 back. This is the
# state the user's box was actually left in, so repair it rather than assume.
NGCFG=/etc/nginx/sites-available/default
if [ -f "$NGCFG" ] && grep -q 'listen 127.0.0.1:8081 ssl' "$NGCFG" 2>/dev/null; then
    echo -e "${BYellow}[*] Nginx is still on 8081 from a 443-split attempt - restoring 443.${NC}"
    sed -i 's/listen 127.0.0.1:8081 ssl http2;/listen 443 ssl http2;/' "$NGCFG"
fi
echo "off" > /etc/dajohn/core/split443.txt 2>/dev/null

if command -v nginx >/dev/null 2>&1; then
    if ! systemctl is-active nginx >/dev/null 2>&1 || ! ss -tln 2>/dev/null | grep -qE '[:.]443([^0-9]|$)'; then
        echo -e "${BYellow}[*] Nginx is not serving 443 - repairing.${NC}"
        if nginx -t >/dev/null 2>&1; then
            systemctl restart nginx >/dev/null 2>&1
        else
            # Config itself is broken (this is the 4433-in-the-listener case).
            /usr/local/bin/dajohn-nginx-restore 2>&1 | sed 's/^/    /'
        fi
    fi
    sleep 1
    if ss -tln 2>/dev/null | grep -qE '[:.]443([^0-9]|$)'; then
        echo -e "${BGreen}[ OK ] Nginx owns 443 again - Reality stays on 4433.${NC}"
    else
        warn "443 is still closed. Run: dajohn-nginx-restore"
    fi
fi
# ==========================================================================
# 3. HYSTERIA 2 OBFS + REALITY DEST/SHORTID HARDENING
# ==========================================================================
# 3a. Salamander obfs. Part 2's Hysteria config has no obfs block, so the QUIC
# handshake carries its stock fingerprint and is trivially classifiable. The
# password is generated once and cached: it is part of every client link, so
# regenerating it on each run would silently kill every Hysteria account.
echo -e "\n${BYellow}[*] Hardening Hysteria 2 (salamander obfs)...${NC}"

HY_CFG=/etc/hysteria/config.yaml
if [ ! -s "$HY_CFG" ]; then
    warn "$HY_CFG missing - run part 2 first; skipping Hysteria hardening."
elif [ "$(cat /etc/dajohn/core/p53_mode.txt 2>/dev/null)" = "shared_all" ]; then
    # shared_all (menu 34 -> 5) deliberately runs Hysteria WITHOUT obfs so its
    # handshake is plain QUIC the udp/53 classifier can match. Re-adding obfs here
    # would make the QUIC rules stop matching and silently drop Hysteria off 53.
    # Leave it off; switch to another port-53 mode first if you want obfs back.
    warn "port-53 mode is shared_all - leaving Hysteria obfs OFF (required for the QUIC demux)."
else
OBFS_FILE=/etc/dajohn/core/hy2_obfs.txt
if [ ! -s "$OBFS_FILE" ]; then
    # The live marker is empty/missing. Before minting a fresh password, look for
    # one parked by shared_all: menu 34 -> 5 renames the live marker to .off when
    # it strips obfs. Minting a new password here instead would (a) silently break
    # every already-issued Hysteria link and (b) orphan the recoverable password,
    # so recover it first and only generate when there is genuinely nothing to
    # fall back to. This is what makes obfs survive a shared_all round-trip even
    # if part 5 is re-run before switching back through the menu.
    if [ -s "${OBFS_FILE}.off" ]; then
        mv -f "${OBFS_FILE}.off" "$OBFS_FILE"
        warn "recovered the previous Hysteria obfs password from .off (was parked by shared_all)."
    else
        openssl rand -hex 12 > "$OBFS_FILE"
    fi
    chmod 600 "$OBFS_FILE"
fi
HY_OBFS=$(cat "$OBFS_FILE")

# A stale .off can only linger now if a fresh .txt was written some other way
# while an old parked password still existed; it is an outdated password and the
# restore path would wrongly resurrect it, so drop it once we have a live marker.
[ -s "${OBFS_FILE}.off" ] && rm -f "${OBFS_FILE}.off"

# Snapshot before either branch touches the file - the rewrite path below can
# fail too, and the restore at the bottom needs something current to fall back
# to (this used to be taken only on the fresh-append path).
cp -f "$HY_CFG" "${HY_CFG}.pre-obfs"

if grep -q '^obfs:' "$HY_CFG"; then
    # Already present. Force the cached password back in, in case part 2 was
    # re-run and wrote a fresh file, or someone hand-edited it.
    python3 - "$HY_CFG" "$HY_OBFS" <<'EOF_PY' 2>/dev/null || warn "could not refresh the obfs password - check $HY_CFG by hand."
import sys, re
p, pw = sys.argv[1], sys.argv[2]
s = open(p).read()
s = re.sub(r'(obfs:\s*\n\s*type:\s*salamander\s*\n\s*salamander:\s*\n\s*password:\s*).*',
           lambda m: m.group(1) + pw, s, count=1)
open(p, 'w').write(s)
EOF_PY
else
    cp -f "$HY_CFG" "${HY_CFG}.pre-obfs"
    cat >> "$HY_CFG" <<EOF
obfs:
  type: salamander
  salamander:
    password: $HY_OBFS
EOF
fi

systemctl restart hysteria-server >/dev/null 2>&1
sleep 2
if systemctl is-active --quiet hysteria-server; then
    echo -e "${BGreen}[ OK ] Hysteria 2 obfs active.${NC}"
    echo -e "${BCyan}       obfs password: ${BGreen}${HY_OBFS}${NC}"
    echo -e "${BYellow}       Existing Hysteria clients MUST add this obfs password.${NC}"
    echo -e "${BYellow}       Re-issue links with menu option 54.${NC}"
else
    warn "hysteria-server did not restart with obfs - reverting."
    [ -f "${HY_CFG}.pre-obfs" ] && cp -f "${HY_CFG}.pre-obfs" "$HY_CFG"
    systemctl restart hysteria-server >/dev/null 2>&1
fi
fi

# 3b. Reality dest / serverNames / shortIds.
# www.google.com is a weak front: it is the default in every tutorial, so it is
# the first SNI a censor fingerprints, and Google's TLS profile does not match
# what Xray presents. A CDN host is a better mask. shortIds [""] also means
# every client shares the empty id, which removes the per-client
# distinguisher Reality is designed around.
#
# The private key is NOT touched, so existing links stay valid - but the SNI
# does change, so clients must update serverName. That is why this is a
# prompt, not an automatic rewrite.
echo -e "\n${BYellow}[*] Reality dest / shortId hardening...${NC}"

if [ ! -s "$XCFG" ]; then
    warn "$XCFG missing - skipping Reality hardening."
else
CUR_DEST=$(jq -r '[.inbounds[]?|select(.streamSettings.realitySettings!=null)|.streamSettings.realitySettings.dest]|first // "none"' "$XCFG" 2>/dev/null)
CUR_SID=$(jq -r  '[.inbounds[]?|select(.streamSettings.realitySettings!=null)|.streamSettings.realitySettings.shortIds]|first|join(",")' "$XCFG" 2>/dev/null)
echo -e "  Current dest     : ${BCyan}${CUR_DEST}${NC}"
echo -e "  Current shortIds : ${BCyan}[${CUR_SID}]${NC}"

cat << 'EOF_RH' > /usr/local/bin/dajohn-reality-harden
#!/bin/bash
# Repoint Reality at a better front and give it real shortIds.
# Keeps the private key, so issued links stay cryptographically valid; clients
# only need their serverName/SNI updated to the new front.
G='\033[1;32m'; R='\033[1;31m'; Y='\033[1;33m'; C='\033[1;36m'; N='\033[0m'
XCFG=/usr/local/etc/xray/config.json
[ -s "$XCFG" ] || { echo -e "${R}[!] $XCFG missing.${N}"; exit 1; }

FRONT="$1"
if [ -z "$FRONT" ]; then
    echo -e "${C}Pick a Reality front (must be TLS1.3 + H2, and reachable from this VPS):${N}"
    echo "   1) www.microsoft.com     (large, boring, CDN-backed)"
    echo "   2) www.cloudflare.com    (CDN, TLS1.3, good globally)"
    echo "   3) www.apple.com         (huge traffic volume)"
    echo "   4) www.amazon.com"
    echo "   5) custom"
    read -r -p " Select [1-5]: " s
    case "$s" in
        1) FRONT="www.microsoft.com" ;;
        2) FRONT="www.cloudflare.com" ;;
        3) FRONT="www.apple.com" ;;
        4) FRONT="www.amazon.com" ;;
        5) read -r -p " Enter hostname (no https://): " FRONT ;;
        *) echo -e "${R}Cancelled.${N}"; exit 1 ;;
    esac
fi
FRONT=$(printf '%s' "$FRONT" | tr -d ' \r' | sed 's#^https\?://##; s#/.*##')
if ! printf '%s' "$FRONT" | grep -qE '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'; then
    echo -e "${R}[!] '$FRONT' is not a valid hostname.${N}"; exit 1
fi

# A front that this VPS cannot reach over TLS1.3 makes every Reality
# handshake fail, so it is verified before anything is written.
echo -e "${Y}[*] Verifying ${FRONT} supports TLS 1.3...${N}"
if ! echo | timeout 12 openssl s_client -connect "${FRONT}:443" -servername "$FRONT" -tls1_3 >/dev/null 2>&1; then
    echo -e "${R}[!] ${FRONT} did not complete a TLS 1.3 handshake from this VPS.${N}"
    echo -e "${Y}    Reality would break. Pick a different front.${N}"
    exit 1
fi
echo -e "${G}[ OK ] ${FRONT} handshakes on TLS 1.3.${N}"

# Real shortIds: one shared plus a few spares. Hex, even length, <=16 chars.
SID1=$(openssl rand -hex 4)
SID2=$(openssl rand -hex 6)
SID3=$(openssl rand -hex 8)

cp -f "$XCFG" "${XCFG}.pre-harden"
jq --arg f "$FRONT" --arg a "$SID1" --arg b "$SID2" --arg c "$SID3" '
  (.inbounds[]? | select(.streamSettings.realitySettings != null) | .streamSettings.realitySettings) |=
     (.dest = ($f + ":443") | .serverNames = [$f] | .shortIds = ["", $a, $b, $c])
' "$XCFG" > /tmp/frh.json 2>/dev/null

if [ ! -s /tmp/frh.json ] || ! jq empty /tmp/frh.json 2>/dev/null; then
    echo -e "${R}[!] jq edit failed - config left unchanged.${N}"; rm -f /tmp/frh.json; exit 1
fi
mv /tmp/frh.json "$XCFG"
# mv preserves the temp file's mode, which would leave the config unreadable to
# user "nobody" and break the next xray restart.
chmod 644 "$XCFG"

if ! /usr/local/bin/xray run -test -config "$XCFG" >/tmp/frh.test 2>&1; then
    echo -e "${R}[!] Xray rejected the config - rolling back.${N}"; tail -n 12 /tmp/frh.test
    cp -f "${XCFG}.pre-harden" "$XCFG"; chmod 644 "$XCFG"; exit 1
fi
systemctl restart xray; sleep 2
if ! systemctl is-active --quiet xray; then
    echo -e "${R}[!] Xray did not restart - rolling back.${N}"
    cp -f "${XCFG}.pre-harden" "$XCFG"; chmod 644 "$XCFG"; systemctl restart xray; exit 1
fi

echo "$FRONT" > /etc/dajohn/core/reality_dest.txt
echo "$SID1"  > /etc/dajohn/core/reality_sid.txt
echo ""
echo -e "${G}================ REALITY UPDATED ================${N}"
echo -e "  Front / SNI : ${G}${FRONT}${N}"
echo -e "  shortIds    : ${C}\"\", ${SID1}, ${SID2}, ${SID3}${N}"
echo -e "  Public key  : ${C}$(cat /etc/dajohn/core/reality_pub.txt 2>/dev/null)${N}"
echo -e "${Y}  Clients must update serverName/SNI to ${FRONT}.${N}"
echo -e "${Y}  Re-issue links with menu option 54.${N}"
echo -e "${G}================================================${N}"
EOF_RH
chmod +x /usr/local/bin/dajohn-reality-harden
echo -e "${BGreen}[ OK ] dajohn-reality-harden installed (run it from menu option 82).${NC}"
fi

# ==========================================================================
# 4. UDP-CUSTOM  (ZIVPN-style standalone UDP, for Android injector clients)
# ==========================================================================
# Nothing in parts 1-4 serves this niche: badvpn/udpgw only forwards UDP that
# is already inside an SSH tunnel, and Hysteria needs a QUIC-capable client.
# udp-custom is what the cheap-data-plan injector apps actually speak.
#
# Accounts live in /etc/dajohn/data/udp_users.txt as "user pass expiry", the
# same shape as the other Dajohn databases, so the expiry sweep and the menu
# follow the existing patterns. The config is REBUILT from that file - the
# text DB is the source of truth, never the JSON.
echo -e "\n${BYellow}[*] Installing UDP-Custom...${NC}"

mkdir -p /etc/dajohn/udp
touch /etc/dajohn/data/udp_users.txt
chmod 600 /etc/dajohn/data/udp_users.txt

elf_ok(){
    [ -s "$1" ] || return 1
    [ "$(stat -c%s "$1" 2>/dev/null || echo 0)" -ge 100000 ] || return 1
    [ "$(od -An -c -N4 "$1" 2>/dev/null | tr -d ' \n')" = "177ELF" ] || return 1
    [ "$(od -An -tx1 -j18 -N2 "$1" 2>/dev/null | tr -d ' \n')" = "$ELF_MACH" ] || return 1
    return 0
}

# Same failure mode part 4 documents: a 404 saved AS the binary passes [ -x ],
# so the download is skipped forever while systemd reports "Exec format error".
#
# The URL is RESOLVED, not hardcoded. udp-custom has no single canonical upstream
# - it is redistributed across several mirrors that come and go, and a dead
# hardcoded link is indistinguishable from a network failure. So: try each known
# mirror through the GitHub API (which reports assets honestly), and let the
# admin override everything with UDP_CUSTOM_URL for a mirror we don't know about:
#
#     UDP_CUSTOM_URL="https://.../udp-custom-linux-amd64" bash part5.sh
if ! elf_ok /etc/dajohn/udp/udp-custom; then
    rm -f /etc/dajohn/udp/udp-custom
    UDP_TRIED=""

    try_udp(){
        [ -n "$1" ] || return 1
        UDP_TRIED="${UDP_TRIED}
        $1"
        curl -fsSL --max-time 120 -o /etc/dajohn/udp/udp-custom.dl "$1" 2>/dev/null || { rm -f /etc/dajohn/udp/udp-custom.dl; return 1; }
        if elf_ok /etc/dajohn/udp/udp-custom.dl; then
            mv -f /etc/dajohn/udp/udp-custom.dl /etc/dajohn/udp/udp-custom
            chmod +x /etc/dajohn/udp/udp-custom
            return 0
        fi
        rm -f /etc/dajohn/udp/udp-custom.dl
        return 1
    }

    # 1. explicit override wins
    try_udp "$UDP_CUSTOM_URL"

    # 2. The known-good source: a raw file committed to the repo, NOT a release
    #    asset. This is why the GitHub releases API never found it - there is no
    #    release, so an /releases/latest lookup returns nothing and the earlier
    #    hardcoded /releases/latest/download/... path 404'd.
    #    Verified 2026-07-31: amd64 is a valid 64-bit x86_64 ELF (4,782,592 B).
    #    ONLY amd64 exists upstream - bin/ contains just that binary and a
    #    banner.jpg, and the arm64 path returns the 14-byte string
    #    "404: Not Found". elf_ok rejects that on size, so an ARM box falls
    #    through to the manual instructions instead of installing a text file.
    if ! elf_ok /etc/dajohn/udp/udp-custom; then
        try_udp "https://raw.githubusercontent.com/http-custom/udp-custom/main/bin/udp-custom-linux-${DEB_ARCH}"
    fi

    # 3. Fall back to asking the API of each candidate repo for a matching
    #    asset, in case a mirror does publish proper releases.
    if ! elf_ok /etc/dajohn/udp/udp-custom; then
        for REPO in "http-custom/udp-custom" "rudi9999/UDP-Custom" "Ndik-XD/udp-custom" "kanolahy/udp-custom-1"; do
            RJ=$(curl -fsSL --max-time 20 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null)
            [ -z "$RJ" ] && continue
            # Prefer an asset naming this arch; fall back to the sole asset if a
            # release ships one arch-agnostic binary.
            AU=$(printf '%s' "$RJ" | jq -r --arg a "$DEB_ARCH" \
                 '[.assets[]?|select((.name|ascii_downcase)|test($a))]|first|.browser_download_url // empty' 2>/dev/null)
            [ -z "$AU" ] && AU=$(printf '%s' "$RJ" | jq -r \
                 '[.assets[]?|select((.name|ascii_downcase)|test("udp"))]|first|.browser_download_url // empty' 2>/dev/null)
            try_udp "$AU" && break
        done
    fi

    if elf_ok /etc/dajohn/udp/udp-custom; then
        echo -e "${BGreen}[ OK ] udp-custom binary installed (${DEB_ARCH}).${NC}"
    else
        rm -f /etc/dajohn/udp/udp-custom
        warn "No working udp-custom binary found for ${DEB_ARCH} - UDP-Custom skipped."
        warn "  Everything else in part 5 is unaffected."
        if [ "$DEB_ARCH" != "amd64" ]; then
            echo -e "${BYellow}      NOTE: upstream only publishes an amd64 build - there is no${NC}"
            echo -e "${BYellow}      ${DEB_ARCH} binary to fetch. You need one built for this arch.${NC}"
        fi
        echo -e "${BYellow}      Tried:${UDP_TRIED:-
        (no candidate URL resolved - GitHub API unreachable?)}${NC}"
        echo -e "${BYellow}      To install manually, drop the binary in place and re-run:${NC}"
        echo -e "${BCyan}        install -m755 /path/to/udp-custom /etc/dajohn/udp/udp-custom${NC}"
        echo -e "${BCyan}        bash part5.sh${NC}"
        echo -e "${BYellow}      Or point the installer at a mirror you trust:${NC}"
        echo -e "${BCyan}        UDP_CUSTOM_URL='https://.../udp-custom-linux-${DEB_ARCH}' bash part5.sh${NC}"
    fi
fi

if [ -x /etc/dajohn/udp/udp-custom ]; then

cat << 'EOF_UDPBUILD' > /usr/local/bin/dajohn-udp-build
#!/bin/bash
# Rebuild /etc/dajohn/udp/config.json from /etc/dajohn/data/udp_users.txt.
# Safe to run any time. Expired rows are skipped, not deleted - dajohn-udp-expire
# owns removal, exactly like part 4's TUIC/AnyTLS split.
CFG=/etc/dajohn/udp/config.json
DB=/etc/dajohn/data/udp_users.txt
TODAY=$(date +%F)
mkdir -p /etc/dajohn/udp; touch "$DB"

# awk filters and emits TSV, jq builds the JSON. Dates compare as strings:
# YYYY-MM-DD sorts correctly as text and mktime is a gawk extension that does
# not exist in the mawk Ubuntu ships.
# 'xp' not 'exp': exp() is an awk built-in and using it as a variable name is a
# syntax error, not a warning - the whole filter dies and every account vanishes.
# AUTH IS PAM, AND THAT IS WHAT THIS BINARY ACTUALLY DOES.
# The shipped binary is UDP-Custom v1.4. Its "mode":"passwords" does NOT mean
# "read this JSON user list" - it means "authenticate each client through PAM",
# i.e. against the box's real Linux/SSH accounts (/etc/passwd + /etc/shadow).
# Proven on the live box: the journal logged pam_unix(passwd:auth) 'user unknown'
# for a name that was not a Linux user, and the identical client connected the
# instant a real SSH username+password was used. So NO credential list belongs in
# config.json - v1.4 ignores it entirely. A client's UDP login IS their SSH login.
#
# This is why every panel SSH account (part 3's useradd + chpasswd) is already a
# valid UDP account for free - there is nothing extra to provision. The udp_users
# DB below is kept only so the account menu and expiry tooling still have something
# to list; it does not gate access. Do NOT re-add an "auth.config" array here - it
# does nothing on v1.4 and only misleads the next reader.
NUSERS=$(awk -v today="$TODAY" 'NF>=2 { xp=(NF>=3?$3:""); if (xp!="" && xp<today) next; c++ } END{print c+0}' "$DB")

cat > "$CFG" <<EOF
{
  "listen": ":36712",
  "stream_buffer": 134217728,
  "receive_buffer": 268435456,
  "send_buffer": 268435456,
  "auth": {
    "mode": "passwords"
  }
}
EOF
chmod 600 "$CFG"
if systemctl is-active --quiet udp-custom; then
    systemctl restart udp-custom >/dev/null 2>&1
    # The restart re-lays udp-custom's blanket DNAT rules at the top of
    # PREROUTING, which steals udp/53 from DAJOHN_DNSMUX and kills SlowDNS.
    # Put the demux chain back at position 1. The unit also does this via
    # ExecStartPost; doing it here too covers a manual/direct rebuild.
    sleep 1
    [ -x /usr/local/bin/dajohn-iptables ] && /usr/local/bin/dajohn-iptables >/dev/null 2>&1
fi
exit 0
EOF_UDPBUILD
chmod +x /usr/local/bin/dajohn-udp-build

cat > /etc/systemd/system/udp-custom.service <<'EOF_UDPSVC'
[Unit]
Description=UDP Custom Server
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=/etc/dajohn/udp
ExecStart=/etc/dajohn/udp/udp-custom server -exclude 53,443,4430,5300,8388,51820 -config /etc/dajohn/udp/config.json
Restart=always
RestartSec=3
# udp-custom re-installs its blanket DNAT rules every time it starts, at the TOP
# of PREROUTING - which steals udp/53 back from part 2's DAJOHN_DNSMUX chain and
# silently kills SlowDNS. dajohn-udp-build restarts this unit on every account
# add, so without this the demux breaks the next time an account is created.
# Re-asserting the chain here makes the repair automatic instead of manual.
ExecStartPost=-/usr/local/bin/dajohn-iptables
[Install]
WantedBy=multi-user.target
EOF_UDPSVC

# -exclude matters far more than it looks. udp-custom does NOT just bind 36712 -
# it installs DNAT rules covering EVERY UDP port except the excluded ones:
#     udp dpts:1:52      -> :36712
#     udp dpts:54:5299   -> :36712
#     udp dpts:5301:65535 -> :36712
# so any UDP service whose port is not excluded, and which has no earlier
# PREROUTING rule, silently loses all inbound traffic. With the old
# "-exclude 53,5300" that meant WireGuard (51820), Shadowsocks UDP (8388),
# Hysteria's direct port (4430) and TUIC on 443/UDP were all dead - they were
# reachable only if some earlier chain caught them first (DAJOHN_HOP saves the
# Hysteria 20000-40000 range, DAJOHN_TUIC saves 8443). Nothing errors; the
# packets just go to the wrong daemon.
#
# 53 STAYS EXCLUDED even in the shared port-53 modes. Reaching udp-custom on 53
# is the job of part 2's DAJOHN_DNSMUX chain, which classifies the packet first
# and only forwards non-DNS traffic here. Dropping 53 from this list would let
# udp-custom's own blanket DNAT swallow DNS as well, killing SlowDNS.

cat << 'EOF_UDPEXP' > /usr/local/bin/dajohn-udp-expire
#!/bin/bash
# Drop expired UDP-Custom accounts, then rebuild. Own script rather than an
# edit to dajohn-autoexpire, which part 3 regenerates.
DB=/etc/dajohn/data/udp_users.txt
[ -f "$DB" ] || exit 0
TODAY=$(date +%F)
TMP=$(mktemp)
awk -v today="$TODAY" 'NF<3 || $3=="" || $3>=today' "$DB" > "$TMP"
if ! cmp -s "$TMP" "$DB"; then
    cp -f "$DB" "${DB}.bak"
    mv "$TMP" "$DB"
    chmod 600 "$DB"
    /usr/local/bin/dajohn-udp-build
else
    rm -f "$TMP"
fi
exit 0
EOF_UDPEXP
chmod +x /usr/local/bin/dajohn-udp-expire
(crontab -l 2>/dev/null | grep -v 'dajohn-udp-expire'; echo "23 0 * * * /usr/local/bin/dajohn-udp-expire") | crontab -

# UDP port range for the injector clients + the service port itself.
ufw allow 36712/udp >/dev/null 2>&1
ufw allow 6000:19999/udp >/dev/null 2>&1

/usr/local/bin/dajohn-udp-build
systemctl daemon-reload
systemctl enable --now udp-custom >/dev/null 2>&1
sleep 2
if systemctl is-active --quiet udp-custom; then
    echo -e "${BGreen}[ OK ] UDP-Custom running on 36712/udp.${NC}"
else
    warn "udp-custom installed but did not start - check: journalctl -u udp-custom -n 20"
fi

# udp-custom installs its own catch-all DNAT rules at RUNTIME, so it must be
# started before dajohn-iptables re-asserts the Hysteria chains - whichever rule
# sits earlier in PREROUTING wins, and the mux chain has to stay at position 1.

# Seed the port-53 mode if nothing has set it yet. Without this the box falls into
# dajohn-iptables' migration path, which reads the legacy hy2_shared53.txt and can
# only ever produce slowdns/hysteria/shared_hy - so udp-custom would never appear
# in the demux chain no matter what was selected. Existing files are left alone.
mkdir -p /etc/dajohn/core
if [ ! -s /etc/dajohn/core/p53_mode.txt ]; then
    if [ "$(cat /etc/dajohn/core/hy2_shared53.txt 2>/dev/null)" = "on" ]; then
        echo "shared_hy" > /etc/dajohn/core/p53_mode.txt
    elif grep -q '^listen: :53' /etc/hysteria/config.yaml 2>/dev/null; then
        echo "hysteria" > /etc/dajohn/core/p53_mode.txt
    else
        echo "slowdns" > /etc/dajohn/core/p53_mode.txt
    fi
fi

[ -x /usr/local/bin/dajohn-iptables ] && /usr/local/bin/dajohn-iptables
fi

# ==========================================================================
# 5. MENU INJECTION  (option [10] - Tunnels & UDP)
# ==========================================================================
# Same caveat and same marker discipline as part 4: /usr/local/bin/menu is
# generated by part 3, so this patch is lost whenever part 3 re-runs.
#
# Option numbers start at 81. Parts 1-3 use 1-62, part 4 uses 70-80.
echo -e "\n${BYellow}[*] Patching Dashboard Menu with Tunnels & UDP...${NC}"

if [ ! -f /usr/local/bin/menu ]; then
    warn "/usr/local/bin/menu not found - run part 3 (then 4), then re-run part 5."
else
cp -f /usr/local/bin/menu /usr/local/bin/menu.pre-part5 2>/dev/null

if grep -q "# >>> DAJOHN-PART5-TUN >>>" /usr/local/bin/menu; then
    sed -i '/# >>> DAJOHN-PART5-TUN >>>/,/# <<< DAJOHN-PART5-TUN <<</d' /usr/local/bin/menu
fi
# Older part 5 builds injected submenu_tunnels() WITHOUT the marker comments, so
# the marker delete above misses them and the stale definition survives a re-run
# (two defs; whichever bash sees last wins, so the menu looks unchanged). Strip any
# remaining submenu_tunnels() by name, brace-counted, so exactly one copy - the
# fresh marked block below - is ever present.
if grep -q '^submenu_tunnels()' /usr/local/bin/menu; then
    awk '
        /^submenu_tunnels\(\)/ && depth==0 { skip=1 }
        skip {
            n=gsub(/{/,"{"); depth+=n
            m=gsub(/}/,"}"); depth-=m
            if (depth<=0) { skip=0 }
            next
        }
        { print }
    ' /usr/local/bin/menu > /usr/local/bin/menu.tun.$$ && mv /usr/local/bin/menu.tun.$$ /usr/local/bin/menu
fi

cat << 'EOF_P5MENU' > /tmp/p5_menu.txt
# >>> DAJOHN-PART5-TUN >>>
submenu_tunnels() {
    while true; do
        clear; hr
        echo -e "         ${PURPLE}🌐 ITZDAJOHN — TUNNELS & UDP${NC}"
        hr
        SDM=$(cat /etc/dajohn/core/slowdns_mode.txt 2>/dev/null || echo unknown)
        echo -e "   ${CYAN}SlowDNS mode${NC}   : ${GREEN}${SDM}${NC}"
        hr
        echo -e "   ${CYAN}SlowDNS + V2Ray${NC}"
        echo -e "   ${GREEN}[83] Switch SlowDNS Mode (mux / ssh / ws / ssl)${NC}"
        echo -e "   ${GREEN}[84] SlowDNS + V2Ray Client Info${NC}"
        echo -e "   ${GREEN}[90] Test SlowDNS + V2Ray (server-side self test)${NC}"
        echo -e "   ${GREEN}[91] End-to-End Tunnel Test (real dnstt-client)${NC}"
        echo -e "   ${GREEN}[92] Watch Mux Log (see what your VPN app sends)${NC}"
        hr
        echo -e "   ${CYAN}UDP Custom${NC}     [87] Info  ${GREEN}(login = any SSH account)${NC}"
        hr
        echo -e "   ${CYAN}Hardening${NC}"
        echo -e "   ${GREEN}[82] Harden Reality Front (dest + shortIds)${NC}"
        echo -e "   ${GREEN}[88] Show Hysteria obfs Password${NC}"
        echo -e "   ${GREEN}[89] Rebuild UDP-Custom Config${NC}"
        hr; echo -e "   ${YELLOW}[0] Back${NC}"; echo -ne " ${YELLOW}Select:${NC} "
        read choice; choice=$(echo "$choice" | tr -d ' ')
        [ "$choice" = "0" ] && return

        case $choice in
            81)
               # Kept as a stub so an old muscle-memory keypress explains itself
               # instead of silently falling through to "Invalid".
               echo -e "\n${YELLOW}[!] Option 81 (Reality on 443) has been removed.${NC}"
               echo -e "${CYAN}    It rewrote the Nginx listener to share 443, and repeated${NC}"
               echo -e "${CYAN}    failures took HTTPS - and with it WS/VMess/VLESS and the${NC}"
               echo -e "${CYAN}    sub links - offline. Not worth it for a port change.${NC}"
               echo -e "${GREEN}    Reality is unchanged on 4433/tcp: see menu option 11.${NC}"
               echo -e "${CYAN}    If Nginx is still broken from an old attempt, run:${NC}"
               echo -e "${GREEN}      dajohn-nginx-restore${NC}"
               read -n 1 -s -r -p "Press any key..." ;;
            82)
               /usr/local/bin/dajohn-reality-harden
               read -n 1 -s -r -p "Press any key..." ;;
            83)
               echo -e "\n${CYAN}--- SLOWDNS MODE ---${NC}"
               echo -e "   ${GREEN}[1] mux${NC}  SSH + WS + TLS together, auto-detected (recommended)"
               echo -e "   ${GREEN}[2] ssh${NC}  SSH only (original behaviour)"
               echo -e "   ${GREEN}[3] ws ${NC}  V2Ray / WS only, plain HTTP (no TLS)"
               echo -e "   ${GREEN}[4] ssl${NC}  TLS only - for ssldns clients that always use TLS"
               echo -e "   ${YELLOW}mux already serves TLS; pick ssl only to skip detection.${NC}"
               read -r -p " Select [1-4]: " m
               case "$m" in
                   1) /usr/local/bin/dajohn-slowdns-mode mux ;;
                   2) /usr/local/bin/dajohn-slowdns-mode ssh ;;
                   3) /usr/local/bin/dajohn-slowdns-mode ws ;;
                   4) /usr/local/bin/dajohn-slowdns-mode ssl ;;
                   *) echo "Cancelled." ;;
               esac
               read -n 1 -s -r -p "Press any key..." ;;
            84)
               source /etc/dajohn/core/env.conf 2>/dev/null
               clear; hr
               echo -e "     ${PURPLE}SLOWDNS + V2RAY CLIENT SETUP${NC}"
               hr
               echo -e "   ${CYAN}A) HTTP CUSTOM / injector apps${NC}"
               echo -e "   ${YELLOW}The app builds the DNS tunnel itself and routes V2Ray${NC}"
               echo -e "   ${YELLOW}through it. So the V2Ray block uses your REAL domain on${NC}"
               echo -e "   ${YELLOW}port 80 - NOT 127.0.0.1. Enable BOTH toggles:${NC}"
               echo -e "     slowdnsEnabled : ${GREEN}true${NC}"
               echo -e "     v2rayEnabled   : ${GREEN}true${NC}"
               echo ""
               echo -e "   ${CYAN}SlowDNS section${NC}"
               echo -e "     Nameserver  : ${GREEN}${NS_DOMAIN}${NC}"
               echo -e "     Public key  : ${GREEN}$(cat /etc/dajohn/core/slowdns_pub.txt 2>/dev/null)${NC}"
               echo -e "     DNS Resolver: ${GREEN}your ISP DNS${NC} (or 8.8.8.8)"
               echo ""
               echo -e "   ${CYAN}V2Ray section - VLESS (recommended)${NC}"
               echo -e "     protocol    : ${GREEN}vless${NC}"
               echo -e "     address     : ${GREEN}${DOMAIN}${NC}"
               echo -e "     port        : ${GREEN}80${NC}"
               echo -e "     encryption  : ${GREEN}none${NC}"
               echo -e "     network     : ${GREEN}ws${NC}"
               echo -e "     security    : ${GREEN}none${NC}"
               echo -e "     path        : ${GREEN}/vless${NC}"
               echo -e "     Host header : ${GREEN}${DOMAIN}${NC}"
               VL=$(awk 'NF>=2 && $1!=$2 {printf "       %-16s %s\n", $1, $2}' /etc/xray/vless_users.db 2>/dev/null | head -5)
               if [ -n "$VL" ]; then
                   echo -e "     ${CYAN}id (UUID) - your VLESS accounts:${NC}"; echo "$VL"
               else
                   echo -e "     ${YELLOW}id: no VLESS accounts - create one: menu -> 2 -> [ 9]${NC}"
               fi
               echo ""
               echo -e "   ${CYAN}V2Ray section - VMess alternative${NC}"
               echo -e "     protocol ${GREEN}vmess${NC}   path ${GREEN}/api/vmess${NC}   alterId ${GREEN}0${NC}"
               VU=$(awk 'NF>=2{printf "       %-16s %s\n", $1, $2}' /etc/xray/vmess_users.db 2>/dev/null | head -5)
               [ -n "$VU" ] && echo "$VU"
               hr
               echo -e "   ${CYAN}B) Termux + v2rayNG (manual dnstt-client)${NC}"
               echo -e "   ${YELLOW}Only if your app cannot do SlowDNS itself. Here YOU run${NC}"
               echo -e "   ${YELLOW}dnstt-client, so V2Ray points at the LOCAL port:${NC}"
               echo -e "     dnstt-client -udp <ISP_DNS>:53 -pubkey-file server.pub \\"
               echo -e "                  ${NS_DOMAIN} 127.0.0.1:8080"
               echo -e "     then v2rayNG -> address ${GREEN}127.0.0.1${NC} port ${GREEN}8080${NC}, same"
               echo -e "     network/path/Host as above."
               hr
               echo -e "   ${YELLOW}SlowDNS mode must be 'mux', 'ws' or 'ssl'. Current: $(cat /etc/dajohn/core/slowdns_mode.txt 2>/dev/null || echo unknown)${NC}"
               echo -e "   ${YELLOW}Verify server side with [90]/[91]; watch live traffic with [92].${NC}"
               hr
               read -n 1 -s -r -p "Press any key..." ;;
            85|86)
               # UDP-Custom v1.4 authenticates via PAM against the box's real SSH
               # accounts - it does NOT read a credential list from config.json. A
               # separate "UDP account" therefore authenticates nobody, so Create
               # and Delete are gone: manage the SSH account instead and the UDP
               # login follows it automatically. Kept as a stub so an old keypress
               # explains itself rather than silently doing nothing.
               echo -e "\n${YELLOW}UDP-Custom has no accounts of its own.${NC}"
               echo -e "The UDP login IS an SSH login - v1.4 checks PAM (real SSH users)."
               echo -e "Create or remove the ${CYAN}SSH${NC} account (SSH menu) and UDP follows it."
               echo -e "Use ${GREEN}[87]${NC} to see connection details."
               read -n 1 -s -r -p "Press any key..." ;;
            87)
               echo -e "\n${CYAN}--- UDP-CUSTOM INFO ---${NC}"
               echo -e "  Auth: ${GREEN}PAM${NC} - any SSH account on this box logs in."
               echo -e "  Username/Password = that account's ${CYAN}SSH${NC} username & password."
               echo ""
               IP=$(/usr/local/bin/dajohn-ip 2>/dev/null)
               echo -e "  Host     : ${CYAN}${IP}${NC}"
               # In a shared port-53 mode the demux chain sends non-DNS udp/53 here,
               # so 53 is the port worth advertising - carriers often pass it free.
               case "$(cat /etc/dajohn/core/p53_mode.txt 2>/dev/null)" in
                 shared_udp|shared_all)
                   echo -e "  Port     : ${GREEN}53${NC} (shared with SlowDNS) or ${CYAN}36712${NC} direct" ;;
                 *)
                   echo -e "  Port     : ${CYAN}36712${NC}  (menu 34 can move this to 53)" ;;
               esac
               echo ""
               echo -e "  ${YELLOW}SSH accounts that can use UDP right now:${NC}"
               # Real login accounts: a password set in shadow and a normal-range UID.
               # Excludes system/service users and locked (! / *) shadow entries.
               awk -F: '($2!="!"&&$2!="*"&&$2!=""){print $1}' /etc/shadow 2>/dev/null \
                 | while read -r su; do
                     uid=$(id -u "$su" 2>/dev/null)
                     [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ "$su" != "nobody" ] \
                       && echo -e "    ${GREEN}${su}${NC}"
                   done
               echo ""
               systemctl is-active --quiet udp-custom && echo -e "  Service: ${GREEN}running${NC}" || echo -e "  Service: ${RED}STOPPED${NC}"
               read -n 1 -s -r -p "Press any key..." ;;
            88)
               echo ""
               if [ -s /etc/dajohn/core/hy2_obfs.txt ]; then
                   echo -e "  ${CYAN}Hysteria 2 obfs (salamander):${NC}"
                   echo -e "  ${GREEN}$(cat /etc/dajohn/core/hy2_obfs.txt)${NC}"
                   echo -e "  ${YELLOW}Every Hysteria client needs this value.${NC}"
               else
                   echo -e "  ${RED}No obfs password set (re-run part 5).${NC}"
               fi
               read -n 1 -s -r -p "Press any key..." ;;
            90)
               echo ""
               /usr/local/bin/dajohn-slowdns-test
               read -n 1 -s -r -p "Press any key..." ;;
            91)
               echo ""
               echo -e "${YELLOW}Runs a real dnstt-client against this server. Takes ~30s.${NC}"
               echo -e "${YELLOW}First run also builds dnstt-client (a few minutes).${NC}"
               /usr/local/bin/dajohn-slowdns-e2e
               read -n 1 -s -r -p "Press any key..." ;;
            92)
               clear; hr
               echo -e "     ${PURPLE}MUX DECISION LOG${NC}"
               hr
               echo -e "   ${CYAN}Every connection the DNS tunnel hands to the mux is logged${NC}"
               echo -e "   ${CYAN}with its first bytes and where it was routed.${NC}"
               echo ""
               echo -e "   ${YELLOW}Now connect with your VPN app and watch what appears:${NC}"
               echo -e "     ${GREEN}-> HTTP${NC}          V2Ray path is working"
               echo -e "     ${GREEN}-> SSH${NC}           SSH path is working"
               echo -e "     ${RED}UNRECOGNISED${NC}    the app sends a payload we do not parse"
               echo -e "     ${RED}(nothing)${NC}       traffic never reached the server at all"
               echo ""
               echo -e "   ${GREEN}Ctrl+C to stop watching.${NC}"
               hr
               mkdir -p /var/log/dajohn 2>/dev/null
               touch /var/log/dajohn/mux.log 2>/dev/null
               tail -n 25 -f /var/log/dajohn/mux.log
               read -n 1 -s -r -p "Press any key..." ;;
            89)
               /usr/local/bin/dajohn-udp-build
               systemctl restart udp-custom >/dev/null 2>&1
               sleep 1
               systemctl is-active --quiet udp-custom && echo -e "${GREEN}Rebuilt - udp-custom running.${NC}" || echo -e "${RED}udp-custom is down: journalctl -u udp-custom -n 20${NC}"
               read -n 1 -s -r -p "Press any key..." ;;
            *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
        esac
    done
}
# <<< DAJOHN-PART5-TUN <<<
EOF_P5MENU

# Category line + dispatch first, function second - same ordering reason part 4
# documents: the function body also contains "Tunnels & UDP" in its header, so
# injecting it first would let the guard below match the function and skip the
# line the user actually clicks.
#
# Anchor on part 4's [9] line when present so the entries stay in order, and
# fall back to [8] on a box where part 4 was never run.
if ! grep -q '\[10\].*Tunnels & UDP' /usr/local/bin/menu; then
    if grep -q '\[9\].*Advanced Integrations' /usr/local/bin/menu; then
        sed -i '/\[9\].*Advanced Integrations/a\        echo -e "   ${GREEN}[10] 🌐 Tunnels \& UDP${NC}"' /usr/local/bin/menu
    else
        sed -i '/\[8\].*System & Settings/a\        echo -e "   ${GREEN}[10] 🌐 Tunnels \& UDP${NC}"' /usr/local/bin/menu
    fi
fi
if ! grep -q "10) submenu_tunnels ;;" /usr/local/bin/menu; then
    if grep -q "9) submenu_advanced ;;" /usr/local/bin/menu; then
        sed -i '/9) submenu_advanced ;;/a\            10) submenu_tunnels ;;' /usr/local/bin/menu
    else
        sed -i '/8) submenu_system ;;/a\            10) submenu_tunnels ;;' /usr/local/bin/menu
    fi
fi

if grep -q '^show_menu() {' /usr/local/bin/menu; then
    sed -i '/^show_menu() {/e cat /tmp/p5_menu.txt' /usr/local/bin/menu
else
    warn "could not find show_menu() in the menu - tunnels submenu not injected."
fi
rm -f /tmp/p5_menu.txt

# A broken menu locks you out of the whole panel, so verify and roll back.
if bash -n /usr/local/bin/menu 2>/dev/null; then
    echo -e "${BGreen}[ OK ] Menu patched - option [10] Tunnels & UDP.${NC}"
else
    cp -f /usr/local/bin/menu.pre-part5 /usr/local/bin/menu
    warn "menu patch produced invalid syntax - rolled back, option 10 unavailable."
fi
fi

# ==========================================
# 6. SUMMARY
# ==========================================
clear
echo -e "${BCyan}======================================================${NC}"
echo -e "${BPurple}   PART 5 COMPLETE - TUNNELS & UDP                    ${NC}"
echo -e "${BCyan}======================================================${NC}"

chk(){ systemctl is-active --quiet "$2" 2>/dev/null \
    && printf "  %-16s ${BGreen}%s${NC}\n" "$1" "running" \
    || printf "  %-16s ${BRed}%s${NC}\n" "$1" "STOPPED"; }

echo -e "\n${BYellow}[ SERVICES ]${NC}"
chk "SlowDNS"       "slowdns"
chk "SlowDNS mux"   "dajohn-mux"
chk "UDP-Custom"    "udp-custom"
chk "Hysteria 2"    "hysteria-server"
chk "Xray"          "xray"
chk "Nginx"         "nginx"

echo -e "\n${BYellow}[ MODES ]${NC}"
echo -e "  SlowDNS       : ${BGreen}$(cat /etc/dajohn/core/slowdns_mode.txt 2>/dev/null || echo 'not set')${NC}"
echo -e "  Reality front : ${BGreen}$(cat /etc/dajohn/core/reality_dest.txt 2>/dev/null || echo 'www.google.com (harden with menu 82)')${NC}"
echo -e "  Hysteria obfs : ${BGreen}$(cat /etc/dajohn/core/hy2_obfs.txt 2>/dev/null || echo 'not set')${NC}"

echo -e "\n${BYellow}[ PORTS ]${NC}"
for p in 53:udp 36712:udp 443:tcp 4433:tcp; do
    P="${p%%:*}"; T="${p##*:}"; F="-tln"; [ "$T" = "udp" ] && F="-uln"
    ss $F 2>/dev/null | grep -qE "[:.]${P}([^0-9]|\$)" \
        && printf "  %-4s %-6s ${BGreen}OPEN${NC}\n" "$T" "$P" \
        || printf "  %-4s %-6s ${BRed}CLOSED${NC}\n" "$T" "$P"
done
ss -tln 2>/dev/null | grep -qE '[:.]2222([^0-9]|$)' \
    && printf "  %-4s %-6s ${BGreen}OPEN${NC}  (dajohn-mux, loopback)\n" "tcp" "2222" \
    || printf "  %-4s %-6s ${BYellow}closed${NC} (dajohn-mux)\n" "tcp" "2222"

if [ -n "$WARNINGS" ]; then
    echo -e "\n${BYellow}[ WARNINGS ]${NC}${BYellow}${WARNINGS}${NC}"
fi

echo -e "\n${BCyan}======================================================${NC}"
echo -e "  ${BGreen}New menu option [10] Tunnels & UDP${NC}"
echo -e "  ${BYellow}Next steps:${NC}"
echo -e "    menu -> 10 -> 84   V2Ray-over-SlowDNS client setup"
echo -e "    menu -> 10 -> 85   create a UDP-Custom account"
echo -e "    menu -> 10 -> 82   harden the Reality front"
echo -e "  ${BRed}Re-running part 2 or 3 wipes parts 4+5 - re-run both after.${NC}"
echo -e "${BCyan}======================================================${NC}"

