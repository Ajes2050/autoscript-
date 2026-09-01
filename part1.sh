#!/bin/bash
# ==========================================================
# ITZDAJOHN v5.4 TITAN EDITION - PART 1: CORE ENGINE
# ==========================================================

BRed='\033[1;31m'
BGreen='\033[1;32m'
BYellow='\033[1;33m'
BBlue='\033[1;34m'
BPurple='\033[1;35m'
BCyan='\033[1;36m'
NC='\033[0m'

clear
echo -e "${BCyan}======================================================${NC}"
echo -e "${BPurple}    INITIALIZING SYSTEM CHECKS... PLEASE WAIT         ${NC}"
echo -e "${BCyan}======================================================${NC}"

if [ "${EUID}" -ne 0 ]; then
    echo -e "${BRed}[CRITICAL ERROR] You must run this script as root!${NC}"
    exit 1
fi

# ==========================================================================
# LOW-RAM SWAP GUARANTEE — tiny VPSes (512MB/1GB) with no swap OOM-kill the
# dnstt `go build` in Part 2 and the panel fails silently at "Compiling
# SlowDNS". Detect low memory BEFORE any heavy work and add a 2G swapfile.
# Only acts when actually needed; never blocks the install on failure.
# ==========================================================================
MEM_KB=$(awk '/^MemTotal/{print $2}' /proc/meminfo)
SWAP_KB=$(awk '/^SwapTotal/{print $2}' /proc/meminfo)
# Ensure ~2G of swap on low-RAM boxes (512MB/1GB droplets) BEFORE the heavy
# dnstt `go build` in Part 2, which OOM-kills otherwise. Trigger on low RAM even
# when a tiny swap already exists (< 2G total), and VERIFY swapon actually took:
# a fallocate'd file can be silently rejected by the kernel, so fall back to dd
# and re-check /proc/meminfo instead of trusting the exit codes.
if [ -n "$MEM_KB" ] && [ "$MEM_KB" -lt 1572864 ] && [ "${SWAP_KB:-0}" -lt 2097152 ]; then
    echo -e "\n${BYellow}[*] Low memory (${MEM_KB} KB RAM, ${SWAP_KB:-0} KB swap) — ensuring a 2G swapfile...${NC}"
    if ! swapon --show 2>/dev/null | grep -q '/swapfile'; then
        [ -f /swapfile ] && { swapoff /swapfile 2>/dev/null; rm -f /swapfile; }
        fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none 2>/dev/null
        chmod 600 /swapfile
        mkswap /swapfile >/dev/null 2>&1
        # If swapon fails (fallocate file rejected on some filesystems), rebuild with dd and retry.
        if ! swapon /swapfile 2>/dev/null; then
            rm -f /swapfile
            dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none 2>/dev/null
            chmod 600 /swapfile; mkswap /swapfile >/dev/null 2>&1; swapon /swapfile 2>/dev/null
        fi
        grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    NOW_SWAP=$(awk '/^SwapTotal/{print $2}' /proc/meminfo)
    if [ "${NOW_SWAP:-0}" -ge 1048576 ]; then
        echo -e "${BGreen}[ OK ] Swap active: ${NOW_SWAP} KB.${NC}"
    else
        echo -e "${BYellow}[!] Could not enable swap (${NOW_SWAP:-0} KB) — the SlowDNS build may be tight; continuing.${NC}"
    fi
fi

echo -e "${BYellow}[*] Disabling interactive pop-ups to prevent freezing...${NC}"
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
sed -i 's/#$nrconf{restart} = '"'"'i'"'"';/$nrconf{restart} = '"'"'a'"'"';/g' /etc/needrestart/needrestart.conf 2>/dev/null

echo -e "\n${BYellow}[*] Disabling systemd-resolved to free Port 53...${NC}"
systemctl stop systemd-resolved >/dev/null 2>&1
systemctl disable systemd-resolved >/dev/null 2>&1
rm -f /etc/resolv.conf
echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" > /etc/resolv.conf

fun_bar() {
    CMD[0]="$1"
    CMD[1]="$2"
    (
        [[ -e $HOME/dajohn.log ]] && rm $HOME/dajohn.log
        DEBIAN_FRONTEND=noninteractive ${CMD[0]} -y -q -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" < /dev/null >/dev/null 2>&1
        if [ -n "${CMD[1]}" ]; then
            DEBIAN_FRONTEND=noninteractive ${CMD[1]} -y -q -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" < /dev/null >/dev/null 2>&1
        fi
        touch $HOME/dajohn.log
    ) >/dev/null 2>&1 &

    tput civis
    echo -ne "  ${BYellow}Processing...${NC} "
    while true; do
        for ((i = 0; i < 18; i++)); do echo -ne "${BCyan}█${NC}"; sleep 0.1; done
        if [[ -e $HOME/dajohn.log ]]; then
            rm $HOME/dajohn.log
            echo -e " ${BGreen}[ DONE ]${NC}"
            tput cnorm
            break
        fi
        echo -ne "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b"
        for ((i = 0; i < 18; i++)); do echo -ne " "; sleep 0.05; done
        echo -ne "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b"
    done
}

clear
echo -e "${BCyan}======================================================${NC}"
echo -e "${BPurple}            ITZDAJOHN CONFIGURATION              ${NC}"
echo -e "${BCyan}======================================================${NC}"

# Detect the public IP up front so we have a resolvable fallback hostname ready
# BEFORE prompting. <ip>.nip.io resolves straight back to the IP via free
# wildcard DNS, so certbot/nginx/hysteria all get a real name to work with.
EARLY_IP=$(curl -s -m5 -4 ipv4.icanhazip.com 2>/dev/null | tr -d '[:space:]')
[ -z "$EARLY_IP" ] && EARLY_IP=$(curl -s -m5 -4 ifconfig.me 2>/dev/null | tr -d '[:space:]')
[ -z "$EARLY_IP" ] && EARLY_IP=$(curl -s -m5 -4 https://api.ipify.org 2>/dev/null | tr -d '[:space:]')
[ -n "$EARLY_IP" ] && AUTO_DOMAIN="${EARLY_IP}.nip.io"

echo -e " ${BYellow}No domain? Just press Enter — one is auto-generated from your IP.${NC}"
echo -e " ${BYellow}You can set a real domain later from the menu (option 23).${NC}"
[ -n "$AUTO_DOMAIN" ] && echo -e " ${BCyan}Auto domain if blank: ${AUTO_DOMAIN}${NC}"
echo ""

# Non-blocking prompts: only prompt when stdin is a real terminal, and even then
# time out after 60s. Run over SSH without a TTY (no -t) the reads used to hang
# forever at "ITZDAJOHN CONFIGURATION" — this is the freeze. Now: no TTY or no
# answer => fall through to the auto values below.
DOMAIN=""
NS_DOMAIN=""
if [ -n "${DAJOHN_DOMAIN:-}" ]; then
    # Launcher collected these up front (silent-install path) — prefer them
    # over the interactive prompt so nothing has to be typed mid-install.
    DOMAIN="${DAJOHN_DOMAIN:-}"
    NS_DOMAIN="${DAJOHN_NS:-}"
elif [ -t 0 ]; then
    read -t 60 -p " Enter your Domain Name (blank = auto)    : " DOMAIN || true
    read -t 60 -p " Enter SlowDNS Nameserver (blank to skip) : " NS_DOMAIN || true
else
    echo -e " ${BYellow}[*] No terminal attached — using auto domain, no SlowDNS NS.${NC}"
fi
DOMAIN="${DOMAIN// /}"
NS_DOMAIN="${NS_DOMAIN// /}"

# Blank domain => the resolvable <ip>.nip.io hostname (real IP fallback if even
# that failed). Set the real domain later with menu option 23 (Update Domain).
if [ -z "$DOMAIN" ]; then
    DOMAIN="${AUTO_DOMAIN:-$EARLY_IP}"
    echo -e " ${BYellow}[*] Using auto domain: ${BCyan}${DOMAIN}${NC}"
fi

echo -e "\n${BYellow}[*] Building Itzdajohn Directory Structure...${NC}"
mkdir -p /etc/dajohn/core /etc/dajohn/data /etc/dajohn/modules /var/log/dajohn /etc/xray

echo -e "\n${BCyan}[*] Installing Backend Core Dependencies...${NC}"
echo -ne " updating system repos  "; fun_bar "apt-get update" "apt-get upgrade"
echo -ne " installing compilers   "; fun_bar "apt-get install build-essential git cmake golang" ""
# qrencode (QR codes in menu) + at (short trial accounts)
echo -ne " installing core tools  "; fun_bar "apt-get install curl wget jq uuid-runtime psmisc qrencode at" ""
echo -ne " installing networking  "; fun_bar "apt-get install iptables ufw net-tools" ""
systemctl enable --now atd >/dev/null 2>&1

# Enable Google BBR congestion control + network tuning (big throughput win on tunnels).
# Written to a dedicated sysctl.d file so it's idempotent on re-runs.
echo -e "\n${BYellow}[*] Enabling BBR & network tuning...${NC}"
cat <<EOF > /etc/sysctl.d/99-dajohn.conf
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.core.rmem_max=67108864
net.core.wmem_max=67108864
# Without the tcp_rmem/tcp_wmem arrays, TCP autotuning caps the window at the
# small kernel default no matter how big rmem_max/wmem_max are - so on a
# high-latency tunnel the download ramps up then plateaus well below the link.
# The 3rd value is the ceiling autotuning may grow to (max = rmem_max/wmem_max).
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_notsent_lowat=131072
# UDP throughput: the kernel defaults for udp_mem and netdev_max_backlog are far
# too low for the bandwidth udp-custom pushes. Without these, inbound UDP packets
# are silently dropped at the kernel level well before the app sees them, capping
# throughput around 10 Mbps on a link that can do 10x that.
net.core.netdev_max_backlog=10000
net.core.optmem_max=25165824
net.ipv4.udp_mem=786432 1048576 26777216
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
# SlowDNS/ZIVPN is a long-lived UDP flow on :53. The kernel default evicts an
# idle UDP conntrack entry after 120s (udp_timeout_stream) / 30s (udp_timeout),
# so a quiet tunnel drops and re-handshakes on a fixed ~2-min cycle. Widen both
# so the flow survives normal idle gaps.
net.netfilter.nf_conntrack_udp_timeout=60
net.netfilter.nf_conntrack_udp_timeout_stream=600
EOF
# The nf_conntrack_* keys only exist once the module is loaded. Load it now (so
# sysctl --system below can set them) and persist it via modules-load.d so at
# boot systemd-modules-load brings it up BEFORE systemd-sysctl applies the file
# (systemd-sysctl is ordered After=systemd-modules-load) - otherwise the two UDP
# timeouts get silently skipped on every reboot and the ~2-min drop returns.
modprobe nf_conntrack 2>/dev/null
echo nf_conntrack > /etc/modules-load.d/dajohn-conntrack.conf
sysctl --system >/dev/null 2>&1
if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
    echo -e "${BGreen}[ OK ] BBR is active.${NC}"
else
    echo -e "${BYellow}[!] BBR not active yet (kernel may need a reboot).${NC}"
fi

# ==========================================================================
# dajohn-ip : single reliable public-IP helper used by Part 3 and the menu.
# FIX: every menu option used to call `curl -s ipv4.icanhazip.com` with NO
# timeout. When that hung or returned empty, links were generated with a
# blank host (vless://uuid@:443) and looked valid but could never connect.
# This helper always has a timeout and always falls back to env.conf.
# ==========================================================================
cat << 'EOF_IP' > /usr/local/bin/dajohn-ip
#!/bin/bash
IP=$(curl -s -m5 -4 ipv4.icanhazip.com 2>/dev/null | tr -d '[:space:]')
[ -z "$IP" ] && IP=$(curl -s -m5 -4 ifconfig.me 2>/dev/null | tr -d '[:space:]')
[ -z "$IP" ] && IP=$(curl -s -m5 -4 https://api.ipify.org 2>/dev/null | tr -d '[:space:]')
[ -z "$IP" ] && IP=$(. /etc/dajohn/core/env.conf 2>/dev/null; echo "$VPS_IP")
echo "$IP"
EOF_IP
chmod +x /usr/local/bin/dajohn-ip

# curl is guaranteed installed BEFORE we call it, so VPS_IP is never empty.
# Reuse the IP we already detected above; only re-probe if that came back empty.
echo -e "\n${BYellow}[*] Detecting public IP address...${NC}"
VPS_IP="${EARLY_IP:-$(/usr/local/bin/dajohn-ip)}"
[ -z "$VPS_IP" ] && echo -e "${BRed}[WARN] Could not auto-detect public IP. Edit /etc/dajohn/core/env.conf manually.${NC}"

# DOMAIN was already resolved at the prompt (real entry, <ip>.nip.io, or IP).
# Last-ditch guard: if it is somehow still empty, use the IP so no part breaks.
[ -z "$DOMAIN" ] && DOMAIN="$VPS_IP"

cat <<EOF > /etc/dajohn/core/env.conf
DOMAIN="$DOMAIN"
NS_DOMAIN="$NS_DOMAIN"
VPS_IP="$VPS_IP"
EOF

clear
echo -e "${BGreen}======================================================${NC}"
echo -e "${BPurple}   PART 1 COMPLETE: FOUNDATION LAID SUCCESSFULLY      ${NC}"
echo -e "${BGreen}======================================================${NC}"
echo -e "  Domain : ${BCyan}${DOMAIN}${NC}"
echo -e "  NS     : ${BCyan}${NS_DOMAIN}${NC}"
echo -e "  IP     : ${BCyan}${VPS_IP:-NOT DETECTED}${NC}"
echo -e "${BGreen}======================================================${NC}"
echo -e "  Next: ${BYellow}bash /root/part2.sh${NC}"
