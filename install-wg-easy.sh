#!/usr/bin/env bash
# install-wg-easy.sh - Quiet, logged, interactive (TUI-capable) installer for WireGuard + wg-easy (Docker)
# behind Caddy/Let's Encrypt on Debian 13. Includes unattended-upgrades, fail2ban, UFW,
# explicit HTTP→HTTPS redirect, full pre/post-flight checks, percentage progress bar,
# optional whiptail TUI, autostart for all services + compose stack, and a full logfile.
#
# Copyright (C) 2025 LINUXexpert.org
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/>.

set -Eeuo pipefail

# ===== Formatting / Helpers =====
RED=$'\e[31m'; GRN=$'\e[32m'; BLU=$'\e[34m'; YLW=$'\e[33m'; BLD=$'\e[1m'; DIM=$'\e[2m'; CLR=$'\e[0m'
err()  { printf "%s[ERROR]%s %s\n" "$RED" "$CLR" "$*" >&3; }
ok()   { printf "%s[OK]%s    %s\n" "$GRN" "$CLR" "$*" >&3; }
info() { printf "%s[INFO]%s  %s\n" "$BLU" "$CLR" "$*" >&3; }
warn() { printf "%s[WARN]%s  %s\n" "$YLW" "$CLR" "$*" >&3; }

require_root() { [[ $EUID -eq 0 ]] || { err "Please run as root (sudo)."; exit 1; }; }

check_debian13() {
  if ! command -v lsb_release &>/dev/null; then apt-get update -y >/dev/null 2>&1 && apt-get install -y lsb-release >/dev/null 2>&1; fi
  local dist ver; dist=$(lsb_release -is 2>/dev/null || echo Debian); ver=$(lsb_release -rs 2>/dev/null || echo "13")
  [[ "$dist" == "Debian" ]] || { err "This script targets Debian. Detected: $dist"; exit 1; }
  [[ "${ver%%.*}" -ge 12 ]] || { err "Detected Debian $ver. Use Debian 12+ (targets Debian 13)."; exit 1; }
}

# ===== Console I/O helpers (FD3 prints, /dev/tty reads) =====
ask() {  # ask "Prompt" var [default]
  local prompt="$1" __var="$2" def="${3-}" reply
  if [[ -n "$def" ]]; then printf "%s [default: %s] " "$prompt" "$def" >&3; else printf "%s " "$prompt" >&3; fi
  IFS= read -r reply < /dev/tty
  [[ -z "$reply" && -n "$def" ]] && reply="$def"
  printf -v "$__var" "%s" "$reply"
}
ask_req() { local prompt="$1" __var="$2" def="${3-}"; while true; do ask "$prompt" "$__var" "$def"; [[ -n "${!__var}" ]] && break; printf "(value required)\n" >&3; done; }
ask_secret() {
  local prompt="$1" __var="$2" secret
  printf "%s" "$prompt" >&3; stty -echo < /dev/tty; IFS= read -r secret < /dev/tty; stty echo < /dev/tty; printf "\n" >&3
  while [[ -z "$secret" ]]; do printf "(value required) %s" "$prompt" >&3; stty -echo < /dev/tty; IFS= read -r secret < /dev/tty; stty echo < /dev/tty; printf "\n" >&3; done
  printf -v "$__var" "%s" "$secret"
}

# ===== Optional TUI (whiptail) =====
WT=0
wt_yesno()   { whiptail --title "$1" --yesno "$2" 10 72; }
wt_input()   { local out; out=$(whiptail --title "$1" --inputbox "$2" 10 72 "$3" 3>&1 1>&2 2>&3) || return 1; printf "%s" "$out"; }
wt_password(){ local out; out=$(whiptail --title "$1" --passwordbox "$2" 10 72 3>&1 1>&2 2>&3) || return 1; printf "%s" "$out"; }
tui_or_cli_prompts() {
  if (( WT == 1 )); then
    WG_DOMAIN=$(wt_input "wg-easy Domain" "Enter the domain for the wg-easy web UI:" "") || exit 1
    while [[ -z "$WG_DOMAIN" ]]; do WG_DOMAIN=$(wt_input "Required" "Domain cannot be empty:" "") || exit 1; done
    LE_EMAIL=$(wt_input "Let's Encrypt Email" "Email for ACME/Notices:" "") || exit 1
    while [[ -z "$LE_EMAIL" ]]; do LE_EMAIL=$(wt_input "Required" "Email cannot be empty:" "") || exit 1; done
    if wt_yesno "ACME Mode" "Use Let's Encrypt STAGING (test-only)?" ; then ACME_CA="https://acme-staging-v02.api.letsencrypt.org/directory"; else ACME_CA="https://acme-v02.api.letsencrypt.org/directory"; fi
    WG_HOST=$(wt_input "Public Hostname/IP" "Hostname or IP clients will reach:" "$WG_DOMAIN") || exit 1
    WG_PORT=$(wt_input "WireGuard UDP Port" "UDP port for WireGuard:" "51820") || exit 1
    WG_EASY_PORT=$(wt_input "wg-easy UI Port" "Local-only UI port:" "51821") || exit 1
    WG_DEFAULT_ADDRESS=$(wt_input "Tunnel Subnet" "IPv4 CIDR for tunnel:" "10.8.0.0/24") || exit 1
    WG_DEFAULT_DNS=$(wt_input "Client DNS" "Comma-separated DNS for clients:" "1.1.1.1,9.9.9.9") || exit 1
    if wt_yesno "IPv6 Forwarding" "Enable IPv6 forwarding for WireGuard?" ; then ENABLE_IPV6="Y"; else ENABLE_IPV6="N"; fi
    if wt_yesno "Basic Auth" "Protect UI with Basic Auth (Caddy)?" ; then
      ENABLE_BASICAUTH="Y"
      BASIC_USER=$(wt_input "Basic Auth User" "Username for Basic Auth:" "admin") || exit 1
      BASIC_PASS=$(wt_password "Basic Auth Password" "Enter Basic Auth password:") || exit 1
      while [[ -z "$BASIC_PASS" ]]; do BASIC_PASS=$(wt_password "Required" "Password cannot be empty:") || exit 1; done
    else ENABLE_BASICAUTH="N"; fi
    WGEASY_ADMIN_PASS=$(wt_password "wg-easy Admin Password" "Password for wg-easy UI:") || exit 1
    while [[ -z "$WGEASY_ADMIN_PASS" ]]; do WGEASY_ADMIN_PASS=$(wt_password "Required" "Password cannot be empty:") || exit 1; done
    IP_ALLOW_CIDR=$(wt_input "UI Allowlist (optional)" "CIDR allowed to UI (blank = none):" "") || exit 1
    if wt_yesno "Firewall" "Install & enable UFW (22/tcp, 80/tcp, 443/tcp, ${WG_PORT}/udp)?" ; then ENABLE_UFW="Y"; else ENABLE_UFW="N"; fi
    if wt_yesno "Unattended Upgrades" "Enable unattended security updates?" ; then
      ENABLE_AUTOUPD="Y"
      if wt_yesno "Upgrade Emails" "Send email notifications for unattended upgrades?" ; then
        UPD_MAIL=$(wt_input "Email" "Address to notify:" "$LE_EMAIL") || exit 1
      else UPD_MAIL=""; fi
    else ENABLE_AUTOUPD="N"; UPD_MAIL=""; fi
    if wt_yesno "fail2ban" "Install & configure fail2ban (sshd + Caddy)?" ; then
      ENABLE_F2B="Y"
      F2B_BANTIME=$(wt_input "fail2ban bantime" "e.g., 1h, 6h, 24h:" "1h") || exit 1
      F2B_FINDTIME=$(wt_input "fail2ban findtime" "e.g., 10m, 15m:" "10m") || exit 1
      F2B_MAXRETRY=$(wt_input "fail2ban maxretry" "e.g., 5:" "5") || exit 1
    else ENABLE_F2B="N"; F2B_BANTIME="1h"; F2B_FINDTIME="10m"; F2B_MAXRETRY="5"; fi
    if wt_yesno "Autostart Compose" "Create a systemd unit to re-up wg-easy on boot?" ; then ENABLE_COMPOSE_UNIT="Y"; else ENABLE_COMPOSE_UNIT="N"; fi
  else
    ask_req "Domain for the wg-easy web UI (e.g., vpn.example.com):" WG_DOMAIN
    ask_req "Email for Let's Encrypt / Caddy (TLS notices):" LE_EMAIL
    ask "Use Let's Encrypt STAGING for first issuance (test-only)? [y/N]:" LE_STAGING "N"
    [[ "$LE_STAGING" =~ ^[Yy]$ ]] && ACME_CA="https://acme-staging-v02.api.letsencrypt.org/directory" || ACME_CA="https://acme-v02.api.letsencrypt.org/directory"
    ask "Public hostname/IP clients will reach:" WG_HOST "$WG_DOMAIN"
    ask "WireGuard UDP listen port:" WG_PORT "51820"
    ask "wg-easy UI port (local only):" WG_EASY_PORT "51821"
    ask "Default tunnel subnet (IPv4 CIDR):" WG_DEFAULT_ADDRESS "10.8.0.0/24"
    ask "Default DNS server(s), comma-separated:" WG_DEFAULT_DNS "1.1.1.1,9.9.9.9"
    ask "Enable IPv6 forwarding for WireGuard? [y/N]:" ENABLE_IPV6 "N"
    ask "Protect the UI with Basic Auth via Caddy? [y/N]:" ENABLE_BASICAUTH "N"
    BASIC_USER=""; BASIC_PASS=""
    if [[ "$ENABLE_BASICAUTH" =~ ^[Yy]$ ]]; then ask "Basic Auth username:" BASIC_USER "admin"; ask_secret "Basic Auth password:" BASIC_PASS; fi
    ask_secret "wg-easy admin password:" WGEASY_ADMIN_PASS
    ask "Restrict UI to IP/CIDR (blank = none):" IP_ALLOW_CIDR ""
    ask "Install & enable UFK (22/tcp, 80/tcp, 443/tcp, ${WG_PORT}/udp)? [Y/n]:" ENABLE_UFW "Y"
    ask "Enable unattended security updates? [Y/n]:" ENABLE_AUTOUPD "Y"
    UPD_MAIL=""; if [[ "$ENABLE_AUTOUPD" =~ ^[Yy]$ ]]; then ask "Email notifications for upgrades? (blank = none):" UPD_MAIL "$LE_EMAIL"; fi
    ask "Install & configure fail2ban (sshd + Caddy)? [Y/n]:" ENABLE_F2B "Y"
    F2B_BANTIME="1h"; F2B_FINDTIME="10m"; F2B_MAXRETRY="5"
    if [[ "$ENABLE_F2B" =~ ^[Yy]$ ]]; then
      ask "fail2ban bantime:" F2B_BANTIME "$F2B_BANTIME"
      ask "fail2ban findtime:" F2B_FINDTIME "$F2B_FINDTIME"
      ask "fail2ban maxretry:" F2B_MAXRETRY "$F2B_MAXRETRY"
    fi
    ask "Create a systemd unit to re-up wg-easy on boot? [Y/n]:" ENABLE_COMPOSE_UNIT "Y"
  fi
}

# ===== Progress bar =====
STEP_NUM=0; STEP_MAX=0; BAR_WIDTH=42
repeat_char() { local n=$1 c="$2"; [[ $n -le 0 ]] && return 0; printf "%0.s${c}" $(seq 1 "$n"); }
draw_bar()   { local pct=$1; (( pct<0 )) && pct=0; (( pct>100 )) && pct=100; local filled=$(( pct * BAR_WIDTH / 100 )); printf "\r[%-*s] %3d%%" "$BAR_WIDTH" "$(repeat_char "$filled" "#")" "$pct" >&3; }
advance_bar(){
  STEP_NUM=$((STEP_NUM+1))
  (( STEP_MAX < 1 )) && STEP_MAX=1
  local pct=$(( STEP_NUM * 100 / STEP_MAX ))
  draw_bar "$pct"
}

# ===== Step runner (safe printf) =====
run_step() {
  local title="$1"; shift
  printf "%s\n" "" >&3
  printf "%s\n" "Step $((STEP_NUM+1))/$STEP_MAX: $title" >&3
  {
    printf "%s\n" "--- [$(date -Is)] $title ---" >&2
    bash -o pipefail -c "$@" >&2
    printf "%s\n" "--- [$(date -Is)] $title (OK) ---" >&2
  }
  advance_bar
}

# ===== Trap & Logging =====
cleanup_on_error(){ printf "\n" >&3; err "An unexpected error occurred. See the log: $LOGFILE"; }
trap cleanup_on_error ERR

LOGFILE="$(pwd)/install-wg-easy-$(date +%Y%m%d-%H%M%S).log"
exec 3>&1
exec > >(tee -a "$LOGFILE") 2>&1
export DEBIAN_FRONTEND=noninteractive
APTQ="-o Dpkg::Use-Pty=0 -y -qq"

require_root
check_debian13

# ===== Minimal prereqs for prompts & optional TUI =====
info "Installer log: $LOGFILE"
apt-get update -qq >/dev/null 2>&1 || true
apt-get install $APTQ ca-certificates gnupg apt-transport-https curl iproute2 dnsutils jq apache2-utils openssl whiptail >/dev/null 2>&1 || true

# TUI choice
if command -v whiptail >/dev/null 2>&1; then
  if whiptail --title "Interface" --yesno "Use TUI (whiptail) for prompts?" 9 60; then WT=1; else WT=0; fi
fi

# Detect public IPs (best-effort)
detect_pubip() { local v="$1" ip=""; case "$v" in 4) ip=$(curl -fsS4 --max-time 5 https://ifconfig.me || true);; 6) ip=$(curl -fsS6 --max-time 5 https://ifconfig.me || true);; esac; [[ -n "$ip" ]] && echo "$ip" || echo "UNKNOWN"; }
PUBIP4=$(detect_pubip 4); PUBIP6=$(detect_pubip 6)

# ===== Prompts =====
printf "\n%s=== WireGuard + wg-easy (Docker) behind Caddy/Let's Encrypt (Debian 13) ===%s\n\n" "$BLD" "$CLR" >&3
tui_or_cli_prompts

printf "\n" >&3
info "Detected public IPs: IPv4=${PUBIP4}, IPv6=${PUBIP6}"

# DNS preflight
DNS_OK="UNKNOWN"; DNS_MATCH_IP="NO"
A_RECORDS=$(dig +short A "$WG_DOMAIN" || true); AAAA_RECORDS=$(dig +short AAAA "$WG_DOMAIN" || true)
if [[ -n "$A_RECORDS$AAAA_RECORDS" ]]; then
  DNS_OK="YES"
  if [[ "$A_RECORDS" == *"$PUBIP4"* ]] || { [[ "$PUBIP6" != "UNKNOWN" ]] && [[ "$AAAA_RECORDS" == *"$PUBIP6"* ]]; }; then DNS_MATCH_IP="YES"; fi
else DNS_OK="NO"; fi
info "DNS for ${WG_DOMAIN}: found=${DNS_OK}, points-here=${DNS_MATCH_IP}"
[[ "$DNS_OK" == "YES" ]] || warn "No A/AAAA records found. ACME issuance will fail until DNS is configured."

# Confirm
if (( WT )); then
  wt_yesno "Confirm" "Proceed with installation?" || { err "Aborted by user."; exit 1; }
else
  ask "Proceed with installation? [Y/n]:" CONFIRM "Y"; [[ "$CONFIRM" =~ ^[Yy]$ ]] || { err "Aborted by user."; exit 1; }
fi

# Port preflight
port_in_use() { ss -plntu 2>/dev/null | grep -E "LISTEN|UNCONN" | grep -qE "[:.]$1(\s|$)"; }
if port_in_use 80 || port_in_use 443; then
  warn "Ports 80/443 appear in use. Caddy may fail. Showing listeners:"; ss -plnt | awk 'NR==1 || /:80 |:443 / {print}' >&3
  if (( WT )); then wt_yesno "Ports busy" "Continue anyway?" || { err "Please free 80/443 and re-run."; exit 1; }
  else ask "Continue anyway? [y/N]:" cont_p "N"; [[ "$cont_p" =~ ^[Yy]$ ]] || { err "Please free 80/443 and re-run."; exit 1; }; fi
fi
if ss -plnu | grep -qE "[:.]${WG_PORT}(\s|$)"; then
  warn "UDP port ${WG_PORT} already in use." >&3
  if (( WT )); then wt_yesno "UDP busy" "Continue anyway?" || { err "Please free UDP ${WG_PORT} and re-run."; exit 1; }
  else ask "Continue anyway? [y/N]:" cont_w "N"; [[ "$cont_w" =~ ^[Yy]$ ]] || { err "Please free UDP ${WG_PORT} and re-run."; exit 1; }; fi
fi

# ===== STEP_MAX calculation (procedural; no division by zero) =====
STEP_MAX=0
# 1 Update/base tools
STEP_MAX=$((STEP_MAX+1))
# 2 sysctl forwarding
STEP_MAX=$((STEP_MAX+1))
# 3 Docker Engine
STEP_MAX=$((STEP_MAX+1))
# 4 docker compose plugin
STEP_MAX=$((STEP_MAX+1))
# 5 Caddy
STEP_MAX=$((STEP_MAX+1))
# 6 wg-easy deployment files
STEP_MAX=$((STEP_MAX+1))
# 7 Caddyfile
STEP_MAX=$((STEP_MAX+1))
# optional: UFW
if [[ "$ENABLE_UFW" =~ ^[Yy]$ ]]; then STEP_MAX=$((STEP_MAX+1)); fi
# optional: unattended-upgrades
if [[ "$ENABLE_AUTOUPD" =~ ^[Yy]$ ]]; then STEP_MAX=$((STEP_MAX+1)); fi
# optional: fail2ban
if [[ "$ENABLE_F2B" =~ ^[Yy]$ ]]; then STEP_MAX=$((STEP_MAX+1)); fi
# 11 launch wg-easy
STEP_MAX=$((STEP_MAX+1))
# optional: compose autostart unit
if [[ "${ENABLE_COMPOSE_UNIT:-Y}" =~ ^[Yy]$ ]]; then STEP_MAX=$((STEP_MAX+1)); fi
# 12 reload caddy
STEP_MAX=$((STEP_MAX+1))

APP_DIR="/opt/wg-easy"
CONFIG_DIR="$APP_DIR/config"
CADDYFILE="/etc/caddy/Caddyfile"
ACCESS_LOG_DIR="/var/log/caddy"
COMPOSE_UNIT="/etc/systemd/system/wg-easy-compose.service"

printf "\n" >&3; draw_bar 0

# 1) apt update & base tools
run_step "Update packages & base tools" "apt-get update -qq; apt-get install $APTQ ca-certificates gnupg apt-transport-https curl jq apache2-utils iproute2 dnsutils openssl"

# 2) sysctl forwarding
run_step "Configure IP forwarding" "cat > /etc/sysctl.d/99-wireguard-forwarding.conf <<EOF
net.ipv4.ip_forward=1
$([[ "$ENABLE_IPV6" =~ ^[Yy]$ ]] && echo 'net.ipv6.conf.all.forwarding=1')
EOF
sysctl --system >/dev/null"

# 3) Docker Engine (enable autostart)
run_step "Install & enable Docker Engine" "command -v docker >/dev/null || { curl -fsSL https://get.docker.com | sh; }; systemctl enable --now docker"

# 4) docker compose plugin
run_step "Install docker compose plugin" "docker compose version >/dev/null 2>&1 || apt-get install $APTQ docker-compose-plugin"

# 5) Caddy (enable autostart)
run_step "Install & enable Caddy" "
if ! command -v caddy >/dev/null; then
  apt-get install $APTQ debian-keyring debian-archive-keyring
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  echo 'deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq && apt-get install $APTQ caddy
fi
systemctl enable --now caddy
mkdir -p $ACCESS_LOG_DIR
chown -R caddy:caddy $ACCESS_LOG_DIR || true
"

# 6) wg-easy deployment files (bcrypt for wg-easy password)
WGEASY_PASS_HASH=$(htpasswd -nbB user "$WGEASY_ADMIN_PASS" | cut -d: -f2)
run_step "Create wg-easy deployment files" "
mkdir -p '$CONFIG_DIR'
cat > '$APP_DIR/.env' <<EOF
WG_HOST=$WG_HOST
PASSWORD_HASH=$WGEASY_PASS_HASH
WG_PORT=$WG_PORT
WG_DEFAULT_ADDRESS=$WG_DEFAULT_ADDRESS
WG_DEFAULT_DNS=$WG_DEFAULT_DNS
UI_TRAFFIC_STATS=true
EOF

cat > '$APP_DIR/compose.yaml' <<EOF
name: wg-easy
services:
  wg-easy:
    image: ghcr.io/wg-easy/wg-easy:latest
    container_name: wg-easy
    env_file:
      - .env
    volumes:
      - ./config:/etc/wireguard
    ports:
      - \"$WG_PORT:$WG_PORT/udp\"
      - \"127.0.0.1:$WG_EASY_PORT:$WG_EASY_PORT/tcp\"
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv6.conf.all.forwarding=1
    restart: unless-stopped
EOF
"

# 7) Caddyfile (no empty blocks; safe for allowlist/basicauth combos)
# Build optional snippets
CADDY_BASICAUTH_LINE=""
if [[ "$ENABLE_BASICAUTH" =~ ^[Yy]$ ]]; then
  BASIC_HASH=$( (caddy hash-password --plaintext "$BASIC_PASS" 2>/dev/null) || (htpasswd -nbB x "$BASIC_PASS" | cut -d: -f2) )
  CADDY_BASICAUTH_LINE=$'    basicauth /* {\n      '"$BASIC_USER"' '"$BASIC_HASH"$'\n    }\n'
fi

if [[ -n "$IP_ALLOW_CIDR" ]]; then
  SITE_BODY=$(cat <<EOS
  log {
    output file $ACCESS_LOG_DIR/access.log
    format json
  }
  header {
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    X-Content-Type-Options "nosniff"
    X-Frame-Options "SAMEORIGIN"
    Referrer-Policy "no-referrer"
    X-XSS-Protection "1; mode=block"
  }

  @allow_ips {
    remote_ip $IP_ALLOW_CIDR
  }

  handle {
    respond "Forbidden" 403
  }

  handle @allow_ips {
$CADDY_BASICAUTH_LINE    reverse_proxy 127.0.0.1:$WG_EASY_PORT
  }

  tls {
    protocols tls1.2 tls1.3
  }
EOS
)
else
  SITE_BODY=$(cat <<EOS
  log {
    output file $ACCESS_LOG_DIR/access.log
    format json
  }
  header {
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    X-Content-Type-Options "nosniff"
    X-Frame-Options "SAMEORIGIN"
    Referrer-Policy "no-referrer"
    X-XSS-Protection "1; mode=block"
  }

$CADDY_BASICAUTH_LINE  reverse_proxy 127.0.0.1:$WG_EASY_PORT

  tls {
    protocols tls1.2 tls1.3
  }
EOS
)
fi

run_step "Write Caddyfile with HTTP→HTTPS redirect & ACME" "
cat > '$CADDYFILE' <<EOF
{
  email $LE_EMAIL
  acme_ca $ACME_CA
}

http://$WG_DOMAIN {
  redir https://{host}{uri} 308
}

$WG_DOMAIN {
  encode gzip
$SITE_BODY
}
EOF
caddy validate --config '$CADDYFILE' >/dev/null
"

# 8) UFW (enable autostart)
if [[ "$ENABLE_UFW" =~ ^[Yy]$ ]]; then
  run_step "Configure UFW firewall (22/tcp, 80/tcp, 443/tcp, ${WG_PORT}/udp)" "
  apt-get install $APTQ ufw
  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow ${WG_PORT}/udp
  ufw --force enable || true
  systemctl enable --now ufw || true
  "
fi

# 9) unattended-upgrades (enable autostart)
if [[ "$ENABLE_AUTOUPD" =~ ^[Yy]$ ]]; then
  run_step "Enable unattended security updates" "
  apt-get install $APTQ unattended-upgrades apt-listchanges
  dpkg-reconfigure --priority=low unattended-upgrades >/dev/null || true
  cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'CFG'
Unattended-Upgrade::Origins-Pattern {
        \"origin=Debian,codename=\${distro_codename},label=Debian-Security\";
        \"origin=Debian,codename=\${distro_codename},label=Debian\";
};
Unattended-Upgrade::AutoFixInterruptedDpkg \"true\";
Unattended-Upgrade::MinimalSteps \"true\";
Unattended-Upgrade::InstallOnShutdown \"false\";
Unattended-Upgrade::Remove-Unused-Kernel-Packages \"true\";
Unattended-Upgrade::Remove-New-Unused-Dependencies \"true\";
Unattended-Upgrade::Remove-Unused-Dependencies \"true\";
Unattended-Upgrade::Automatic-Reboot \"true\";
Unattended-Upgrade::Automatic-Reboot-Time \"03:30\";
Unattended-Upgrade::OnlyOnACPower \"false\";
Unattended-Upgrade::Verbose \"true\";
CFG
  if [[ -n \"$UPD_MAIL\" ]]; then
    sed -i \"1 i Unattended-Upgrade::Mail \\\"$UPD_MAIL\\\";\" /etc/apt/apt.conf.d/50unattended-upgrades
    sed -i \"1 i Unattended-Upgrade::MailReport \\\"on-change\\\";\" /etc/apt/apt.conf.d/50unattended-upgrades
  fi
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'CFG'
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Download-Upgradeable-Packages \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
APT::Periodic::AutocleanInterval \"7\";
CFG
  systemctl enable --now unattended-upgrades >/dev/null
  systemctl restart unattended-upgrades >/dev/null || true
  "
fi

# 10) fail2ban (enable autostart)
if [[ "$ENABLE_F2B" =~ ^[Yy]$ ]]; then
  run_step "Install & enable fail2ban (sshd + Caddy)" "
  apt-get install $APTQ fail2ban
  systemctl enable --now fail2ban
  cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = $F2B_BANTIME
findtime = $F2B_FINDTIME
maxretry = $F2B_MAXRETRY
destemail = ${UPD_MAIL:-$LE_EMAIL}
sender = root@\$(hostname -f 2>/dev/null || hostname)
action = %(action_mwl)s

[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = %(sshd_log)s
backend = systemd

[caddy-httperrors]
enabled = true
port    = http,https
filter  = caddy-httperrors
logpath = $ACCESS_LOG_DIR/access.log
backend = auto
EOF
  mkdir -p /etc/fail2ban/filter.d
  cat > /etc/fail2ban/filter.d/caddy-httperrors.conf <<'EOF'
[Definition]
failregex = ^\{.*\"status\":(401|403).*\}$
ignoreregex =
EOF
  systemctl restart fail2ban
  "
fi

# 11) wg-easy compose: launch now
run_step "Launch wg-easy container" "
cd '$APP_DIR'
docker compose pull
docker compose up -d
"

# 12) (Optional) systemd unit to re-up compose stack on boot
if [[ "${ENABLE_COMPOSE_UNIT:-Y}" =~ ^[Yy]$ ]]; then
  run_step "Create & enable systemd unit for wg-easy compose (autostart)" "
cat > '$COMPOSE_UNIT' <<EOF
[Unit]
Description=wg-easy (docker compose)
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/docker compose -f $APP_DIR/compose.yaml up -d
ExecReload=/usr/bin/docker compose -f $APP_DIR/compose.yaml up -d
ExecStop=/usr/bin/docker compose -f $APP_DIR/compose.yaml down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now wg-easy-compose.service
"
fi

# 13) Reload Caddy
run_step "Reload Caddy (activate config)" "caddy validate --config '$CADDYFILE' && (systemctl reload caddy || systemctl restart caddy)"

# ===== Post-Install Sanity Checks =====
printf "\n\n%s=== Running sanity checks ===%s\n" "$BLD" "$CLR" >&3
checklist_ok=0; checklist_fail=0
check(){ local desc="$1"; shift; if bash -c "$@" >/dev/null 2>&1; then ok "$desc"; ((checklist_ok++)); else warn "$desc - needs attention"; ((checklist_fail++)); fi; }

check "IPv4 forwarding enabled" 'sysctl -n net.ipv4.ip_forward | grep -q "^1$"'
[[ "$ENABLE_IPV6" =~ ^[Yy]$ ]] && check "IPv6 forwarding enabled" 'sysctl -n net.ipv6.conf.all.forwarding | grep -q "^1$"'
check "Docker enabled & active" 'systemctl is-enabled docker >/dev/null && systemctl is-active --quiet docker'
check "Caddy enabled & active" 'systemctl is-enabled caddy >/dev/null && systemctl is-active --quiet caddy'
check "wg-easy container running" 'docker ps --format "{{.Names}}" | grep -q "^wg-easy$"'
check "WireGuard UDP listening on :${WG_PORT}" 'ss -plnu | grep -q ":${WG_PORT} "'
check "Caddy listening on :80 and :443" 'ss -plnt | grep -q ":80 " && ss -plnt | grep -q ":443 "'
check "wg-easy UI bound to loopback :${WG_EASY_PORT}" 'ss -plnt | grep -q "127.0.0.1:${WG_EASY_PORT} "'
if [[ "${ENABLE_COMPOSE_UNIT:-Y}" =~ ^[Yy]$ ]]; then
  check "wg-easy compose unit enabled" 'systemctl is-enabled wg-easy-compose.service >/dev/null'
fi
if [[ "$ENABLE_UFW" =~ ^[Yy]$ ]]; then
  check "UFW enabled & allows 80/443 and ${WG_PORT}/udp" 'systemctl is-enabled ufw >/dev/null && ufw status | grep -q "80/tcp" && ufw status | grep -q "443/tcp" && ufw status | grep -q "${WG_PORT}/udp"'
fi
if [[ "$ENABLE_F2B" =~ ^[Yy]$ ]]; then
  check "fail2ban enabled & active" 'systemctl is-enabled fail2ban >/dev/null && systemctl is-active --quiet fail2ban'
fi
if [[ "$ENABLE_AUTOUPD" =~ ^[Yy]$ ]]; then
  check "unattended-upgrades enabled & active" 'systemctl is-enabled unattended-upgrades >/dev/null && systemctl is-active --quiet unattended-upgrades'
fi

# HTTP->HTTPS redirect verification
REDIR_OUT=$(curl -sI "http://$WG_DOMAIN/" || true)
REDIR_CODE=$(printf "%s" "$REDIR_OUT" | awk '/^HTTP/{print $2; exit}')
REDIR_LOC=$(printf "%s" "$REDIR_OUT" | awk '/^Location:/ {print $2; exit}' | tr -d '\r')
if [[ "$REDIR_CODE" =~ ^30[18]$ ]] && [[ "$REDIR_LOC" == "https://$WG_DOMAIN/"* ]]; then
  ok "HTTP→HTTPS redirect in place (${REDIR_CODE} to ${REDIR_LOC})"
else
  warn "HTTP→HTTPS redirect not confirmed (code=$REDIR_CODE, location=$REDIR_LOC)"
fi

# HTTPS reachability & cert info (best-effort)
TLS_OK=0
if [[ "$DNS_MATCH_IP" == "YES" && "$ACME_CA" != *"staging"* ]]; then
  if curl -fsS --max-time 20 "https://${WG_DOMAIN}/" -o /dev/null; then ok "HTTPS reachable at https://${WG_DOMAIN}/"; TLS_OK=1; else warn "HTTPS not reachable yet (DNS/ACME may be pending)."; fi
else
  [[ "$ACME_CA" == *"staging"* ]] && warn "Using Let's Encrypt STAGING (test-only certs)."
  [[ "$DNS_MATCH_IP" != "YES" ]] && warn "Domain may not point here yet; HTTPS check skipped."
fi
if echo | openssl s_client -servername "$WG_DOMAIN" -connect "$WG_DOMAIN:443" -showcerts 2>/dev/null | openssl x509 -noout -issuer -enddate >/tmp/certinfo.txt 2>/dev/null; then
  ISSUER=$(grep '^issuer=' /tmp/certinfo.txt | sed 's/^issuer= *//'); ENDDATE=$(grep '^notAfter=' /tmp/certinfo.txt | cut -d= -f2)
  if [[ -n "$ENDDATE" ]]; then
    EXP_TS=$(date -d "$ENDDATE" +%s 2>/dev/null || echo 0); NOW_TS=$(date +%s)
    if (( EXP_TS > NOW_TS )); then DAYS_LEFT=$(( (EXP_TS - NOW_TS) / 86400 )); ok "TLS cert issuer: $ISSUER"; ok "TLS cert expiry: $ENDDATE (~${DAYS_LEFT} days)"; else warn "TLS cert appears expired/unreadable ($ENDDATE)"; fi
  fi
else warn "Could not retrieve certificate to verify issuer/expiry."; fi

printf "\nSanity check summary: %d passed, %d need attention.\n" "$checklist_ok" "$checklist_fail" >&3
(( checklist_fail == 0 )) || warn "Some items may resolve automatically after DNS/ACME propagation."

# ===== Summary =====
cat >&3 <<SUMMARY

${BLD}===========================================================
 WireGuard + wg-easy behind HTTPS (Let's Encrypt auto-renew)
===========================================================${CLR}

Web UI:        https://${WG_DOMAIN}/
UI Backend:    127.0.0.1:${WG_EASY_PORT} (loopback only)
VPN Port:      UDP ${WG_PORT}
WG Host:       ${WG_HOST}
Tunnel CIDR:   ${WG_DEFAULT_ADDRESS}
Client DNS:    ${WG_DEFAULT_DNS}
IPv6 Fwd:      $( [[ "$ENABLE_IPV6" =~ ^[Yy]$ ]] && echo "ENABLED" || echo "DISABLED" )
Basic Auth:    $( [[ "$ENABLE_BASICAUTH" =~ ^[Yy]$ ]] && echo "ENABLED (user: ${BASIC_USER})" || echo "DISABLED" )
IP Allowlist:  $( [[ -n "$IP_ALLOW_CIDR" ]] && echo "$IP_ALLOW_CIDR" || echo "None" )
Firewall:      $( [[ "$ENABLE_UFW" =~ ^[Yy]$ ]] && echo "UFW enabled" || echo "Not managed" )
Auto updates:  $( [[ "$ENABLE_AUTOUPD" =~ ^[Yy]$ ]] && echo "ENABLED" || echo "DISABLED" )
fail2ban:      $( [[ "$ENABLE_F2B" =~ ^[Yy]$ ]] && echo "ENABLED (sshd + caddy-httperrors)" || echo "DISABLED" )
ACME CA:       ${ACME_CA}
Autostart:     Docker ✓, Caddy ✓, $( [[ "${ENABLE_COMPOSE_UNIT:-Y}" =~ ^[Yy]$ ]] && echo "wg-easy compose unit ✓" || echo "compose unit ✗ (containers still auto-restart)") 
Run log:       ${LOGFILE}

Useful:
  - Restart wg-easy:            docker compose -f ${APP_DIR}/compose.yaml restart
  - Update wg-easy:             cd ${APP_DIR} && docker compose pull && docker compose up -d
  - Reload Caddy:               systemctl reload caddy
  - Check fail2ban:             fail2ban-client status
  - Show TLS info:              echo | openssl s_client -servername ${WG_DOMAIN} -connect ${WG_DOMAIN}:443 2>/dev/null | openssl x509 -noout -issuer -enddate

SUMMARY

exit 0
