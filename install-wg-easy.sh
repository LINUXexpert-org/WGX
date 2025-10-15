#!/usr/bin/env bash
# install-wg-easy.sh - Interactive (TUI-capable), quiet & logged installer for:
# WireGuard + wg-easy (Docker) behind Caddy (Let's Encrypt) on Debian 13+.
# Includes: optional Basic-Auth via Caddy, sanitized Caddyfile (no plugin auth),
# autosave purge, UFW, unattended-upgrades, fail2ban (sshd + Caddy JSON),
# loopback-bound wg-easy UI, systemd autostart, percentage progress bar, full log.
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

# ---------- UI helpers ----------
RED=$'\e[31m'; GRN=$'\e[32m'; BLU=$'\e[34m'; YLW=$'\e[33m'; BLD=$'\e[1m'; CLR=$'\e[0m'
err()  { printf "%s[ERROR]%s %s\n" "$RED" "$CLR" "$*" >&3; }
ok()   { printf "%s[OK]%s    %s\n" "$GRN" "$CLR" "$*" >&3; }
info() { printf "%s[INFO]%s  %s\n" "$BLU" "$CLR" "$*" >&3; }
warn() { printf "%s[WARN]%s  %s\n" "$YLW" "$CLR" "$*" >&3; }

require_root() { [[ $EUID -eq 0 ]] || { err "Please run as root (sudo)."; exit 1; }; }
check_debian12p() {
  if ! command -v lsb_release &>/dev/null; then apt-get update -y >/dev/null 2>&1 && apt-get install -y lsb-release >/dev/null 2>&1; fi
  local dist ver; dist=$(lsb_release -is 2>/dev/null || echo Debian); ver=$(lsb_release -rs 2>/dev/null || echo "13")
  [[ "$dist" == "Debian" ]] || { err "This script targets Debian. Detected: $dist"; exit 1; }
  [[ "${ver%%.*}" -ge 12 ]] || { err "Detected Debian $ver. Use Debian 12+."; exit 1; }
}

# ---------- Input helpers (FD3 for user; /dev/tty for reads) ----------
ask() { local p="$1" __v="$2" d="${3-}" r; [[ -n "$d" ]] && printf "%s [default: %s] " "$p" "$d" >&3 || printf "%s " "$p" >&3; IFS= read -r r < /dev/tty; [[ -z "$r" && -n "$d" ]] && r="$d"; printf -v "$__v" "%s" "$r"; }
ask_req(){ local p="$1" __v="$2" d="${3-}"; while true; do ask "$p" "$__v" "$d"; [[ -n "${!__v}" ]] && break; printf "(value required)\n" >&3; done; }
ask_secret(){ local p="$1" __v="$2" s; printf "%s" "$p" >&3; stty -echo < /dev/tty; IFS= read -r s < /dev/tty; stty echo < /dev/tty; printf "\n" >&3; while [[ -z "$s" ]]; do printf "(value required) %s" "$p" >&3; stty -echo < /dev/tty; IFS= read -r s < /dev/tty; stty echo < /dev/tty; printf "\n" >&3; done; printf -v "$__v" "%s" "$s"; }

# ---------- Optional TUI (whiptail) ----------
WT=0
wt_yesno()   { whiptail --title "$1" --yesno "$2" 10 72; }
wt_input()   { local o; o=$(whiptail --title "$1" --inputbox "$2" 10 72 "$3" 3>&1 1>&2 2>&3) || return 1; printf "%s" "$o"; }
wt_password(){ local o; o=$(whiptail --title "$1" --passwordbox "$2" 10 72 3>&1 1>&2 2>&3) || return 1; printf "%s" "$o"; }

# ---------- Percentage bar ----------
STEP_NUM=0; STEP_MAX=0; BAR_WIDTH=44
repeat_char(){ local n=${1:-0} c="${2:-#}"; (( n<=0 )) && { printf ""; return; }; perl -e 'print $ARGV[1] x $ARGV[0]' "$n" "$c"; }
draw_bar(){ local pct=${1:-0}; (( pct<0 ))&&pct=0; (( pct>100 ))&&pct=100; local f=$(( pct * BAR_WIDTH / 100 )); printf "\r[%-*s] %3d%%" "$BAR_WIDTH" "$(repeat_char "$f" "#")" "$pct" >&3; }
advance_bar(){ STEP_NUM=$((STEP_NUM+1)); (( STEP_MAX < 1 )) && STEP_MAX=1; local pct=$(( STEP_NUM * 100 / STEP_MAX )); draw_bar "$pct"; }

run_step(){
  local title="$1"; shift
  (( STEP_MAX < 1 )) && STEP_MAX=1
  printf "\n" >&3
  printf "Step %d/%d: %s\n" "$((STEP_NUM+1))" "$STEP_MAX" "$title" >&3
  { printf "--- [%s] %s ---\n" "$(date -Is)" "$title" >&2; bash -o pipefail -c "$@" >&2; printf "--- [%s] %s (OK) ---\n" "$(date -Is)" "$title" >&2; }
  advance_bar
}

cleanup_on_error(){ printf "\n" >&3; err "An unexpected error occurred. See the log: $LOGFILE"; }
trap cleanup_on_error ERR

LOGFILE="$(pwd)/install-wg-easy-$(date +%Y%m%d-%H%M%S).log"
exec 3>&1
exec > >(tee -a "$LOGFILE") 2>&1
export DEBIAN_FRONTEND=noninteractive
APTQ="-o Dpkg::Use-Pty=0 -y -qq"

require_root
check_debian12p

info "Installer log: $LOGFILE"
apt-get update -qq >/dev/null 2>&1 || true
apt-get install $APTQ ca-certificates gnupg apt-transport-https curl iproute2 dnsutils jq apache2-utils openssl whiptail >/dev/null 2>&1 || true

# ---------- Subnet normalization ----------
norm_cidr(){
  local in="$1" base="" range=""
  [[ "$in" == */* ]] && { range="${in##*/}"; in="${in%%/*}"; }
  IFS=. read -r o1 o2 o3 o4 <<<"$in"
  [[ -z "$o1" || -z "$o2" || -z "$o3" ]] && { echo "ERR"; return; }
  base="${o1}.${o2}.${o3}.x"
  [[ -z "$range" ]] && range="24"
  [[ "$range" =~ ^[0-9]+$ && "$range" -ge 0 && "$range" -le 32 ]] || range="24"
  printf "%s;%s" "$base" "$range"
}

# ---------- Prompts ----------
if command -v whiptail >/dev/null 2>&1; then
  if whiptail --title "Interface" --yesno "Use TUI (whiptail) for prompts?" 9 60; then WT=1; fi
fi

tui_or_cli_prompts(){
  if (( WT )); then
    WG_DOMAIN=$(wt_input "wg-easy Domain" "Domain for the web UI:" "") || exit 1
    while [[ -z "$WG_DOMAIN" ]]; do WG_DOMAIN=$(wt_input "Required" "Domain cannot be empty:" "") || exit 1; done
    LE_EMAIL=$(wt_input "Let's Encrypt Email" "Email for ACME notices:" "") || exit 1
    while [[ -z "$LE_EMAIL" ]]; do LE_EMAIL=$(wt_input "Required" "Email cannot be empty:" "") || exit 1; done
    if wt_yesno "ACME Mode" "Use Let's Encrypt STAGING (test-only)?"; then ACME_CA="https://acme-staging-v02.api.letsencrypt.org/directory"; else ACME_CA="https://acme-v02.api.letsencrypt.org/directory"; fi
    WG_HOST=$(wt_input "Public Hostname/IP" "Hostname or IP clients will reach:" "$WG_DOMAIN") || exit 1
    WG_PORT=$(wt_input "WireGuard UDP Port" "UDP port for WireGuard:" "51820") || exit 1
    WG_EASY_PORT=$(wt_input "wg-easy UI Port" "Local-only UI port (host & container):" "51821") || exit 1
    RAW_SUBNET=$(wt_input "Tunnel Subnet" "Example: 10.8.0.x or 10.8.0.0/24" "10.8.0.x") || exit 1
    WG_DEFAULT_DNS=$(wt_input "Client DNS" "Comma-separated DNS for clients:" "1.1.1.1,9.9.9.9") || exit 1
    if wt_yesno "IPv6 Forwarding" "Enable IPv6 forwarding?"; then ENABLE_IPV6="Y"; else ENABLE_IPV6="N"; fi
    if wt_yesno "Basic Auth" "Protect UI with Basic Auth (Caddy)?"; then
      ENABLE_BASICAUTH="Y"
      BASIC_USER=$(wt_input "Basic Auth User" "Username:" "admin") || exit 1
      BASIC_PASS=$(wt_password "Basic Auth Password" "Enter password:") || exit 1
      while [[ -z "$BASIC_PASS" ]]; do BASIC_PASS=$(wt_password "Required" "Password cannot be empty:") || exit 1; done
    else ENABLE_BASICAUTH="N"; fi
    WGEASY_ADMIN_PASS=$(wt_password "wg-easy Admin Password" "Password for wg-easy UI (stored as bcrypt):") || exit 1
    while [[ -z "$WGEASY_ADMIN_PASS" ]]; do WGEASY_ADMIN_PASS=$(wt_password "Required" "Password cannot be empty:") || exit 1; done
    IP_ALLOW_CIDR=$(wt_input "UI Allowlist (optional)" "CIDR allowed to UI (blank = none):" "") || exit 1
    if wt_yesno "Firewall" "Install & enable UFW (22/tcp, 80/tcp, 443/tcp, ${WG_PORT}/udp)?"; then ENABLE_UFW="Y"; else ENABLE_UFW="N"; fi
    if wt_yesno "Unattended Upgrades" "Enable unattended security updates?"; then
      ENABLE_AUTOUPD="Y"
      if wt_yesno "Upgrade Emails" "Send email notifications for unattended upgrades?"; then UPD_MAIL=$(wt_input "Email" "Address to notify:" "$LE_EMAIL") || exit 1; else UPD_MAIL=""; fi
    else ENABLE_AUTOUPD="N"; UPD_MAIL=""; fi
    if wt_yesno "fail2ban" "Install & configure fail2ban (sshd + Caddy)?"; then
      ENABLE_F2B="Y"
      F2B_BANTIME=$(wt_input "fail2ban bantime" "e.g., 1h, 6h, 24h:" "1h") || exit 1
      F2B_FINDTIME=$(wt_input "fail2ban findtime" "e.g., 10m, 15m:" "10m") || exit 1
      F2B_MAXRETRY=$(wt_input "fail2ban maxretry" "e.g., 5:" "5") || exit 1
    else ENABLE_F2B="N"; F2B_BANTIME="1h"; F2B_FINDTIME="10m"; F2B_MAXRETRY="5"; fi
    if wt_yesno "Autostart Compose" "Create a systemd unit to re-up wg-easy on boot?"; then ENABLE_COMPOSE_UNIT="Y"; else ENABLE_COMPOSE_UNIT="N"; fi
    if wt_yesno "Caddy Purge" "Purge conflicting Caddy configs/autosave?"; then PURGE_CADDY="Y"; else PURGE_CADDY="N"; fi
  else
    ask_req "Domain for the wg-easy web UI (e.g., vpn.example.com):" WG_DOMAIN
    ask_req "Email for Let's Encrypt / Caddy (TLS notices):" LE_EMAIL
    ask "Use Let's Encrypt STAGING first (test-only)? [y/N]:" LE_STAGING "N"
    [[ "$LE_STAGING" =~ ^[Yy]$ ]] && ACME_CA="https://acme-staging-v02.api.letsencrypt.org/directory" || ACME_CA="https://acme-v02.api.letsencrypt.org/directory"
    ask "Public hostname/IP clients will reach:" WG_HOST "$WG_DOMAIN"
    ask "WireGuard UDP listen port:" WG_PORT "51820"
    ask "wg-easy UI port (host+container):" WG_EASY_PORT "51821"
    ask "Tunnel subnet (e.g., 10.8.0.x OR 10.8.0.0/24):" RAW_SUBNET "10.8.0.x"
    ask "Default DNS server(s), comma-separated:" WG_DEFAULT_DNS "1.1.1.1,9.9.9.9"
    ask "Enable IPv6 forwarding for WireGuard? [y/N]:" ENABLE_IPV6 "N"
    ask "Protect the UI with Basic Auth via Caddy? [y/N]:" ENABLE_BASICAUTH "N"
    BASIC_USER=""; BASIC_PASS=""; if [[ "$ENABLE_BASICAUTH" =~ ^[Yy]$ ]]; then ask "Basic Auth username:" BASIC_USER "admin"; ask_secret "Basic Auth password:" BASIC_PASS; fi
    ask_secret "wg-easy admin password (stored as bcrypt):" WGEASY_ADMIN_PASS
    ask "Restrict UI to IP/CIDR (blank = none):" IP_ALLOW_CIDR ""
    ask "Install & enable UFW (22/tcp, 80/tcp, 443/tcp, ${WG_PORT}/udp)? [Y/n]:" ENABLE_UFW "Y"
    ask "Enable unattended security updates? [Y/n]:" ENABLE_AUTOUPD "Y"
    UPD_MAIL=""; [[ "$ENABLE_AUTOUPD" =~ ^[Yy]$ ]] && ask "Email for upgrade notices (blank = none):" UPD_MAIL "$LE_EMAIL"
    ask "Install & configure fail2ban (sshd + Caddy)? [Y/n]:" ENABLE_F2B "Y"
    F2B_BANTIME="1h"; F2B_FINDTIME="10m"; F2B_MAXRETRY="5"
    if [[ "$ENABLE_F2B" =~ ^[Yy]$ ]]; then ask "fail2ban bantime:" F2B_BANTIME "$F2B_BANTIME"; ask "fail2ban findtime:" F2B_FINDTIME "$F2B_FINDTIME"; ask "fail2ban maxretry:" F2B_MAXRETRY "$F2B_MAXRETRY"; fi
    ask "Create a systemd unit to re-up wg-easy on boot? [Y/n]:" ENABLE_COMPOSE_UNIT "Y"
    ask "Purge conflicting Caddy configs/autosave? [Y/n]:" PURGE_CADDY "Y"
  fi
}
printf "\n%s=== WireGuard + wg-easy (Docker) behind Caddy/Let's Encrypt) ===%s\n\n" "$BLD" "$CLR" >&3
tui_or_cli_prompts

# Normalize subnet -> WG_DEFAULT_ADDRESS + RANGE
SUB=$(norm_cidr "${RAW_SUBNET:-10.8.0.x}") || SUB="ERR"
[[ "$SUB" == "ERR" ]] && { err "Invalid subnet '${RAW_SUBNET:-}'"; exit 1; }
WG_DEFAULT_ADDRESS="${SUB%%;*}"
WG_DEFAULT_ADDRESS_RANGE="${SUB##*;}"

# DNS pre-flight (best effort)
A_RECORDS=$(dig +short A "$WG_DOMAIN" || true); AAAA_RECORDS=$(dig +short AAAA "$WG_DOMAIN" || true)
[[ -n "$A_RECORDS$AAAA_RECORDS" ]] || warn "No A/AAAA records found for $WG_DOMAIN. ACME will fail until DNS is configured."

# Confirm
if (( WT )); then wt_yesno "Confirm" "Proceed with installation?" || { err "Aborted by user."; exit 1; }
else ask "Proceed with installation? [Y/n]:" CONFIRM "Y"; [[ "$CONFIRM" =~ ^[Yy]$ ]] || { err "Aborted by user."; exit 1; }; fi

# ---------- Derived paths ----------
APP_DIR="/opt/wg-easy"
CONFIG_DIR="$APP_DIR/config"
CADDYFILE="/etc/caddy/Caddyfile"
ACCESS_LOG_DIR="/var/log/caddy"
COMPOSE_UNIT="/etc/systemd/system/wg-easy-compose.service"
DROPIN_DIR="/etc/systemd/system/caddy.service.d"
AUTOSAVES=(
  "/var/lib/caddy/autosave.json"
  "/var/lib/caddy/.config/caddy/autosave.json"
  "/var/lib/caddy/.local/share/caddy/autosave.json"
  "/var/lib/caddy/.local/state/caddy/autosave.json"
  "/root/.config/caddy/autosave.json"
  "/root/.local/share/caddy/autosave.json"
  "/root/.local/state/caddy/autosave.json"
)

# ---------- Basic Auth (optional) ----------
BASIC_HASH=""
if [[ "${ENABLE_BASICAUTH:-N}" =~ ^[Yy]$ ]]; then
  BASIC_USER="$(printf "%s" "${BASIC_USER:-admin}" | tr -cd "A-Za-z0-9._-")"
  if command -v caddy >/dev/null 2>&1; then BASIC_HASH="$(caddy hash-password --plaintext "${BASIC_PASS}" 2>/dev/null | awk '/^\$2[aby]\$/{print; exit}' | tr -d '\r\n' || true)"; fi
  [[ -z "$BASIC_HASH" ]] && BASIC_HASH="$(htpasswd -nbB x "${BASIC_PASS}" 2>/dev/null | cut -d: -f2 | sed 's/^\$2y\$/\$2a$/' | tr -d '\r\n' || true)"
  [[ "$BASIC_HASH" =~ ^\$2[aby]\$.+ ]] || { warn "Could not generate bcrypt; disabling Caddy basic_auth."; ENABLE_BASICAUTH="N"; }
fi

# ---------- STEP_MAX ----------
STEP_MAX=0
[[ "${PURGE_CADDY:-Y}" =~ ^[Yy]$ ]] && STEP_MAX=$((STEP_MAX+1))
for _ in 1 2 3 4 5 6 7; do STEP_MAX=$((STEP_MAX+1)); done
[[ "${ENABLE_UFW:-Y}" =~ ^[Yy]$ ]] && STEP_MAX=$((STEP_MAX+1))
[[ "${ENABLE_AUTOUPD:-Y}" =~ ^[Yy]$ ]] && STEP_MAX=$((STEP_MAX+1))
[[ "${ENABLE_F2B:-Y}" =~ ^[Yy]$ ]] && STEP_MAX=$((STEP_MAX+1))
STEP_MAX=$((STEP_MAX+1)) # launch wg-easy
[[ "${ENABLE_COMPOSE_UNIT:-Y}" =~ ^[Yy]$ ]] && STEP_MAX=$((STEP_MAX+1))
STEP_MAX=$((STEP_MAX+1)) # caddy reload
printf "\n" >&3; draw_bar 0

# ---------- Steps ----------
# 0) Purge Caddy extras / autosaves (optional)
if [[ "${PURGE_CADDY:-Y}" =~ ^[Yy]$ ]]; then
  run_step "Purge conflicting Caddy configs & AUTOSAVEs" "
  TS=\$(date +%Y%m%d-%H%M%S)
  mkdir -p /etc/caddy/backup-\$TS
  cp -a /etc/caddy/* /etc/caddy/backup-\$TS/ 2>/dev/null || true
  find /etc/caddy -maxdepth 1 -type f ! -name 'Caddyfile' -print -exec mv {} /etc/caddy/backup-\$TS/ \\; || true
  for d in conf.d sites-enabled snippets vhosts d; do [ -e \"/etc/caddy/\$d\" ] && mv \"/etc/caddy/\$d\" \"/etc/caddy/backup-\$TS/\$d\"; done
  [ -f /etc/caddy/caddy.json ] && mv /etc/caddy/caddy.json \"/etc/caddy/backup-\$TS/caddy.json\"
  for f in ${AUTOSAVES[*]}; do rm -f \"\$f\" 2>/dev/null || true; done
  "
fi

# 1) Packages
run_step "Update packages & base tools" "apt-get update -qq; apt-get install $APTQ ca-certificates gnupg apt-transport-https curl jq apache2-utils iproute2 dnsutils openssl"

# 2) IP forwarding
run_step "Configure IP forwarding" "cat > /etc/sysctl.d/99-wireguard-forwarding.conf <<EOF
net.ipv4.ip_forward=1
$([[ "${ENABLE_IPV6:-N}" =~ ^[Yy]$ ]] && echo 'net.ipv6.conf.all.forwarding=1')
EOF
sysctl --system >/dev/null"

# 3) Docker
run_step "Install & enable Docker Engine" "command -v docker >/dev/null || { curl -fsSL https://get.docker.com | sh; }; systemctl enable --now docker"

# 4) docker compose plugin
run_step "Install docker compose plugin" "docker compose version >/dev/null 2>&1 || apt-get install $APTQ docker-compose-plugin"

# 5) Caddy install + drop-in + perms + autosave purge
run_step "Install & enable Caddy (+drop-in, perms, purge autosaves)" "
if ! command -v caddy >/dev/null; then
  apt-get install $APTQ debian-keyring debian-archive-keyring
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  echo 'deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq && apt-get install $APTQ caddy
fi
systemctl enable --now caddy
mkdir -p $ACCESS_LOG_DIR /var/lib/caddy
chown -R caddy:caddy $ACCESS_LOG_DIR /var/lib/caddy
chmod 755 /etc/caddy
# Ensure access log exists and is readable by fail2ban
touch $ACCESS_LOG_DIR/access.log
chown caddy:caddy $ACCESS_LOG_DIR/access.log
chmod 755 $ACCESS_LOG_DIR
chmod 644 $ACCESS_LOG_DIR/access.log
mkdir -p '$DROPIN_DIR'
cat > '$DROPIN_DIR/override.conf' <<'OVR'
[Service]
Environment=
EnvironmentFile=
ExecStart=
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile
User=caddy
Group=caddy
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
LimitNOFILE=1048576
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/caddy /var/log/caddy
# Admin is off; force reload via CLI
ExecReload=
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force
OVR
systemctl daemon-reload
for f in ${AUTOSAVES[*]}; do rm -f \"\$f\" 2>/dev/null || true; done
"

# 6) wg-easy .env + compose (robust bcrypt; safe writes; loopback bind)
run_step "Create wg-easy deployment files" "
set -Eeuo pipefail
mkdir -p '$CONFIG_DIR'

# --- Generate a valid 60-char bcrypt for PASSWORD_HASH (handles &, $, quotes) ---
PW_STR=\"$WGEASY_ADMIN_PASS\"
RAW=\$(docker run --rm ghcr.io/wg-easy/wg-easy wgpw \"\$PW_STR\" | tr -d '\r' || true)
HASH=\$(printf '%s\n' \"\$RAW\" | grep -Eo '\\$2[aby]\\$[0-9]{2}\\$[./A-Za-z0-9]{53}' || true)
if [ -z \"\$HASH\" ]; then
  HASH=\$(htpasswd -nbB x \"\$PW_STR\" | cut -d: -f2 | sed 's/^\\$2y\\$/\\$2b$/' | tr -d '\r' || true)
fi
if [ \${#HASH} -ne 60 ] || ! printf '%s' \"\$HASH\" | grep -Eq '^\\$2[aby]\\$[0-9]{2}\\$[./A-Za-z0-9]{53}\$'; then
  echo 'ERROR: Failed to produce a valid 60-char bcrypt for PASSWORD_HASH' >&2
  echo \"RAW: \$RAW\" >&2
  echo \"HASH: \$HASH (len=\${#HASH})\" >&2
  exit 1
fi

# --- Fresh .env without $-expansion; append PASSWORD_HASH safely ---
tee '$APP_DIR/.env' >/dev/null <<'ENVEOF'
WG_HOST='"$WG_HOST"'
WG_PORT='"$WG_PORT"'
WG_DEFAULT_ADDRESS='"$WG_DEFAULT_ADDRESS"'
WG_DEFAULT_ADDRESS_RANGE='"$WG_DEFAULT_ADDRESS_RANGE"'
WG_DEFAULT_DNS='"$WG_DEFAULT_DNS"'
WG_EASY_PORT='"$WG_EASY_PORT"'
PORT='"$WG_EASY_PORT"'
ENVEOF

awk -v h=\"\$HASH\" 'END{ print \"PASSWORD_HASH=\" h }' /dev/null | tee -a '$APP_DIR/.env' >/dev/null
sed -i 's/\r$//' '$APP_DIR/.env'
sed -i '/^PASSWORD=/d' '$APP_DIR/.env'
[ \$(grep -c '^PASSWORD_HASH=' '$APP_DIR/.env') -eq 1 ] || { echo 'Unexpected PASSWORD_HASH lines in .env' >&2; exit 1; }
grep -Eq '^WG_HOST=' '$APP_DIR/.env' || { echo 'WG_HOST missing in .env' >&2; exit 1; }

# --- Compose file (env_file, loopback UI, UDP port) ---
tee '$APP_DIR/compose.yaml' >/dev/null <<'EOF'
name: wg-easy
services:
  wg-easy:
    image: ghcr.io/wg-easy/wg-easy:latest
    container_name: wg-easy
    env_file:
      - .env
    environment:
      - PORT=${WG_EASY_PORT:-51821}
      - WG_PORT=${WG_PORT:-51820}
    volumes:
      - ./config:/etc/wireguard
    ports:
      - "127.0.0.1:${WG_EASY_PORT:-51821}:${WG_EASY_PORT:-51821}/tcp"
      - "${WG_PORT:-51820}:${WG_PORT:-51820}/udp"
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv6.conf.all.forwarding=1
    restart: unless-stopped
EOF
"

# 7) Caddyfile + sanitize + proxy headers + validate
AUTH_BLOCK_CORE=""; AUTH_BLOCK_LEGACY=""
if [[ "${ENABLE_BASICAUTH:-N}" =~ ^[Yy]$ && "${BASIC_HASH:-}" =~ ^\$2[aby]\$.+ ]]; then
  AUTH_BLOCK_CORE=$'  basic_auth /* {\n    '"${BASIC_USER:-admin}"' '"$BASIC_HASH"$'\n  }\n'
  AUTH_BLOCK_LEGACY=$'  basicauth /* {\n    '"${BASIC_USER:-admin}"' '"$BASIC_HASH"$'\n  }\n'
fi

if [[ -n "${IP_ALLOW_CIDR:-}" ]]; then
  SITE_BODY=$(cat <<EOS
  log {
    output file $ACCESS_LOG_DIR/access.log
    format json
  }

  @allow_ips {
    remote_ip $IP_ALLOW_CIDR
  }

  handle {
    respond "Forbidden" 403
  }

  handle @allow_ips {
${AUTH_BLOCK_CORE}  reverse_proxy 127.0.0.1:$WG_EASY_PORT {
      header_up Host {host}
      header_up X-Forwarded-Host {host}
      header_up X-Forwarded-Proto https
    }
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

${AUTH_BLOCK_CORE}  reverse_proxy 127.0.0.1:$WG_EASY_PORT {
    header_up Host {host}
    header_up X-Forwarded-Host {host}
    header_up X-Forwarded-Proto https
  }

  tls {
    protocols tls1.2 tls1.3
  }
EOS
)
fi

run_step "Write Caddyfile; sanitize & validate" "
cat > '$CADDYFILE' <<EOF
{
  admin off
  email $LE_EMAIL
  acme_ca $ACME_CA
}

http://$WG_DOMAIN {
  redir https://{host}{uri} 308
}

$WG_DOMAIN {
$SITE_BODY
}
EOF

# Strip plugin 'authentication' & imports if present
awk 'BEGIN{skip=0}
  /^[[:space:]]*authentication[[:space:]]*\\{/ {skip=1; depth=1; next}
  skip==1 { if (\$0 ~ /\\{/) depth++; if (\$0 ~ /\\}/){depth--; if (depth==0){skip=0; next}}; next }
  /^[[:space:]]*import[[:space:]]+/ {next}
  {print}
' '$CADDYFILE' > /etc/caddy/Caddyfile.sanitized && mv /etc/caddy/Caddyfile.sanitized '$CADDYFILE'

caddy fmt --overwrite '$CADDYFILE' >/dev/null 2>&1 || true
caddy validate --config '$CADDYFILE'
caddy adapt --config '$CADDYFILE' --pretty > /tmp/caddy-adapt.json || true
"

# 8) UFW
if [[ "${ENABLE_UFW:-Y}" =~ ^[Yy]$ ]]; then
  run_step "Configure UFW (22/tcp, 80/tcp, 443/tcp, ${WG_PORT}/udp)" "
  apt-get install $APTQ ufw
  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow ${WG_PORT}/udp
  ufw --force enable || true
  systemctl enable --now ufw || true
  "
fi

# 9) unattended-upgrades (keep literal ${distro_codename})
if [[ "${ENABLE_AUTOUPD:-Y}" =~ ^[Yy]$ ]]; then
  run_step "Enable unattended security updates" "
  apt-get install $APTQ unattended-upgrades apt-listchanges
  dpkg-reconfigure --priority=low unattended-upgrades >/dev/null || true
  cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'CFG'
Unattended-Upgrade::Origins-Pattern {
        \"origin=Debian,codename=\${distro_codename},label=Debian-Security\";
        \"origin=Debian,codename=\${distro_codename},label=Debian\";
};
Unattended-Upgrade::Automatic-Reboot \"true\";
Unattended-Upgrade::Automatic-Reboot-Time \"03:30\";
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

# 10) fail2ban (HARDENED)
if [[ "${ENABLE_F2B:-Y}" =~ ^[Yy]$ ]]; then
  run_step "Install & enable fail2ban (sshd + Caddy JSON)" "
  apt-get install $APTQ fail2ban
  systemctl enable --now fail2ban || true

  # Ensure Caddy log exists & is readable
  mkdir -p $ACCESS_LOG_DIR
  touch $ACCESS_LOG_DIR/access.log
  chown caddy:caddy $ACCESS_LOG_DIR $ACCESS_LOG_DIR/access.log
  chmod 755 $ACCESS_LOG_DIR
  chmod 644 $ACCESS_LOG_DIR/access.log

  # Filter capturing client IP from Caddy JSON logs; bans on 401/403 bursts
  cat > /etc/fail2ban/filter.d/caddy-httperrors.conf <<'EOF'
[Definition]
failregex = ^\{.*\"request\":\{.*\"remote_ip\":\"<HOST>\".*\}.*\"status\":(?:401|403).*\}$
ignoreregex =
EOF

  # Minimal, valid jail
  cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = ${F2B_BANTIME:-1h}
findtime = ${F2B_FINDTIME:-10m}
maxretry = ${F2B_MAXRETRY:-5}

[sshd]
enabled  = true
backend  = systemd

[caddy-httperrors]
enabled  = true
port     = http,https
filter   = caddy-httperrors
logpath  = $ACCESS_LOG_DIR/access.log
backend  = auto
EOF

  # Validate then restart
  fail2ban-client -d >/dev/null
  systemctl restart fail2ban
  "
fi

# 11) Launch wg-easy
run_step "Launch wg-easy container" "
cd '$APP_DIR'
docker compose pull
docker compose up -d
"

# 12) systemd unit for autostart (compose)
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

# 13) Reload Caddy (activate config; purge AUTOSAVEs again)
run_step "Reload Caddy (activate config; purge AUTOSAVEs again)" "
for f in ${AUTOSAVES[*]}; do rm -f \"\$f\" 2>/dev/null || true; done
caddy validate --config '$CADDYFILE'
systemctl reload caddy || systemctl restart caddy
"

# ---------- Post-install checks ----------
printf "\n\n%s=== Running sanity checks ===%s\n" "$BLD" "$CLR" >&3
checklist_ok=0; checklist_fail=0
check(){ local d="$1"; shift; if bash -c "$@" >/dev/null 2>&1; then ok "$d"; ((checklist_ok++)); else warn "$d - needs attention"; ((checklist_fail++)); fi; }
check "IPv4 forwarding enabled" 'sysctl -n net.ipv4.ip_forward | grep -q "^1$"'
[[ "${ENABLE_IPV6:-N}" =~ ^[Yy]$ ]] && check "IPv6 forwarding enabled" 'sysctl -n net.ipv6.conf.all.forwarding | grep -q "^1$"'
check "Docker enabled & active" 'systemctl is-enabled docker >/dev/null && systemctl is-active --quiet docker'
check "Caddy enabled & active" 'systemctl is-enabled caddy >/dev/null && systemctl is-active --quiet caddy'
check "wg-easy container running" 'docker ps --format "{{.Names}}" | grep -q "^wg-easy$"'
check "WireGuard UDP listening on :${WG_PORT}" 'ss -plnu | grep -q ":${WG_PORT} "'
check "Caddy listening on :80 and :443" 'ss -plnt | grep -q ":80 " && ss -plnt | grep -q ":443 "'
check "wg-easy UI bound to loopback :${WG_EASY_PORT}" 'ss -lnt | grep -q "127.0.0.1:${WG_EASY_PORT} "'

# Backend reachability
BACKEND_HEAD=$(curl -sSIL "http://127.0.0.1:${WG_EASY_PORT}" 2>/dev/null | head -n1 || true)
[[ "$BACKEND_HEAD" =~ ^HTTP ]] && ok "wg-easy backend responds: ${BACKEND_HEAD}" || warn "wg-easy backend did not respond; check 'docker logs wg-easy'"

# HTTP -> HTTPS redirect
REDIR_OUT=$(curl -sI "http://$WG_DOMAIN/" || true)
REDIR_CODE=$(printf "%s" "$REDIR_OUT" | awk '/^HTTP/{print $2; exit}')
REDIR_LOC=$(printf "%s" "$REDIR_OUT" | awk '/^Location:/ {print $2; exit}' | tr -d '\r')
if [[ "$REDIR_CODE" =~ ^30[18]$ ]] && [[ "$REDIR_LOC" == "https://$WG_DOMAIN/"* ]]; then ok "HTTP→HTTPS redirect in place (${REDIR_CODE} to ${REDIR_LOC})"; else warn "HTTP→HTTPS redirect not confirmed"; fi

printf "\nSanity check summary: %d passed, %d need attention.\n" "$checklist_ok" "$checklist_fail" >&3

# ---------- Summary ----------
cat >&3 <<SUMMARY

${BLD}===========================================================
 WireGuard + wg-easy behind HTTPS (Let's Encrypt auto-renew)
===========================================================${CLR}

Web UI:        https://${WG_DOMAIN}/
UI Backend:    127.0.0.1:${WG_EASY_PORT} (loopback only)
VPN Port:      UDP ${WG_PORT}
WG Host:       ${WG_HOST}
Tunnel Base:   ${WG_DEFAULT_ADDRESS} /${WG_DEFAULT_ADDRESS_RANGE}
Client DNS:    ${WG_DEFAULT_DNS}
IPv6 Fwd:      $( [[ "${ENABLE_IPV6:-N}" =~ ^[Yy]$ ]] && echo "ENABLED" || echo "DISABLED" )
Basic Auth:    $( [[ "${ENABLE_BASICAUTH:-N}" =~ ^[Yy]$ ]] && echo "ENABLED (via Caddy)" || echo "DISABLED (wg-easy auth only)" )
IP Allowlist:  $( [[ -n "${IP_ALLOW_CIDR:-}" ]] && echo "$IP_ALLOW_CIDR" || echo "None" )
Firewall:      $( [[ "${ENABLE_UFW:-Y}" =~ ^[Yy]$ ]] && echo "UFW enabled" || echo "Not managed" )
Auto updates:  $( [[ "${ENABLE_AUTOUPD:-Y}" =~ ^[Yy]$ ]] && echo "ENABLED" || echo "DISABLED" )
fail2ban:      $( [[ "${ENABLE_F2B:-Y}" =~ ^[Yy]$ ]] && echo "ENABLED (sshd + caddy-httperrors)" || echo "DISABLED" )
ACME CA:       ${ACME_CA}
Autostart:     Docker ✓, Caddy ✓, $( [[ "${ENABLE_COMPOSE_UNIT:-Y}" =~ ^[Yy]$ ]] && echo "wg-easy compose unit ✓" || echo "compose unit ✗" )
Run log:       ${LOGFILE}

Useful:
  - Restart wg-easy:  docker compose -f ${APP_DIR}/compose.yaml restart
  - Update wg-easy:   cd ${APP_DIR} && docker compose pull && docker compose up -d
  - Logs (wg-easy):   docker logs -f wg-easy
  - Reload Caddy:     systemctl reload caddy
  - Inspect adapted:  less /tmp/caddy-adapt.json

SUMMARY

exit 0
