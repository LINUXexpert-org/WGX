#!/usr/bin/env bash
# install-wg-easy.sh - Quiet, logged, interactive (TUI-capable) installer for WireGuard + wg-easy (Docker)
# behind Caddy/Let's Encrypt on Debian 13. Now uses basic_auth (not basicauth), disables Caddy admin,
# purges ALL autosave paths, quarantines stray configs, validates adapted config for rogue "authentication".
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

RED=$'\e[31m'; GRN=$'\e[32m'; BLU=$'\e[34m'; YLW=$'\e[33m'; BLD=$'\e[1m'; CLR=$'\e[0m'
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

ask() { local prompt="$1" __var="$2" def="${3-}" reply; [[ -n "$def" ]] && printf "%s [default: %s] " "$prompt" "$def" >&3 || printf "%s " "$prompt" >&3; IFS= read -r reply < /dev/tty; [[ -z "$reply" && -n "$def" ]] && reply="$def"; printf -v "$__var" "%s" "$reply"; }
ask_req(){ local p="$1" v="$2" d="${3-}"; while true; do ask "$p" "$v" "$d"; [[ -n "${!v}" ]] && break; printf "(value required)\n" >&3; done; }
ask_secret(){ local p="$1" v="$2" s; printf "%s" "$p" >&3; stty -echo < /dev/tty; IFS= read -r s < /dev/tty; stty echo < /dev/tty; printf "\n" >&3; while [[ -z "$s" ]]; do printf "(value required) %s" "$p" >&3; stty -echo < /dev/tty; IFS= read -r s < /dev/tty; stty echo < /dev/tty; printf "\n" >&3; done; printf -v "$v" "%s" "$s"; }

WT=0
wt_yesno()   { whiptail --title "$1" --yesno "$2" 10 72; }
wt_input()   { local o; o=$(whiptail --title "$1" --inputbox "$2" 10 72 "$3" 3>&1 1>&2 2>&3) || return 1; printf "%s" "$o"; }
wt_password(){ local o; o=$(whiptail --title "$1" --passwordbox "$2" 10 72 3>&1 1>&2 2>&3) || return 1; printf "%s" "$o"; }

STEP_NUM=0; STEP_MAX=0; BAR_WIDTH=42
repeat_char(){ local n=$1 c="$2"; [[ $n -le 0 ]] && return 0; printf "%0.s${c}" $(seq 1 "$n"); }
draw_bar(){ local pct=$1; ((pct<0))&&pct=0; ((pct>100))&&pct=100; local f=$(( pct * BAR_WIDTH / 100 )); printf "\r[%-*s] %3d%%" "$BAR_WIDTH" "$(repeat_char "$f" "#")" "$pct" >&3; }
advance_bar(){ STEP_NUM=$((STEP_NUM+1)); (( STEP_MAX<1 )) && STEP_MAX=1; local pct=$(( STEP_NUM * 100 / STEP_MAX )); draw_bar "$pct"; }

run_step(){
  local t="$1"; shift
  printf "\nStep $((STEP_NUM+1))/$STEP_MAX: %s\n" "$t" >&3
  { printf "--- [%s] %s ---\n" "$(date -Is)" "$t" >&2; bash -o pipefail -c "$*" >&2; printf "--- [%s] %s (OK) ---\n" "$(date -Is)" "$t" >&2; }
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
check_debian13

info "Installer log: $LOGFILE"
apt-get update -qq >/dev/null 2>&1 || true
apt-get install $APTQ ca-certificates gnupg apt-transport-https curl iproute2 dnsutils jq apache2-utils openssl whiptail >/dev/null 2>&1 || true

if command -v whiptail >/dev/null 2>&1; then if whiptail --title "Interface" --yesno "Use TUI (whiptail) for prompts?" 9 60; then WT=1; fi; fi

tui_or_cli(){
  if (( WT )); then
    WG_DOMAIN=$(wt_input "wg-easy Domain" "Enter the domain for the wg-easy web UI:" "") || exit 1; while [[ -z "$WG_DOMAIN" ]]; do WG_DOMAIN=$(wt_input "Required" "Domain cannot be empty:" "") || exit 1; done
    LE_EMAIL=$(wt_input "Let's Encrypt Email" "Email for ACME/Notices:" "") || exit 1; while [[ -z "$LE_EMAIL" ]]; do LE_EMAIL=$(wt_input "Required" "Email cannot be empty:" "") || exit 1; done
    if wt_yesno "ACME Mode" "Use Let's Encrypt STAGING (test-only)?"; then ACME_CA="https://acme-staging-v02.api.letsencrypt.org/directory"; else ACME_CA="https://acme-v02.api.letsencrypt.org/directory"; fi
    WG_HOST=$(wt_input "Public Hostname/IP" "Hostname or IP clients will reach:" "$WG_DOMAIN") || exit 1
    WG_PORT=$(wt_input "WireGuard UDP Port" "UDP port for WireGuard:" "51820") || exit 1
    WG_EASY_PORT=$(wt_input "wg-easy UI Port" "Local-only UI port:" "51821") || exit 1
    WG_DEFAULT_ADDRESS=$(wt_input "Tunnel Subnet" "IPv4 CIDR for tunnel:" "10.8.0.0/24") || exit 1
    WG_DEFAULT_DNS=$(wt_input "Client DNS" "Comma-separated DNS for clients:" "1.1.1.1,9.9.9.9") || exit 1
    if wt_yesno "IPv6 Forwarding" "Enable IPv6 forwarding for WireGuard?"; then ENABLE_IPV6="Y"; else ENABLE_IPV6="N"; fi
    if wt_yesno "Basic Auth" "Protect UI with Basic Auth (Caddy)?"; then
      ENABLE_BASICAUTH="Y"; BASIC_USER=$(wt_input "Basic Auth User" "Username for Basic Auth:" "admin") || exit 1; BASIC_PASS=$(wt_password "Basic Auth Password" "Enter Basic Auth password:") || exit 1; while [[ -z "$BASIC_PASS" ]]; do BASIC_PASS=$(wt_password "Required" "Password cannot be empty:") || exit 1; done
    else ENABLE_BASICAUTH="N"; fi
    WGEASY_ADMIN_PASS=$(wt_password "wg-easy Admin Password" "Password for wg-easy UI:") || exit 1; while [[ -z "$WGEASY_ADMIN_PASS" ]]; do WGEASY_ADMIN_PASS=$(wt_password "Required" "Password cannot be empty:") || exit 1; done
    IP_ALLOW_CIDR=$(wt_input "UI Allowlist (optional)" "CIDR allowed to UI (blank = none):" "") || exit 1
    if wt_yesno "Firewall" "Install & enable UFW (22/tcp, 80/tcp, 443/tcp, ${WG_PORT}/udp)?"; then ENABLE_UFW="Y"; else ENABLE_UFW="N"; fi
    if wt_yesno "Unattended Upgrades" "Enable unattended security updates?"; then
      ENABLE_AUTOUPD="Y"; if wt_yesno "Upgrade Emails" "Send email notifications for unattended upgrades?"; then UPD_MAIL=$(wt_input "Email" "Address to notify:" "$LE_EMAIL") || exit 1; else UPD_MAIL=""; fi
    else ENABLE_AUTOUPD="N"; UPD_MAIL=""; fi
    if wt_yesno "fail2ban" "Install & configure fail2ban (sshd + Caddy)?"; then ENABLE_F2B="Y"; F2B_BANTIME=$(wt_input "fail2ban bantime" "e.g., 1h, 6h, 24h:" "1h") || exit 1; F2B_FINDTIME=$(wt_input "fail2ban findtime" "e.g., 10m, 15m:" "10m") || exit 1; F2B_MAXRETRY=$(wt_input "fail2ban maxretry" "e.g., 5:" "5") || exit 1; else ENABLE_F2B="N"; F2B_BANTIME="1h"; F2B_FINDTIME="10m"; F2B_MAXRETRY="5"; fi
    if wt_yesno "Autostart Compose" "Create a systemd unit to re-up wg-easy on boot?"; then ENABLE_COMPOSE_UNIT="Y"; else ENABLE_COMPOSE_UNIT="N"; fi
    if wt_yesno "Caddy Purge" "Purge conflicting configs (authentication/imports/autosave)?"; then PURGE_CADDY="Y"; else PURGE_CADDY="N"; fi
    if wt_yesno "Force Unit Caddyfile" "Force Caddy to use /etc/caddy/Caddyfile (systemd drop-in)?"; then FORCE_CADDY_DROPIN="Y"; else FORCE_CADDY_DROPIN="N"; fi
  else
    ask_req "Domain for the wg-easy web UI (e.g., vpn.example.com):" WG_DOMAIN
    ask_req "Email for Let's Encrypt / Caddy (TLS notices):" LE_EMAIL
    ask "Use Let's Encrypt STAGING for first issuance (test-only)? [y/N]:" LE_STAGING "N"; [[ "$LE_STAGING" =~ ^[Yy]$ ]] && ACME_CA="https://acme-staging-v02.api.letsencrypt.org/directory" || ACME_CA="https://acme-v02.api.letsencrypt.org/directory"
    ask "Public hostname/IP clients will reach:" WG_HOST "$WG_DOMAIN"
    ask "WireGuard UDP listen port:" WG_PORT "51820"
    ask "wg-easy UI port (local only):" WG_EASY_PORT "51821"
    ask "Default tunnel subnet (IPv4 CIDR):" WG_DEFAULT_ADDRESS "10.8.0.0/24"
    ask "Default DNS server(s), comma-separated:" WG_DEFAULT_DNS "1.1.1.1,9.9.9.9"
    ask "Enable IPv6 forwarding for WireGuard? [y/N]:" ENABLE_IPV6 "N"
    ask "Protect the UI with Basic Auth via Caddy? [y/N]:" ENABLE_BASICAUTH "N"; BASIC_USER=""; BASIC_PASS=""; if [[ "$ENABLE_BASICAUTH" =~ ^[Yy]$ ]]; then ask "Basic Auth username:" BASIC_USER "admin"; ask_secret "Basic Auth password:" BASIC_PASS; fi
    ask_secret "wg-easy admin password:" WGEASY_ADMIN_PASS
    ask "Restrict UI to IP/CIDR (blank = none):" IP_ALLOW_CIDR ""
    ask "Install & enable UFW (22/tcp, 80/tcp, 443/tcp, ${WG_PORT}/udp)? [Y/n]:" ENABLE_UFW "Y"
    ask "Enable unattended security updates? [Y/n]:" ENABLE_AUTOUPD "Y"; UPD_MAIL=""; if [[ "$ENABLE_AUTOUPD" =~ ^[Yy]$ ]]; then ask "Email notifications for upgrades? (blank = none):" UPD_MAIL "$LE_EMAIL"; fi
    ask "Install & configure fail2ban (sshd + Caddy)? [Y/n]:" ENABLE_F2B "Y"; F2B_BANTIME="1h"; F2B_FINDTIME="10m"; F2B_MAXRETRY="5"
    if [[ "$ENABLE_F2B" =~ ^[Yy]$ ]]; then ask "fail2ban bantime:" F2B_BANTIME "$F2B_BANTIME"; ask "fail2ban findtime:" F2B_FINDTIME "$F2B_FINDTIME"; ask "fail2ban maxretry:" F2B_MAXRETRY "$F2B_MAXRETRY"; fi
    ask "Create a systemd unit to re-up wg-easy on boot? [Y/n]:" ENABLE_COMPOSE_UNIT "Y"
    ask "Purge conflicting configs (authentication/imports/autosave)? [Y/n]:" PURGE_CADDY "Y"
    ask "Force Caddy to use /etc/caddy/Caddyfile (systemd drop-in)? [Y/n]:" FORCE_CADDY_DROPIN "Y"
  fi
}
printf "\n%s=== WireGuard + wg-easy (Docker) behind Caddy/Let's Encrypt (Debian 13) ===%s\n\n" "$BLD" "$CLR" >&3
tui_or_cli

detect_pubip(){ local v="$1" ip=""; case "$v" in 4) ip=$(curl -fsS4 --max-time 5 https://ifconfig.me || true);; 6) ip=$(curl -fsS6 --max-time 5 https://ifconfig.me || true);; esac; [[ -n "$ip" ]] && echo "$ip" || echo "UNKNOWN"; }
PUBIP4=$(detect_pubip 4); PUBIP6=$(detect_pubip 6)
info "Detected public IPs: IPv4=${PUBIP4}, IPv6=${PUBIP6}"

A_RECORDS=$(dig +short A "$WG_DOMAIN" || true); AAAA_RECORDS=$(dig +short AAAA "$WG_DOMAIN" || true)
DNS_OK="NO"; DNS_MATCH_IP="NO"; if [[ -n "$A_RECORDS$AAAA_RECORDS" ]]; then DNS_OK="YES"; if [[ "$A_RECORDS" == *"$PUBIP4"* ]] || { [[ "$PUBIP6" != "UNKNOWN" ]] && [[ "$AAAA_RECORDS" == *"$PUBIP6"* ]]; }; then DNS_MATCH_IP="YES"; fi; fi
info "DNS for ${WG_DOMAIN}: found=${DNS_OK}, points-here=${DNS_MATCH_IP}"
[[ "$DNS_OK" == "YES" ]] || warn "No A/AAAA records found. ACME issuance will fail until DNS is configured."

if (( WT )); then wt_yesno "Confirm" "Proceed with installation?" || { err "Aborted by user."; exit 1; }
else ask "Proceed with installation? [Y/n]:" CONFIRM "Y"; [[ "$CONFIRM" =~ ^[Yy]$ ]] || { err "Aborted by user."; exit 1; }; fi

port_in_use(){ ss -plntu 2>/dev/null | grep -E "LISTEN|UNCONN" | grep -qE "[:.]$1(\s|$)"; }
if port_in_use 80 || port_in_use 443; then warn "Ports 80/443 appear in use. Caddy may fail. Showing listeners:"; ss -plnt | awk 'NR==1 || /:80 |:443 / {print}' >&3; if (( WT )); then wt_yesno "Ports busy" "Continue anyway?" || { err "Please free 80/443 and re-run."; exit 1; } else ask "Continue anyway? [y/N]:" cont_p "N"; [[ "$cont_p" =~ ^[Yy]$ ]] || { err "Please free 80/443 and re-run."; exit 1; }; fi; fi
if ss -plnu | grep -qE "[:.]${WG_PORT}(\s|$)"; then warn "UDP port ${WG_PORT} already in use." >&3; if (( WT )); then wt_yesno "UDP busy" "Continue anyway?" || { err "Please free UDP ${WG_PORT} and re-run."; exit 1; } else ask "Continue anyway? [y/N]:" cont_w "N"; [[ "$cont_w" =~ ^[Yy]$ ]] || { err "Please free UDP ${WG_PORT} and re-run."; exit 1; }; fi; fi

BASIC_HASH=""
if [[ "${ENABLE_BASICAUTH:-N}" =~ ^[Yy]$ ]]; then
  BASIC_USER="$(printf "%s" "${BASIC_USER:-admin}" | tr -cd "A-Za-z0-9._-")"
  if command -v caddy >/dev/null 2>&1; then BASIC_HASH="$(caddy hash-password --plaintext "${BASIC_PASS}" 2>/dev/null | awk '/^\$2[aby]\$/{print; exit}' | tr -d '\r\n' || true)"; fi
  if [[ -z "$BASIC_HASH" ]]; then BASIC_HASH="$(htpasswd -nbB x "${BASIC_PASS}" 2>/dev/null | cut -d: -f2 | sed 's/^\$2y\$/\$2a$/' | tr -d '\r\n' || true)"; fi
  if [[ ! "$BASIC_HASH" =~ ^\$2[aby]\$.+ ]]; then warn "Could not generate a valid bcrypt hash for Caddy basic_auth."; if (( WT )); then wt_yesno "basic_auth Hash Failed" "Disable basic_auth and continue?\n(Choose No to abort)" || { err "Aborting."; exit 1; }; ENABLE_BASICAUTH="N"; else ask "Disable basic_auth and continue? [Y/n]:" PROCEED_NO_BA "Y"; [[ "$PROCEED_NO_BA" =~ ^[Yy]$ ]] && ENABLE_BASICAUTH="N" || { err "Aborting."; exit 1; }; fi; fi
fi

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
)

if [[ "${PURGE_CADDY:-Y}" =~ ^[Yy]$ ]]; then
  run_step "Purge conflicting Caddy configs & AUTOSAVEs" "
  TS=\$(date +%Y%m%d-%H%M%S)
  mkdir -p /etc/caddy/backup-\$TS
  cp -a /etc/caddy/* /etc/caddy/backup-\$TS/ 2>/dev/null || true
  find /etc/caddy -maxdepth 1 -type f ! -name 'Caddyfile' -print -exec mv {} /etc/caddy/backup-\$TS/ \\; || true
  for d in conf.d sites-enabled snippets vhosts d; do [ -e \"/etc/caddy/\$d\" ] && mv \"/etc/caddy/\$d\" \"/etc/caddy/backup-\$TS/\$d\"; done
  [ -f /etc/caddy/caddy.json ] && mv /etc/caddy/caddy.json \"/etc/caddy/backup-\$TS/caddy.json\"
  for f in ${AUTOSAVES[*]}; do rm -f \"\$f\" 2>/dev/null || true; done
  if [[ -s '$CADDYFILE' ]]; then
    awk 'BEGIN{skip=0}
      /^[[:space:]]*authentication[[:space:]]*\\{/ {skip=1; depth=1; next}
      skip==1 { if (\$0 ~ /\\{/) depth++; if (\$0 ~ /\\}/){depth--; if (depth==0){skip=0; next}}; next }
      /^[[:space:]]*import[[:space:]]+/ {next}
      {print}
    ' '$CADDYFILE' > /etc/caddy/Caddyfile.cleaned 2>/dev/null || true
    mv -f /etc/caddy/Caddyfile.cleaned '$CADDYFILE' 2>/dev/null || true
  fi
  "
fi

STEP_MAX=0
STEP_MAX=$((STEP_MAX+1)) # 1 Update/base
STEP_MAX=$((STEP_MAX+1)) # 2 sysctl
STEP_MAX=$((STEP_MAX+1)) # 3 Docker
STEP_MAX=$((STEP_MAX+1)) # 4 compose plugin
STEP_MAX=$((STEP_MAX+1)) # 5 Caddy (+drop-in + autosave purge)
STEP_MAX=$((STEP_MAX+1)) # 6 wg-easy files
STEP_MAX=$((STEP_MAX+1)) # 7 Caddyfile write/sanitize/validate
[[ "${ENABLE_UFW:-Y}" =~ ^[Yy]$ ]] && STEP_MAX=$((STEP_MAX+1))
[[ "${ENABLE_AUTOUPD:-Y}" =~ ^[Yy]$ ]] && STEP_MAX=$((STEP_MAX+1))
[[ "${ENABLE_F2B:-Y}" =~ ^[Yy]$ ]] && STEP_MAX=$((STEP_MAX+1))
STEP_MAX=$((STEP_MAX+1)) # 11 launch
[[ "${ENABLE_COMPOSE_UNIT:-Y}" =~ ^[Yy]$ ]] && STEP_MAX=$((STEP_MAX+1))
STEP_MAX=$((STEP_MAX+1)) # 13 caddy reload
printf "\n" >&3; draw_bar 0

run_step "Update packages & base tools" "apt-get update -qq; apt-get install $APTQ ca-certificates gnupg apt-transport-https curl jq apache2-utils iproute2 dnsutils openssl"
run_step "Configure IP forwarding" "cat > /etc/sysctl.d/99-wireguard-forwarding.conf <<EOF
net.ipv4.ip_forward=1
$([[ "$ENABLE_IPV6" =~ ^[Yy]$ ]] && echo 'net.ipv6.conf.all.forwarding=1')
EOF
sysctl --system >/dev/null"

run_step "Install & enable Docker Engine" "command -v docker >/dev/null || { curl -fsSL https://get.docker.com | sh; }; systemctl enable --now docker"
run_step "Install docker compose plugin" "docker compose version >/dev/null 2>&1 || apt-get install $APTQ docker-compose-plugin"

run_step "Install & enable Caddy (+unit drop-in; remove AUTOSAVEs)" "
if ! command -v caddy >/dev/null; then
  apt-get install $APTQ debian-keyring debian-archive-keyring
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  echo 'deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq && apt-get install $APTQ caddy
fi
systemctl enable --now caddy
mkdir -p $ACCESS_LOG_DIR
chown -R caddy:caddy $ACCESS_LOG_DIR || true
for f in ${AUTOSAVES[*]}; do rm -f \"\$f\" 2>/dev/null || true; done
if [[ '${FORCE_CADDY_DROPIN:-Y}' =~ ^[Yy]$ ]]; then
  mkdir -p '$DROPIN_DIR'
  cat > '$DROPIN_DIR/override.conf' <<OVR
[Service]
ExecStart=
ExecStart=/usr/bin/caddy run --environ --config $CADDYFILE
OVR
  systemctl daemon-reload
fi
"

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

# ===== Build Caddyfile using basic_auth (new name) =====
AUTH_BLOCK=""
if [[ "${ENABLE_BASICAUTH:-N}" =~ ^[Yy]$ && "$BASIC_HASH" =~ ^\$2[aby]\$.+ ]]; then
  read -r -d '' AUTH_BLOCK <<EOT || true
  basic_auth /* {
    $BASIC_USER $BASIC_HASH
  }
EOT
fi

if [[ -n "${IP_ALLOW_CIDR:-}" ]]; then
  read -r -d '' SITE_BODY <<EOS || true
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
$AUTH_BLOCK  reverse_proxy 127.0.0.1:$WG_EASY_PORT
  }

  tls {
    protocols tls1.2 tls1.3
  }
EOS
else
  read -r -d '' SITE_BODY <<EOS || true
  log {
    output file $ACCESS_LOG_DIR/access.log
    format json
  }

$AUTH_BLOCK  reverse_proxy 127.0.0.1:$WG_EASY_PORT

  tls {
    protocols tls1.2 tls1.3
  }
EOS
fi

run_step "Write Caddyfile (admin off); sanitize & validate (no 'authentication')" "
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

# Sanitize legacy imports and caddy-security 'authentication' blocks
awk 'BEGIN{skip=0}
  /^[[:space:]]*authentication[[:space:]]*\\{/ {skip=1; depth=1; next}
  skip==1 { if (\$0 ~ /\\{/) depth++; if (\$0 ~ /\\}/){depth--; if (depth==0){skip=0; next}}; next }
  /^[[:space:]]*import[[:space:]]+/ {next}
  {print}
' '$CADDYFILE' > /etc/caddy/Caddyfile.tmp && mv -f /etc/caddy/Caddyfile.tmp '$CADDYFILE'

# Validate & adapt
caddy validate --config '$CADDYFILE'
caddy adapt    --config '$CADDYFILE' --pretty > /tmp/caddy-adapt.json

# Fail if any caddy-security 'authentication' handler is present
grep -q '\"handler\"\\s*:\\s*\"authentication\"' /tmp/caddy-adapt.json && { echo 'ERROR: Found caddy-security authentication handler in adapted config' >&2; exit 1; }
"

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

if [[ "${ENABLE_F2B:-Y}" =~ ^[Yy]$ ]]; then
  run_step "Install & enable fail2ban (sshd + Caddy)" "
  apt-get install $APTQ fail2ban
  systemctl enable --now fail2ban
  mkdir -p /etc/fail2ban/filter.d
  cat > /etc/fail2ban/filter.d/caddy-httperrors.conf <<'EOF'
[Definition]
failregex = ^\{.*\"status\":(401|403).*\}$
ignoreregex =
EOF
  cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = ${F2B_BANTIME:-1h}
findtime = ${F2B_FINDTIME:-10m}
maxretry = ${F2B_MAXRETRY:-5}

[sshd]
enabled = true
backend = systemd

[caddy-httperrors]
enabled = true
port    = http,https
filter  = caddy-httperrors
logpath = $ACCESS_LOG_DIR/access.log
backend = auto
EOF
  systemctl restart fail2ban
  "
fi

run_step "Launch wg-easy container" "
cd '$APP_DIR'
docker compose pull
docker compose up -d
"

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

run_step "Reload Caddy (activate config; purge AUTOSAVEs again)" "
for f in ${AUTOSAVES[*]}; do rm -f \"\$f\" 2>/dev/null || true; done
caddy validate --config '$CADDYFILE'
systemctl reload caddy || systemctl restart caddy
"

printf "\n\n%s=== Running sanity checks ===%s\n" "$BLD" "$CLR" >&3
okc=0; flc=0
chk(){ local d=\"$1\"; shift; if bash -c \"$@\" >/dev/null 2>&1; then ok \"$d\"; ((okc++)); else warn \"$d - attention\"; ((flc++)); fi; }
chk "IPv4 forwarding enabled" 'sysctl -n net.ipv4.ip_forward | grep -q "^1$"'
[[ "${ENABLE_IPV6:-N}" =~ ^[Yy]$ ]] && chk "IPv6 forwarding enabled" 'sysctl -n net.ipv6.conf.all.forwarding | grep -q "^1$"'
chk "Docker active" 'systemctl is-active --quiet docker'
chk "Caddy active" 'systemctl is-active --quiet caddy'
chk "wg-easy container running" 'docker ps --format "{{.Names}}" | grep -q "^wg-easy$"'
chk "WireGuard UDP :${WG_PORT}" 'ss -plnu | grep -q ":${WG_PORT} "'
chk "Caddy on :80/:443" 'ss -plnt | grep -q ":80 " && ss -plnt | grep -q ":443 "'
chk "wg-easy UI on 127.0.0.1:${WG_EASY_PORT}" 'ss -plnt | grep -q "127.0.0.1:${WG_EASY_PORT} "'

REDIR_OUT=$(curl -sI "http://$WG_DOMAIN/" || true); REDIR_CODE=$(printf "%s" "$REDIR_OUT" | awk '/^HTTP/{print $2; exit}'); REDIR_LOC=$(printf "%s" "$REDIR_OUT" | awk '/^Location:/ {print $2; exit}' | tr -d '\r')
if [[ "$REDIR_CODE" =~ ^30[18]$ ]] && [[ "$REDIR_LOC" == "https://$WG_DOMAIN/"* ]]; then ok "HTTP→HTTPS redirect in place (${REDIR_CODE} to ${REDIR_LOC})"; else warn "HTTP→HTTPS redirect not confirmed"; fi
printf "\nSanity check summary: %d passed, %d attention.\n" "$okc" "$flc" >&3
((flc==0)) || warn "Some items may resolve after DNS/ACME propagation."

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
IPv6 Fwd:      $( [[ "${ENABLE_IPV6:-N}" =~ ^[Yy]$ ]] && echo "ENABLED" || echo "DISABLED" )
Basic Auth:    $( [[ "${ENABLE_BASICAUTH:-N}" =~ ^[Yy]$ ]] && echo "ENABLED (user: ${BASIC_USER})" || echo "DISABLED" )
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
  - Reload Caddy:     systemctl reload caddy
  - Inspect adapted:  less /tmp/caddy-adapt.json

SUMMARY

exit 0
