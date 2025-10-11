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
if p
