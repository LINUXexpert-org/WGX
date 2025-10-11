#!/usr/bin/env bash
# uninstall-wg-easy.sh - Interactive, logged uninstaller for the wg-easy + Caddy setup
# created by install-wg-easy.sh on Debian 13.
#
# Removes the wg-easy compose stack, optional systemd unit, optional Caddyfile and
# systemd override, optional fail2ban jail, optional UFW rules, and offers to restore
# a previous /etc/caddy backup captured by the installer. Leaves Docker/Caddy packages
# installed by default (you can choose to remove them).
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
RED=$'\e[31m'; GRN=$'\e[32m'; BLU=$'\e[34m'; YLW=$'\e[33m'; BLD=$'\e[1m'; CLR=$'\e[0m'
err()  { printf "%s[ERROR]%s %s\n" "$RED" "$CLR" "$*" >&3; }
ok()   { printf "%s[OK]%s    %s\n" "$GRN" "$CLR" "$*" >&3; }
info() { printf "%s[INFO]%s  %s\n" "$BLU" "$CLR" "$*" >&3; }
warn() { printf "%s[WARN]%s  %s\n" "$YLW" "$CLR" "$*" >&3; }

require_root() { [[ $EUID -eq 0 ]] || { err "Please run as root (sudo)."; exit 1; }; }

# ===== Console I/O helpers (FD3 prints, /dev/tty reads) =====
ask() {  # ask "Prompt" var [default]
  local prompt="$1" __var="$2" def="${3-}" reply
  if [[ -n "$def" ]]; then printf "%s [default: %s] " "$prompt" "$def" >&3; else printf "%s " "$prompt" >&3; fi
  IFS= read -r reply < /dev/tty
  [[ -z "$reply" && -n "$def" ]] && reply="$def"
  printf -v "$__var" "%s" "$reply"
}
ask_yn() { local p="$1" v="$2" d="${3:-Y}"; ask "$p [Y/n]:" "$v" "$d"; [[ "${!v}" =~ ^[Yy]$|^$ ]]; }
ask_req() { local prompt="$1" __var="$2" def="${3-}"; while true; do ask "$prompt" "$__var" "$def"; [[ -n "${!__var}" ]] && break; printf "(value required)\n" >&3; done; }

# ===== Percentage bar =====
STEP_NUM=0; STEP_MAX=1; BAR_WIDTH=42
repeat_char() { local n=$1 c="$2"; [[ $n -le 0 ]] && return 0; printf "%0.s${c}" $(seq 1 "$n"); }
draw_bar()   { local pct=$1; (( pct<0 )) && pct=0; (( pct>100 )) && pct=100; local filled=$(( pct * BAR_WIDTH / 100 )); printf "\r[%-*s] %3d%%" "$BAR_WIDTH" "$(repeat_char "$filled" "#")" "$pct" >&3; }
advance_bar(){ STEP_NUM=$((STEP_NUM+1)); (( STEP_MAX < 1 )) && STEP_MAX=1; local pct=$(( STEP_NUM * 100 / STEP_MAX )); draw_bar "$pct"; }

# ===== Step runner =====
run_step() {
  local title="$1"; shift
  printf "\nStep $((STEP_NUM+1))/$STEP_MAX: %s\n" "$title" >&3
  {
    printf "--- [%s] %s ---\n" "$(date -Is)" "$title" >&2
    bash -o pipefail -c "$*" >&2
    printf "--- [%s] %s (OK) ---\n" "$(date -Is)" "$title" >&2
  }
  advance_bar
}

# ===== Trap & Logging =====
cleanup_on_error(){ printf "\n"; err "An unexpected error occurred. See the log: $LOGFILE"; }
trap cleanup_on_error ERR

LOGFILE="$(pwd)/uninstall-wg-easy-$(date +%Y%m%d-%H%M%S).log"
exec 3>&1
exec > >(tee -a "$LOGFILE") 2>&1

export DEBIAN_FRONTEND=noninteractive
APTQ="-o Dpkg::Use-Pty=0 -y -qq"

require_root

# ===== Paths/Artifacts created by the installer =====
APP_DIR="/opt/wg-easy"
COMPOSE_FILE="$APP_DIR/compose.yaml"
ENV_FILE="$APP_DIR/.env"
CONFIG_DIR="$APP_DIR/config"
COMPOSE_UNIT="/etc/systemd/system/wg-easy-compose.service"
CADDYFILE="/etc/caddy/Caddyfile"
CADDY_DROPIN_DIR="/etc/systemd/system/caddy.service.d"
CADDY_DROPIN="$CADDY_DROPIN_DIR/override.conf"
CADDY_ACCESS_LOG="/var/log/caddy/access.log"
SYSCTL_FILE="/etc/sysctl.d/99-wireguard-forwarding.conf"
F2B_JAIL="/etc/fail2ban/jail.local"
F2B_FILTER="/etc/fail2ban/filter.d/caddy-httperrors.conf"

# ===== Detect things =====
HAS_DOCKER=0; command -v docker >/dev/null 2>&1 && HAS_DOCKER=1
HAS_CADDY=0;  command -v caddy  >/dev/null 2>&1 && HAS_CADDY=1
HAS_UFW=0;    command -v ufw    >/dev/null 2>&1 && HAS_UFW=1
HAS_F2B=0;    command -v fail2ban-client >/dev/null 2>&1 && HAS_F2B=1

# Guess VPN port from compose/.env (fallback 51820)
WG_PORT="51820"
if [[ -s "$ENV_FILE" ]]; then
  WG_PORT=$(awk -F= '/^WG_PORT=/{print $2}' "$ENV_FILE" 2>/dev/null || echo "51820")
fi
# Guess UI port (fallback 51821)
WG_EASY_PORT="51821"
if [[ -s "$COMPOSE_FILE" ]]; then
  WG_EASY_PORT=$(awk -F: '/127\.0\.0\.1:[0-9]+:[0-9]+\/tcp/{gsub(/"|\/tcp|127\.0\.0\.1:/,"",$0); split($0,a,":"); print a[1]}' "$COMPOSE_FILE" 2>/dev/null || echo "51821")
fi

# Find latest Caddy backup directory
LATEST_CADDY_BAK="$(ls -1dt /etc/caddy/backup-* 2>/dev/null | head -n1 || true)"

# ===== Intro summary =====
printf "\n${BLD}wg-easy Uninstaller${CLR}\n" >&3
info "Log file: $LOGFILE"
printf "%s\n" "
Detected:
  Docker:      $([[ $HAS_DOCKER -eq 1 ]] && echo "yes" || echo "no")
  Caddy:       $([[ $HAS_CADDY -eq 1 ]] && echo "yes" || echo "no")
  UFW:         $([[ $HAS_UFW   -eq 1 ]] && echo "yes" || echo "no")
  fail2ban:    $([[ $HAS_F2B   -eq 1 ]] && echo "yes" || echo "no")
  Compose dir: $([[ -d "$APP_DIR" ]] && echo "$APP_DIR" || echo "missing")
  Compose file:$([[ -s "$COMPOSE_FILE" ]] && echo "$COMPOSE_FILE" || echo "missing")
  Systemd unit:$([[ -s "$COMPOSE_UNIT" ]] && echo "$COMPOSE_UNIT" || echo "missing")
  Sysctl file: $([[ -s "$SYSCTL_FILE" ]] && echo "$SYSCTL_FILE" || echo "missing")
  Caddyfile:   $([[ -s "$CADDYFILE" ]] && echo "$CADDYFILE" || echo "missing")
  Caddy drop-in:$([[ -s "$CADDY_DROPIN" ]] && echo "$CADDY_DROPIN" || echo "missing")
  Latest Caddy backup: ${LATEST_CADDY_BAK:-none}
" >&3

# ===== Confirm =====
ask_yn "Proceed with uninstall of wg-easy stack (containers, unit, config)?" PROCEED "Y" || { warn "Aborted by user."; exit 0; }

# ===== Choices =====
REMOVE_STACK="Y"
RESTORE_CADDY="N"
REMOVE_CADDYFILE="N"
REMOVE_DROPIN="Y"
RELOAD_CADDY="Y"
REMOVE_F2B_JAIL="Y"
REMOVE_UFW_RULES="Y"
REMOVE_SYSCTL="Y"
REMOVE_APP_DIR="Y"
REMOVE_DOCKER="N"
REMOVE_CADDY_PKG="N"

[[ -n "$LATEST_CADDY_BAK" ]] && ask_yn "Restore latest Caddy backup from '$LATEST_CADDY_BAK'?" RESTORE_CADDY "N"
ask_yn "Remove current /etc/caddy/Caddyfile (if we don't restore a backup)?" REMOVE_CADDYFILE "N"
ask_yn "Remove systemd drop-in forcing /etc/caddy/Caddyfile?" REMOVE_DROPIN "Y"
ask_yn "Remove fail2ban jail/filter created by installer?" REMOVE_F2B_JAIL "Y"
ask_yn "Remove UFW rules for 80/tcp, 443/tcp, ${WG_PORT}/udp (if present)?" REMOVE_UFW_RULES "Y"
ask_yn "Remove sysctl forwarding file ($SYSCTL_FILE)?" REMOVE_SYSCTL "Y"
ask_yn "Delete /opt/wg-easy directory?" REMOVE_APP_DIR "Y"
ask_yn "Also remove Docker Engine (may affect other services)? " REMOVE_DOCKER "N"
ask_yn "Also remove Caddy package (may affect other sites)? " REMOVE_CADDY_PKG "N"

# ===== Compute steps =====
STEP_MAX=0
# stop compose, remove containers
STEP_MAX=$((STEP_MAX+1))
# remove systemd unit
[[ -s "$COMPOSE_UNIT" ]] && STEP_MAX=$((STEP_MAX+1))
# caddy file/restore + drop-in + reload
if [[ "$RESTORE_CADDY" == "Y" || "$REMOVE_CADDYFILE" == "Y" || "$REMOVE_DROPIN" == "Y" || "$RELOAD_CADDY" == "Y" ]]; then
  STEP_MAX=$((STEP_MAX+1))
fi
# fail2ban
[[ "$REMOVE_F2B_JAIL" == "Y" && $HAS_F2B -eq 1 ]] && STEP_MAX=$((STEP_MAX+1))
# ufw
[[ "$REMOVE_UFW_RULES" == "Y" && $HAS_UFW -eq 1 ]] && STEP_MAX=$((STEP_MAX+1))
# sysctl
[[ "$REMOVE_SYSCTL" == "Y" && -f "$SYSCTL_FILE" ]] && STEP_MAX=$((STEP_MAX+1))
# remove app dir
[[ "$REMOVE_APP_DIR" == "Y" && -d "$APP_DIR" ]] && STEP_MAX=$((STEP_MAX+1))
# remove docker
[[ "$REMOVE_DOCKER" == "Y" && $HAS_DOCKER -eq 1 ]] && STEP_MAX=$((STEP_MAX+1))
# remove caddy pkg
[[ "$REMOVE_CADDY_PKG" == "Y" && $HAS_CADDY -eq 1 ]] && STEP_MAX=$((STEP_MAX+1))

printf "\n"; draw_bar 0

# 1) Stop and remove wg-easy stack
if [[ "$REMOVE_STACK" == "Y" ]]; then
  run_step "Stop & remove wg-easy containers/volumes" "
  set -Eeuo pipefail
  if [[ -s '$COMPOSE_FILE' ]]; then
    cd '$APP_DIR'
    if command -v docker >/dev/null 2>&1; then
      docker compose -f '$COMPOSE_FILE' down -v || true
    fi
  else
    # Fallback: stop by name if compose file missing
    if command -v docker >/dev/null 2>&1; then
      docker ps -aq --filter 'name=wg-easy' | xargs -r docker rm -f
      docker volume ls -q | grep -E '^wg-easy' | xargs -r docker volume rm
    fi
  fi
  "
fi

# 2) Remove systemd unit
if [[ -s "$COMPOSE_UNIT" ]]; then
  run_step "Disable & remove systemd unit wg-easy-compose.service" "
  systemctl disable --now wg-easy-compose.service || true
  rm -f '$COMPOSE_UNIT'
  systemctl daemon-reload
  "
fi

# 3) Caddy restore/remove & drop-in
if [[ "$RESTORE_CADDY" == "Y" || "$REMOVE_CADDYFILE" == "Y" || "$REMOVE_DROPIN" == "Y" || "$RELOAD_CADDY" == "Y" ]]; then
  run_step "Caddy restore/remove config & drop-in" "
  set -Eeuo pipefail
  if [[ '$RESTORE_CADDY' == 'Y' && -d '$LATEST_CADDY_BAK' ]]; then
    cp -a '$LATEST_CADDY_BAK'/* /etc/caddy/ 2>/dev/null || true
    echo 'Restored Caddy backup: $LATEST_CADDY_BAK' >&2
  elif [[ '$REMOVE_CADDYFILE' == 'Y' ]]; then
    mv -f '$CADDYFILE' '/etc/caddy/Caddyfile.removed.$(date +%s)' 2>/dev/null || rm -f '$CADDYFILE'
  fi

  if [[ '$REMOVE_DROPIN' == 'Y' ]]; then
    rm -f '$CADDY_DROPIN'
    # If dir is empty, remove it
    rmdir '$CADDY_DROPIN_DIR' 2>/dev/null || true
    systemctl daemon-reload
  fi

  if command -v caddy >/dev/null 2>&1; then
    if [[ -s '$CADDYFILE' ]]; then
      caddy validate --config '$CADDYFILE' || true
    fi
  fi

  if systemctl is-enabled caddy >/dev/null 2>&1; then
    systemctl reload caddy || systemctl restart caddy || true
  fi
  "
fi

# 4) fail2ban cleanup
if [[ "$REMOVE_F2B_JAIL" == "Y" && $HAS_F2B -eq 1 ]]; then
  run_step "Remove fail2ban jail/filter (caddy-httperrors) and reload" "
  set -Eeuo pipefail
  if [[ -s '$F2B_JAIL' ]]; then
    sed -i '/\\[caddy-httperrors\\]/,/^$/d' '$F2B_JAIL' || true
    # Also remove any custom DEFAULTS we added? Keep general sshd config.
  fi
  rm -f '$F2B_FILTER'
  systemctl restart fail2ban || true
  "
fi

# 5) UFW rules
if [[ "$REMOVE_UFW_RULES" == "Y" && $HAS_UFW -eq 1 ]]; then
  run_step "Remove UFW rules for 80/tcp, 443/tcp, ${WG_PORT}/udp" "
  set -Eeuo pipefail
  ufw status numbered | sed -n '1,120p' >&2 || true
  ufw delete allow 80/tcp    || true
  ufw delete allow 443/tcp   || true
  ufw delete allow ${WG_PORT}/udp || true
  "
fi

# 6) Sysctl
if [[ "$REMOVE_SYSCTL" == "Y" && -f "$SYSCTL_FILE" ]]; then
  run_step "Remove sysctl forwarding file and reload" "
  rm -f '$SYSCTL_FILE'
  sysctl --system >/dev/null || true
  "
fi

# 7) Remove app dir
if [[ "$REMOVE_APP_DIR" == "Y" && -d "$APP_DIR" ]]; then
  run_step "Delete application directory ($APP_DIR)" "
  rm -rf '$APP_DIR'
  "
fi

# 8) Remove Docker Engine (optional)
if [[ "$REMOVE_DOCKER" == "Y" && $HAS_DOCKER -eq 1 ]]; then
  run_step "Remove Docker Engine & compose plugin (optional)" "
  apt-get purge $APTQ docker.io docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || true
  apt-get autoremove $APTQ || true
  rm -rf /var/lib/docker /var/lib/containerd || true
  systemctl daemon-reload
  "
fi

# 9) Remove Caddy package (optional)
if [[ "$REMOVE_CADDY_PKG" == "Y" && $HAS_CADDY -eq 1 ]]; then
  run_step "Remove Caddy package (optional)" "
  systemctl disable --now caddy || true
  apt-get purge $APTQ caddy || true
  apt-get autoremove $APTQ || true
  systemctl daemon-reload
  "
fi

# ===== Wrap up =====
printf "\n${BLD}Uninstall complete.${CLR}\n" >&3
ok "Log file: $LOGFILE"
printf "%s\n" "
What we attempted to remove:
  - wg-easy containers/volumes and compose files
  - systemd unit: $COMPOSE_UNIT
  - Caddy override drop-in: $CADDY_DROPIN (per your choice)
  - Caddyfile restored/removed (per your choice). If Caddy remains installed, verify:
      sudo caddy validate --config /etc/caddy/Caddyfile
      sudo systemctl reload caddy
  - fail2ban jail/filter (per your choice)
  - UFW rules for 80/tcp, 443/tcp, ${WG_PORT}/udp (per your choice)
  - sysctl forwarding file (per your choice)
  - app dir: $APP_DIR (per your choice)
  - Docker/Caddy packages (optional, per your choice)
" >&3

exit 0
