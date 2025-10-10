#!/usr/bin/env bash
# wg-easy-uninstall.sh - Safe removal of wg-easy + related config from install-wg-easy.sh
#
# Prompts you to keep/remove data, caddy config, fail2ban bits, and (optionally) packages.
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
LOG="wg-easy-uninstall-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

need_root(){ [[ $EUID -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }; }
need_root

APP_DIR="/opt/wg-easy"
CADDYFILE="/etc/caddy/Caddyfile"
F2B_JAIL="/etc/fail2ban/jail.local"
F2B_FILTER="/etc/fail2ban/filter.d/caddy-httperrors.conf"
SYSCTL_FILE="/etc/sysctl.d/99-wireguard-forwarding.conf"
COMPOSE_UNIT="/etc/systemd/system/wg-easy-compose.service"

yn() { local p="$1" def="${2:-y}" r; read -rp "$p " r; r="${r:-$def}"; [[ "$r" =~ ^[Yy]$ ]]; }
pause(){ read -rp "Press Enter to continue... " _; }

echo "=== wg-easy uninstall ==="
echo "This will stop containers and optionally remove configs and related entries."
yn "Proceed? [Y/n]:" "y" || { echo "Aborted."; exit 0; }

# Stop compose, disable unit
if systemctl is-enabled wg-easy-compose.service >/dev/null 2>&1; then
  echo "[INFO] Disabling wg-easy-compose.service"
  systemctl disable --now wg-easy-compose.service || true
fi
systemctl daemon-reload || true

if [[ -f "$APP_DIR/compose.yaml" ]]; then
  echo "[INFO] Bringing compose down"
  (cd "$APP_DIR" && docker compose down) || true
fi

# Remove unit file
if [[ -f "$COMPOSE_UNIT" ]]; then
  echo "[INFO] Removing $COMPOSE_UNIT"
  rm -f "$COMPOSE_UNIT"
  systemctl daemon-reload || true
fi

# Optionally remove /opt/wg-easy
if yn "Remove wg-easy application directory ($APP_DIR)? [y/N]:" "n"; then
  backup="/root/wg-easy-removed-$(date +%s)"
  echo "[INFO] Moving $APP_DIR to $backup"
  mv "$APP_DIR" "$backup" 2>/dev/null || rm -rf "$APP_DIR"
else
  echo "[INFO] Preserving $APP_DIR"
fi

# Caddy handling
if [[ -f "$CADDYFILE" ]]; then
  echo
  echo "Caddyfile detected at $CADDYFILE."
  echo "If this file was dedicated to wg-easy, you can remove it."
  if yn "Backup and remove $CADDYFILE? [y/N]:" "n"; then
    cp -a "$CADDYFILE" "${CADDYFILE}.bak.$(date +%s)"
    rm -f "$CADDYFILE"
    systemctl reload caddy || systemctl restart caddy || true
    echo "[OK] Caddy reloaded without that file."
  else
    echo "[INFO] Leaving $CADDYFILE untouched."
  fi
fi

# fail2ban bits
if [[ -f "$F2B_FILTER" || -f "$F2B_JAIL" ]]; then
  echo
  echo "fail2ban rules were added for Caddy."
  if yn "Remove caddy-httperrors filter and jail entries? [y/N]:" "n"; then
    [[ -f "$F2B_FILTER" ]] && { cp -a "$F2B_FILTER" "$F2B_FILTER.bak.$(date +%s)"; rm -f "$F2B_FILTER"; }
    # Attempt to surgically comment caddy-httperrors in jail.local
    if [[ -f "$F2B_JAIL" ]]; then
      cp -a "$F2B_JAIL" "$F2B_JAIL.bak.$(date +%s)"
      awk 'BEGIN{skip=0} /^\[caddy-httperrors\]/{skip=1} skip && NF==0{skip=0; next} !skip{print}' "$F2B_JAIL" > "${F2B_JAIL}.new" && mv "${F2B_JAIL}.new" "$F2B_JAIL"
    fi
    systemctl restart fail2ban || true
  else
    echo "[INFO] Leaving fail2ban configuration as-is."
  fi
fi

# sysctl entry
if [[ -f "$SYSCTL_FILE" ]]; then
  if yn "Remove sysctl forwarding file ($SYSCTL_FILE)? [y/N]:" "n"; then
    rm -f "$SYSCTL_FILE"
    sysctl --system >/dev/null 2>&1 || true
  fi
fi

# Docker assets
if yn "Prune dangling Docker images/volumes related to wg-easy? [y/N]:" "n"; then
  docker volume prune -f || true
  docker image prune -f || true
fi

# Packages optional removal
if yn "Remove Caddy package? [y/N]:" "n"; then apt-get -y purge caddy || true; fi
if yn "Remove fail2ban package? [y/N]:" "n"; then apt-get -y purge fail2ban || true; fi
if yn "Remove Docker Engine & compose plugin? [y/N]:" "n"; then
  systemctl disable --now docker || true
  apt-get -y purge docker-ce docker-ce-cli containerd.io docker-compose-plugin || true
fi

echo
echo "[OK] Uninstall steps complete."
echo "[OK] Log saved: $(pwd)/$LOG"
