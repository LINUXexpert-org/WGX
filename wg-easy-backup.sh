#!/usr/bin/env bash
# wg-easy-backup.sh - Backup/restore for wg-easy + Caddy deployment created by install-wg-easy.sh
#
# Backs up:
#   - /opt/wg-easy (compose.yaml, .env, config/)
#   - /etc/caddy/Caddyfile
#   - /etc/fail2ban/jail.local and /etc/fail2ban/filter.d/caddy-httperrors.conf (if present)
#   - /etc/sysctl.d/99-wireguard-forwarding.conf
#   - /etc/systemd/system/wg-easy-compose.service (if present)
#   - UFW rules snapshot (text dumps), Docker compose & image/version info
#   - Optional: /var/lib/caddy (certs/keys) with --include-certs (HIGHLY SENSITIVE)
#
# Restore places files back, reloads daemons, and re-ups the compose stack.
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
LOG="wg-easy-backup-restore-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

need_root(){ [[ $EUID -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }; }
need_root

APP_DIR="/opt/wg-easy"
CADDYFILE="/etc/caddy/Caddyfile"
CADDY_STATE_DIR="/var/lib/caddy"
F2B_JAIL="/etc/fail2ban/jail.local"
F2B_FILTER="/etc/fail2ban/filter.d/caddy-httperrors.conf"
SYSCTL_FILE="/etc/sysctl.d/99-wireguard-forwarding.conf"
COMPOSE_UNIT="/etc/systemd/system/wg-easy-compose.service"

backup() {
  local include_certs="no"
  [[ "${1-}" == "--include-certs" ]] && include_certs="yes"
  local ts="$(date +%Y%m%d-%H%M%S)"
  local out="wg-easy-backup-${ts}.tgz"

  echo "[INFO] Creating backup: ${out}"
  tmpdir="$(mktemp -d)"
  mkdir -p "$tmpdir/meta"

  # Meta snapshots (text)
  { systemctl is-enabled docker || true; systemctl is-enabled caddy || true; } > "$tmpdir/meta/systemd-enabled.txt" 2>&1 || true
  docker version > "$tmpdir/meta/docker-version.txt" 2>&1 || true
  docker images > "$tmpdir/meta/docker-images.txt" 2>&1 || true
  docker compose -f "$APP_DIR/compose.yaml" ls > "$tmpdir/meta/docker-compose-ls.txt" 2>&1 || true
  docker compose -f "$APP_DIR/compose.yaml" ps > "$tmpdir/meta/docker-compose-ps.txt" 2>&1 || true
  ufw status numbered > "$tmpdir/meta/ufw-status.txt" 2>&1 || true
  ss -plnt > "$tmpdir/meta/listeners-tcp.txt" 2>&1 || true
  ss -plnu > "$tmpdir/meta/listeners-udp.txt" 2>&1 || true

  # Copy configs
  [[ -d "$APP_DIR" ]] && rsync -a "$APP_DIR"/ "$tmpdir/opt-wg-easy/" || echo "[WARN] $APP_DIR not found; skipping."
  [[ -f "$CADDYFILE" ]] && install -D -m 0644 "$CADDYFILE" "$tmpdir/etc-caddy/Caddyfile" || echo "[WARN] $CADDYFILE not found; skipping."
  [[ -f "$F2B_JAIL" ]] && install -D -m 0644 "$F2B_JAIL" "$tmpdir/etc-fail2ban/jail.local" || true
  [[ -f "$F2B_FILTER" ]] && install -D -m 0644 "$F2B_FILTER" "$tmpdir/etc-fail2ban/filter.d/caddy-httperrors.conf" || true
  [[ -f "$SYSCTL_FILE" ]] && install -D -m 0644 "$SYSCTL_FILE" "$tmpdir/etc-sysctl/99-wireguard-forwarding.conf" || true
  [[ -f "$COMPOSE_UNIT" ]] && install -D -m 0644 "$COMPOSE_UNIT" "$tmpdir/systemd/wg-easy-compose.service" || true

  # Optional cert state
  if [[ "$include_certs" == "yes" && -d "$CADDY_STATE_DIR" ]]; then
    echo "[INFO] Including Caddy state (certs/keys) — handle securely!"
    rsync -a "$CADDY_STATE_DIR"/ "$tmpdir/var-lib-caddy/"
  fi

  # Include the most recent install log if present
  lastlog="$(ls -1t ./install-wg-easy-*.log 2>/dev/null | head -n1 || true)"
  [[ -n "$lastlog" ]] && install -D -m 0644 "$lastlog" "$tmpdir/meta/last-install-log.txt" || true

  tar -C "$tmpdir" -czf "$out" .
  rm -rf "$tmpdir"
  echo "[OK] Backup written: $(pwd)/$out"
  echo "[OK] Log saved: $(pwd)/$LOG"
}

restore() {
  local tarball="${1-}"
  [[ -f "$tarball" ]] || { echo "[ERROR] Tarball not found: $tarball" >&2; exit 1; }

  echo "[INFO] Restoring from: $tarball"
  tmpdir="$(mktemp -d)"
  tar -C "$tmpdir" -xzf "$tarball"

  # Stop services / containers first (best-effort)
  systemctl stop wg-easy-compose.service 2>/dev/null || true
  (cd "$APP_DIR" 2>/dev/null && docker compose down) || true
  systemctl stop caddy 2>/dev/null || true

  # Restore files (with .bak if existing)
  install -d "$APP_DIR"
  if [[ -d "$tmpdir/opt-wg-easy" ]]; then
    [[ -d "$APP_DIR" ]] && rsync -a "$APP_DIR"/ "$APP_DIR.bak.$(date +%s)"/ || true
    rsync -a "$tmpdir/opt-wg-easy"/ "$APP_DIR"/
  fi

  if [[ -f "$tmpdir/etc-caddy/Caddyfile" ]]; then
    [[ -f "$CADDYFILE" ]] && cp -a "$CADDYFILE" "$CADDYFILE.bak.$(date +%s)"
    install -D -m 0644 "$tmpdir/etc-caddy/Caddyfile" "$CADDYFILE"
  fi

  if [[ -f "$tmpdir/etc-fail2ban/jail.local" ]]; then
    [[ -f "$F2B_JAIL" ]] && cp -a "$F2B_JAIL" "$F2B_JAIL.bak.$(date +%s)"
    install -D -m 0644 "$tmpdir/etc-fail2ban/jail.local" "$F2B_JAIL"
  fi
  if [[ -f "$tmpdir/etc-fail2ban/filter.d/caddy-httperrors.conf" ]]; then
    [[ -f "$F2B_FILTER" ]] && cp -a "$F2B_FILTER" "$F2B_FILTER.bak.$(date +%s)"
    install -D -m 0644 "$tmpdir/etc-fail2ban/filter.d/caddy-httperrors.conf" "$F2B_FILTER"
  fi

  if [[ -f "$tmpdir/etc-sysctl/99-wireguard-forwarding.conf" ]]; then
    [[ -f "$SYSCTL_FILE" ]] && cp -a "$SYSCTL_FILE" "$SYSCTL_FILE.bak.$(date +%s)"
    install -D -m 0644 "$tmpdir/etc-sysctl/99-wireguard-forwarding.conf" "$SYSCTL_FILE"
    sysctl --system >/dev/null 2>&1 || true
  fi

  if [[ -f "$tmpdir/systemd/wg-easy-compose.service" ]]; then
    install -D -m 0644 "$tmpdir/systemd/wg-easy-compose.service" "$COMPOSE_UNIT"
    systemctl daemon-reload
    systemctl enable --now wg-easy-compose.service
  fi

  # Optional Caddy cert state restore
  if [[ -d "$tmpdir/var-lib-caddy" ]]; then
    rsync -a "$tmpdir/var-lib-caddy"/ "$CADDY_STATE_DIR"/
    chown -R caddy:caddy "$CADDY_STATE_DIR" || true
  fi

  # Bring everything back
  systemctl enable --now caddy || true
  (cd "$APP_DIR" && docker compose up -d)
  systemctl reload caddy || systemctl restart caddy
  systemctl restart fail2ban 2>/dev/null || true

  rm -rf "$tmpdir"
  echo "[OK] Restore complete."
  echo "[OK] Log saved: $(pwd)/$LOG"
}

case "${1-}" in
  backup)   shift; backup "${1-}" ;;
  restore)  shift; restore "${1-}" ;;
  *) echo "Usage: $0 {backup [--include-certs] | restore <backup.tgz>}" >&2; exit 1;;
esac
