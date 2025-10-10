#!/usr/bin/env bash
# wg-easy-healthcheck.sh - Periodic healthcheck for the wg-easy + Caddy stack
#
# Checks:
#  - Services: docker, caddy (+ optional fail2ban, ufw, unattended-upgrades)
#  - Container: wg-easy running
#  - Ports: 80/443 TCP; WireGuard UDP (from /opt/wg-easy/.env WG_PORT, default 51820)
#  - HTTP->HTTPS redirect (expects 301/308 to https://<domain>/...)
#  - HTTPS reachability
#  - TLS expiry (warn/crit thresholds) + issuer
#  - DNS A/AAAA points at this server’s public IP (v4/v6 best-effort)
# Outputs: human-readable by default; optional --json and --webhook POST
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

# -------- Defaults & CLI --------
DOMAIN=""
WARN_DAYS=21
CRIT_DAYS=7
JSON=0
WEBHOOK=""
LOGFILE="./wg-easy-health-$(date +%Y%m%d-%H%M%S).log"

usage() {
  cat <<USAGE
Usage: $0 --domain vpn.example.com [options]

Options:
  --domain <host>         FQDN for wg-easy web UI (required)
  --warn-days <N>         TLS expiry warning threshold (default: ${WARN_DAYS})
  --crit-days <N>         TLS expiry critical threshold (default: ${CRIT_DAYS})
  --json                  Emit machine-readable JSON summary to stdout
  --webhook <URL>         POST JSON result to this URL (if given)
  --log <path>            Write a full log to this file (default: ${LOGFILE})
  -h, --help              Show this help

Exit codes: 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN
USAGE
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2;;
    --warn-days) WARN_DAYS="${2:-}"; shift 2;;
    --crit-days) CRIT_DAYS="${2:-}"; shift 2;;
    --json) JSON=1; shift;;
    --webhook) WEBHOOK="${2:-}"; shift 2;;
    --log) LOGFILE="${2:-}"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1" >&2; usage; exit 3;;
  esac
done
[[ -n "$DOMAIN" ]] || { echo "ERROR: --domain is required" >&2; usage; exit 3; }

# Logging: capture everything (script output still goes to console)
exec > >(tee -a "$LOGFILE") 2>&1

# -------- Helpers --------
OKS=0; WARN=0; CRIT=0
RESULTS=()   # human lines
KV=()        # key=value for JSON

hr() { printf -- "----------------------------------------\n"; }
add_kv() { KV+=("$1"); }  # k=v
add_res() { RESULTS+=("$1"); echo "$1"; }

inc_ok(){ OKS=$((OKS+1)); }
inc_warn(){ WARN=$((WARN+1)); }
inc_crit(){ CRIT=$((CRIT+1)); }

# best-effort public IPs (no failure if network restricted)
pub_ip4() { curl -fsS4 --max-time 5 https://ifconfig.me || true; }
pub_ip6() { curl -fsS6 --max-time 5 https://ifconfig.me || true; }

file_get_var() { # file_get_var <file> <key> <default>
  local f="$1" k="$2" def="${3-}" v
  [[ -f "$f" ]] || { printf "%s" "$def"; return 0; }
  v="$(awk -F= -v k="$k" '$1==k{print $2}' "$f" | tail -n1)"
  v="${v:-$def}"
  printf "%s" "$v"
}

check_service() { # check_service <systemd-name> <label>
  local svc="$1" label="$2" en ac
  en="disabled"; ac="inactive"
  systemctl is-enabled "$svc" >/dev/null 2>&1 && en="enabled"
  systemctl is-active --quiet "$svc" && ac="active"
  if [[ "$en" == "enabled" && "$ac" == "active" ]]; then
    add_res "[OK] ${label}: enabled + active"; inc_ok
  else
    add_res "[WARN] ${label}: enabled=${en}, active=${ac}"; inc_warn
  fi
  add_kv "${svc}_enabled=${en}"
  add_kv "${svc}_active=${ac}"
}

check_port_tcp() { # check_port_tcp <port>
  local p="$1"
  if ss -plnt | grep -qE "LISTEN.*[:.]${p} "; then
    add_res "[OK] TCP :${p} listening"; inc_ok
  else
    add_res "[CRIT] TCP :${p} not listening"; inc_crit
  fi
  add_kv "tcp_${p}=listening=$(ss -plnt | grep -cE '[:.]'${p}' ')"
}

check_port_udp() { # check_port_udp <port>
  local p="$1"
  if ss -plnu | grep -qE "[:.]${p} "; then
    add_res "[OK] UDP :${p} listening"; inc_ok
  else
    add_res "[CRIT] UDP :${p} not listening"; inc_crit
  fi
  add_kv "udp_${p}=listening=$(ss -plnu | grep -cE '[:.]'${p}' ')"
}

check_container() { # check_container <name>
  local name="$1"
  if docker ps --format '{{.Names}}' | grep -q "^${name}\$"; then
    add_res "[OK] container '${name}' is running"; inc_ok
    add_kv "container_${name}=running"
  else
    add_res "[CRIT] container '${name}' is NOT running"; inc_crit
    add_kv "container_${name}=not_running"
  fi
}

check_redirect() { # HTTP->HTTPS
  local out code loc
  out="$(curl -sI "http://${DOMAIN}/" || true)"
  code="$(printf "%s" "$out" | awk '/^HTTP/{print $2; exit}')"
  loc="$(printf "%s" "$out" | awk '/^Location:/ {print $2; exit}' | tr -d '\r')"
  if [[ "$code" =~ ^30[18]$ ]] && [[ "$loc" == "https://${DOMAIN}/"* ]]; then
    add_res "[OK] HTTP→HTTPS redirect works (${code} -> ${loc})"; inc_ok
  else
    add_res "[CRIT] HTTP→HTTPS redirect missing or wrong (code=${code}, location=${loc})"; inc_crit
  fi
  add_kv "http_redirect_code=${code:-none}"
  add_kv "http_redirect_location=${loc:-none}"
}

check_https() { # reachability
  if curl -fsS --max-time 20 "https://${DOMAIN}/" -o /dev/null; then
    add_res "[OK] HTTPS reachable at https://${DOMAIN}/"; inc_ok
    add_kv "https_ok=1"
  else
    add_res "[CRIT] HTTPS NOT reachable at https://${DOMAIN}/"; inc_crit
    add_kv "https_ok=0"
  fi
}

check_tls() { # expiry + issuer
  local info issuer enddate ts now days
  if echo | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN:443" -showcerts 2>/dev/null \
     | openssl x509 -noout -issuer -enddate > /tmp/wg_tls.txt 2>/dev/null; then
    issuer="$(grep '^issuer=' /tmp/wg_tls.txt | sed 's/^issuer= *//')"
    enddate="$(grep '^notAfter=' /tmp/wg_tls.txt | cut -d= -f2)"
    if [[ -n "$enddate" ]]; then
      ts=$(date -d "$enddate" +%s 2>/dev/null || echo 0)
      now=$(date +%s)
      days=$(( (ts - now) / 86400 ))
      add_kv "tls_issuer=${issuer// /_}"
      add_kv "tls_not_after=${enddate// /_}"
      add_kv "tls_days_left=${days}"
      if (( days < 0 )); then
        add_res "[CRIT] TLS certificate EXPIRED ($enddate, issuer: $issuer)"; inc_crit
      elif (( days <= CRIT_DAYS )); then
        add_res "[CRIT] TLS certificate critical: ${days} days left (<= ${CRIT_DAYS}), issuer: $issuer"; inc_crit
      elif (( days <= WARN_DAYS )); then
        add_res "[WARN] TLS certificate warning: ${days} days left (<= ${WARN_DAYS}), issuer: $issuer"; inc_warn
      else
        add_res "[OK] TLS certificate healthy: ${days} days left, issuer: $issuer"; inc_ok
      fi
    else
      add_res "[CRIT] TLS certificate end date not readable"; inc_crit
      add_kv "tls_days_left=unknown"
    fi
  else
    add_res "[CRIT] Unable to fetch TLS certificate info"; inc_crit
    add_kv "tls_cert_fetch=failed"
  fi
}

check_dns_vs_public_ip() {
  local a4 a6 pub4 pub6 ok4=0 ok6=0
  a4="$(dig +short A "$DOMAIN" | tail -n1 || true)"
  a6="$(dig +short AAAA "$DOMAIN" | tail -n1 || true)"
  pub4="$(pub_ip4)"; pub6="$(pub_ip6)"
  [[ -n "$a4" && -n "$pub4" && "$a4" == "$pub4" ]] && ok4=1
  [[ -n "$a6" && -n "$pub6" && "$a6" == "$pub6" ]] && ok6=1

  if (( ok4==1 || ok6==1 )); then
    add_res "[OK] DNS points here (A=${a4:-none} ~ ${pub4:-unknown}, AAAA=${a6:-none} ~ ${pub6:-unknown})"; inc_ok
  else
    add_res "[WARN] DNS may not point here (A=${a4:-none} ~ ${pub4:-unknown}, AAAA=${a6:-none} ~ ${pub6:-unknown})"; inc_warn
  fi
  add_kv "dns_a=${a4:-none}"
  add_kv "dns_aaaa=${a6:-none}"
  add_kv "pub_ip4=${pub4:-unknown}"
  add_kv "pub_ip6=${pub6:-unknown}"
}

# -------- Run checks --------
hr
echo "wg-easy healthcheck for domain: ${DOMAIN}"
echo "Warn days: ${WARN_DAYS}, Crit days: ${CRIT_DAYS}"
echo "Log: ${LOGFILE}"
hr

# Core services
check_service docker "Docker"
check_service caddy "Caddy"
# Optional services (don't fail stack if missing)
if systemctl list-unit-files | grep -q '^fail2ban\.service'; then check_service fail2ban "fail2ban"; fi
if systemctl list-unit-files | grep -q '^ufw\.service'; then check_service ufw "UFW"; fi
if systemctl list-unit-files | grep -q '^unattended-upgrades\.service'; then check_service unattended-upgrades "unattended-upgrades"; fi

# Container
check_container "wg-easy"

# Ports
check_port_tcp 80
check_port_tcp 443

WG_ENV="/opt/wg-easy/.env"
WG_PORT="$(file_get_var "$WG_ENV" WG_PORT 51820)"
check_port_udp "$WG_PORT"
add_kv "wg_port=${WG_PORT}"

# HTTP(S) / TLS / DNS
check_redirect
check_https
check_tls
check_dns_vs_public_ip

# -------- Summarize --------
STATE="OK"; EXIT=0
(( CRIT>0 )) && { STATE="CRITICAL"; EXIT=2; }
(( CRIT==0 && WARN>0 )) && { STATE="WARNING"; EXIT=1; }

hr
echo "Result: ${STATE}  (ok=${OKS} warn=${WARN} crit=${CRIT})"
add_kv "result=${STATE}"
add_kv "ok=${OKS}"
add_kv "warn=${WARN}"
add_kv "crit=${CRIT}"
echo "Full log: ${LOGFILE}"
hr

# JSON emit
if (( JSON==1 )); then
  # Convert KV to JSON quickly (no jq requirement to keep deps small)
  # Format: {"key":"value",...}
  first=1
  printf "{"
  for kv in "${KV[@]}"; do
    k="${kv%%=*}"; v="${kv#*=}"
    # escape quotes and backslashes
    v="${v//\\/\\\\}"; v="${v//\"/\\\"}"
    if (( first==1 )); then first=0; printf "\"%s\":\"%s\"" "$k" "$v"
    else printf ",\"%s\":\"%s\"" "$k" "$v"; fi
  done
  printf "}\n"
fi

# Webhook
if [[ -n "$WEBHOOK" ]]; then
  payload="{"
  first=1
  for kv in "${KV[@]}"; do
    k="${kv%%=*}"; v="${kv#*=}"; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"
    if (( first==1 )); then first=0; payload+="\"$k\":\"$v\""; else payload+=",\"$k\":\"$v\""; fi
  done
  payload+="}"
  curl -fsS -X POST -H 'Content-Type: application/json' -d "$payload" "$WEBHOOK" >/dev/null || echo "WARN: webhook POST failed" >&2
fi

exit "$EXIT"
