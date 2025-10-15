# WireGuard eXtended

<img width="232" height="258" alt="wgx_shield" src="https://github.com/user-attachments/assets/4483b40d-1cd4-4423-940a-0be836779c62" />

WireGuard + wg-easy on Debian 13 (Docker, Caddy/Let’s Encrypt)

Turn-key, **quiet + logged**, **interactive (with optional TUI)** installer for a hardened WireGuard VPN using **[wg-easy](https://github.com/wg-easy/wg-easy)** behind **Caddy** with automatic **Let’s Encrypt** TLS and **HTTP→HTTPS**. Includes **UFW**, **fail2ban**, **unattended-upgrades**, health checks, backup/restore, and an uninstall script. We are planning on new features, including replacing WGeasy with a new management backend supporting more robust security and multitenancy with integrated monitoring and more controls over system tuning.

> **Tested:** Debian 13 “Trixie” (Debian 12+ should work)
> **Requires:** Root privileges

---

## Table of Contents

* [Features](#features)
* [Files in this Repo](#files-in-this-repo)
* [Quick Start](#quick-start)
* [Installer Usage (`install-wg-easy.sh`)](#installer-usage-install-wg-easysh)
* [Backup & Restore (`wg-easy-backup.sh`)](#backup--restore-wg-easy-backupsh)
* [Uninstall (`wg-easy-uninstall.sh`)](#uninstall-wg-easy-uninstallsh)
* [Healthcheck (`wg-easy-healthcheck.sh`)](#healthcheck-wg-easy-healthchecksh)

  * [Run via cron](#run-via-cron)
  * [Run via systemd timer](#run-via-systemd-timer)
* [What the Installer Configures](#what-the-installer-configures)
* [Security Notes](#security-notes)
* [Troubleshooting](#troubleshooting)
* [License](#license)

---

## Features

* **WireGuard + wg-easy** in Docker (containers auto-restart & optional auto re-up on boot)
* **Caddy** reverse proxy with **Let’s Encrypt** (staging/production selectable)
* Explicit **HTTP→HTTPS 308 redirect** (verified post-install)
* **Optional Basic Auth** and **optional IP allowlist** for the UI
* **UFW** rules, **fail2ban** jails for Caddy/SSH, **unattended-upgrades**
* **Installer UX**

  * CLI prompts or **TUI** (whiptail)
  * **Quiet mode** after prompts with **percentage progress bar**
  * **Full per-run log file**
* **Healthcheck** script (ports, services, HTTPS, TLS expiry, DNS, JSON/webhook)
* **Backup/Restore** script (configs, compose, Caddyfile, optional Caddy cert state)
* **Uninstall** script (safe, interactive, backups before removal)

---

## Files in this Repo

```
.
├── install-wg-easy.sh              # Main installer (interactive/TUI, quiet+logged)
├── wg-easy-backup.sh               # Backup & restore helper
├── wg-easy-uninstall.sh            # Safe removal tool
├── wg-easy-healthcheck.sh          # Healthcheck (human + JSON/webhook)
├── README.md                       # This file
└── LICENSE                         # GPLv3
```

The installer also creates:

* `/opt/wg-easy/compose.yaml`, `/opt/wg-easy/.env`, `/opt/wg-easy/config/`
* `/etc/caddy/Caddyfile`
* `/etc/systemd/system/wg-easy-compose.service` (optional autostart helper)
* `/etc/fail2ban/jail.local`, `/etc/fail2ban/filter.d/caddy-httperrors.conf` (if enabled)
* `/etc/apt/apt.conf.d/50unattended-upgrades`, `/etc/apt/apt.conf.d/20auto-upgrades` (if enabled)
* `/etc/sysctl.d/99-wireguard-forwarding.conf`

---

## Quick Start

```bash
# 1) Clone and run (as root)
cd /root
git clone https://github.com/LINUXexpert-org/WG-Easy-Installer.git
cd WG-Easy-Installer
sudo bash install-wg-easy.sh
# 2) Choose TUI or CLI, answer prompts (domain, email, ports, etc.)
# 3) Ensure DNS A/AAAA points to this server; free ports 80/443
# 4) Access the UI:
#    https://vpn.example.com/
```

---

## Installer Usage (`install-wg-easy.sh`)

Run:

```bash
sudo bash install-wg-easy.sh
```

Prompts (CLI or TUI):

* **Domain** for the wg-easy UI (e.g., `vpn.example.com`)
* **ACME mode**: Let’s Encrypt staging or production
* **WG_HOST** (public hostname/IP for peers)
* **WireGuard UDP port** (default `51820`)
* **wg-easy UI port** (loopback only; default `51821`)
* **Tunnel subnet** (default `10.8.0.0/24`)
* **Client DNS** (default `1.1.1.1,9.9.9.9`)
* **IPv6 forwarding** enable/disable
* **Basic Auth** for the UI (username/password)
* **IP allowlist** for the UI (CIDR, optional)
* **UFW**, **unattended-upgrades**, **fail2ban**
* **Autostart**: create `wg-easy-compose.service` to re-`up -d` on boot

Outputs:

* **Percentage progress bar** and step titles
* **Full log** at `./install-wg-easy-YYYYmmdd-HHMMSS.log`

Idempotent: safe to re-run; it validates/updates components.

---

## Backup & Restore (`wg-easy-backup.sh`)

Install:

```bash
sudo install -m 0750 wg-easy-backup.sh /usr/local/sbin/wg-easy-backup.sh
```

### Backup

```bash
# Standard backup to ./wg-easy-backup-YYYYmmdd-HHMMSS.tgz
sudo wg-easy-backup.sh backup

# Include Caddy cert/key state (sensitive!)
sudo wg-easy-backup.sh backup --include-certs
```

Backs up:

* `/opt/wg-easy` (compose, env, config/)
* `/etc/caddy/Caddyfile`
* fail2ban jail/filter (if present)
* `99-wireguard-forwarding.conf`
* `wg-easy-compose.service`
* Meta snapshots (Docker images, compose ps/ls, UFW, listeners)

### Restore

```bash
sudo wg-easy-backup.sh restore ./wg-easy-backup-2025....tgz
```

Stops services, restores files (backs up current ones first), reloads daemons, **re-ups** the stack, and reloads Caddy. Logs are written alongside the tarball.

---

## Uninstall (`wg-easy-uninstall.sh`)

Install:

```bash
sudo install -m 0750 wg-easy-uninstall.sh /usr/local/sbin/wg-easy-uninstall.sh
```

Run:

```bash
sudo wg-easy-uninstall.sh
```

What it does (interactive):

* Stops `wg-easy` (docker compose down), disables/removes `wg-easy-compose.service`
* Optionally **removes** `/opt/wg-easy` (or preserves it)
* Optionally removes **Caddyfile** entry (backs up first) and reloads Caddy
* Optionally prunes **fail2ban** caddy filter/jail and the sysctl file
* Optional package removal (Caddy, fail2ban, Docker)
* Logs to `wg-easy-uninstall-YYYYmmdd-HHMMSS.log`

---

## Healthcheck (`wg-easy-healthcheck.sh`)

Install:

```bash
sudo install -m 0755 wg-easy-healthcheck.sh /usr/local/sbin/wg-easy-healthcheck.sh
```

Run (human output + log):

```bash
sudo wg-easy-healthcheck.sh --domain vpn.example.com
```

Options:

```
--domain <host>     # required
--warn-days <N>     # TLS warning threshold (default 21)
--crit-days <N>     # TLS critical threshold (default 7)
--json              # emit JSON summary to stdout
--webhook <URL>     # POST JSON to a webhook (e.g., healthchecks.io)
--log <path>        # override log file path
```

What it checks:

* Services: Docker, Caddy (+ optional: fail2ban, UFW, unattended-upgrades)
* Container: `wg-easy` running
* Ports: `:80`, `:443` TCP; WireGuard UDP (`WG_PORT` from `/opt/wg-easy/.env`, default `51820`)
* HTTP→HTTPS redirect (expects 301/308 to `https://<domain>/…`)
* HTTPS reachability
* TLS issuer & **days to expiry** (warning/critical thresholds)
* DNS A/AAAA vs current public IP (v4/v6)

Exit codes: `0=OK`, `1=WARNING`, `2=CRITICAL`, `3=UNKNOWN`

### Run via cron

Create `/etc/cron.hourly/wg-easy-health`:

```sh
#!/bin/sh
/usr/local/sbin/wg-easy-healthcheck.sh \
  --domain vpn.example.com \
  --warn-days 30 --crit-days 10 \
  --log /var/log/wg-easy-health.log >/dev/null 2>&1
```

Then:

```bash
sudo chmod 755 /etc/cron.hourly/wg-easy-health
```

### Run via systemd timer

`/etc/systemd/system/wg-easy-health.service`:

```ini
[Unit]
Description=wg-easy stack healthcheck

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/wg-easy-healthcheck.sh --domain vpn.example.com --warn-days 30 --crit-days 10 --log /var/log/wg-easy-health.log
```

`/etc/systemd/system/wg-easy-health.timer`:

```ini
[Unit]
Description=Run wg-easy healthcheck every 15 minutes

[Timer]
OnBootSec=2m
OnUnitActiveSec=15m
AccuracySec=1m
Unit=wg-easy-health.service

[Install]
WantedBy=timers.target
```

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wg-easy-health.timer
sudo systemctl status wg-easy-health.timer
```

---

## What the Installer Configures

* **Docker Engine + compose plugin** (enabled at boot)
* **wg-easy** container:

  * `restart: unless-stopped`
  * Optional **systemd unit** `wg-easy-compose.service` to `docker compose up -d` on boot
* **Caddy** (enabled at boot):

  * `http://<domain>` → **308** → `https://<domain>`
  * Reverse proxy to `127.0.0.1:<wg-easy-ui-port>`
  * HSTS & security headers
  * Optional **Basic Auth** and **IP allowlist**
* **UFW** (optional): allows `22/tcp`, `80/tcp`, `443/tcp`, `<WG_PORT>/udp`
* **fail2ban** (optional): `sshd` + `caddy-httperrors` (401/403 patterns)
* **unattended-upgrades** (optional): automatic security updates, optional email notifications
* **sysctl**: `net.ipv4.ip_forward=1` (+ optional `net.ipv6.conf.all.forwarding=1`)

> The wg-easy UI is **loopback-only**; all external access flows through **Caddy over HTTPS** (with optional Basic Auth/allowlist).

---

## Security Notes

* Backups contain **secrets** (WireGuard keys; and TLS private keys if you use `--include-certs`). Store and transmit securely.
* Keep **DNS A/AAAA** pointing to this host for uninterrupted certificate renewals.
* If you enable **Basic Auth**, use a strong unique password and consider a **UI IP allowlist**.
* **UFW** defaults open only the necessary ports; adjust if you run a nonstandard SSH port or other services.
* Schedule the **healthcheck** via a timer/cron and (optionally) a webhook for monitoring.

---

## Troubleshooting

Installer log (latest):

```bash
ls -1t ./install-wg-easy-*.log | head -n1 | xargs -I{} less {}
```

Caddy:

```bash
sudo systemctl status caddy
sudo journalctl -u caddy -e
sudo tail -f /var/log/caddy/access.log
caddy validate --config /etc/caddy/Caddyfile
```

wg-easy container:

```bash
docker ps
docker logs -f wg-easy
```

Firewall:

```bash
sudo ufw status verbose
ss -plnt | egrep ':80 |:443 '
ss -plnu | egrep ":<WG_PORT> "
```

fail2ban:

```bash
sudo fail2ban-client status
sudo fail2ban-client status caddy-httperrors
```

If HTTP→HTTPS isn’t redirecting: ensure **80/443** are free and DNS is correct.

---

## License

All scripts in this repository are released under **GPLv3**.

```
This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License along
with this program. If not, see <https://www.gnu.org/licenses/>.
```

---

**Contributions welcome!** Please open issues/PRs for feature requests, bug fixes, and improvements.
