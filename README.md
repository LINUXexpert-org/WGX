# WG-Easy-Installer
Interactive (TUI-capable) installer for WireGuard + wg-easy (Docker) behind Caddy/Let's Encrypt on Debian 13.

- install-wg-easy.sh - Quiet, logged, interactive (TUI-capable) installer for WireGuard + wg-easy (Docker) behind Caddy/Let's Encrypt on Debian 13. Includes unattended-upgrades, fail2ban, UFW, explicit HTTP->HTTPS redirect, full pre/post-flight checks, percentage progress bar, optional whiptail TUI, autostart for all services + compose stack, and a full logfile.
- wg-easy-backup.sh — makes a clean backup (and can restore) your wg-easy stack, configs, and related bits
  - Usage:
    - Create a backup (default: ./wg-easy-backup-YYYYmmdd-HHMMSS.tgz): sudo wg-easy-backup.sh backup
    - Include Caddy cert/private key state too (safeguard this file!): sudo wg-easy-backup.sh backup --include-certs
    - Restore from a backup tarball: sudo wg-easy-backup.sh restore ./wg-easy-backup-2025....tgz
- wg-easy-uninstall.sh — safely stops, disables, and removes the stack, with prompts to keep/remove data, Caddy config, jails, etc.
- wg-easy-healthcheck.sh - Periodic healthcheck for the wg-easy + Caddy stack
