#!/usr/bin/env bash
# Interactive configuration avoids shipping fake addresses or authentication tokens.
set -euo pipefail
[[ "$EUID" -eq 0 ]] || { echo 'Run with sudo' >&2; exit 1; }
for tool in curl flock systemctl install; do command -v "$tool" >/dev/null || { echo "Missing: $tool" >&2; exit 1; }; done
read -rp 'Watchdog name (lowercase letters, digits, hyphens): ' name
[[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || { echo 'Invalid name' >&2; exit 2; }
read -rp 'Service unit to restart (including .service): ' unit
[[ "$unit" =~ ^(ctunnel-engine@[a-z0-9-]+|ctunnel@[a-z0-9-]+|frpc|frps)\.service$ ]] || { echo 'Unsupported unit' >&2; exit 2; }
read -rp 'HTTP(S) health URL reached THROUGH the tunnel: ' tunnel_url
read -rp 'HTTP(S) health URL for the SAME origin over an INDEPENDENT path: ' origin_url
[[ "$tunnel_url" != "$origin_url" ]] || { echo 'The control probe must use an independent path' >&2; exit 2; }
for url in "$tunnel_url" "$origin_url"; do [[ "$url" == http://* || "$url" == https://* ]] || { echo 'Invalid HTTP(S) URL' >&2; exit 2; }; done
read -rp 'Expected response body (one nonempty line, no trailing newline): ' expected
[[ -n "$expected" ]] || exit 2
src="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install -d -m 0700 /etc/ctunnel/watchdog
install -d -m 0755 /usr/local/lib/ctunnel
umask 077
tmp="$(mktemp /etc/ctunnel/watchdog/.config.XXXXXX)"
trap 'rm -f "$tmp"' EXIT
printf 'WATCH_UNIT=%q\nTUNNEL_URL=%q\nORIGIN_URL=%q\nEXPECTED_BODY=%q\n' "$unit" "$tunnel_url" "$origin_url" "$expected" > "$tmp"
mv -f "$tmp" "/etc/ctunnel/watchdog/$name.env"
install -m 0755 "$src/scripts/ctunnel-watchdog.sh" /usr/local/lib/ctunnel/ctunnel-watchdog
install -m 0644 "$src/systemd/ctunnel-watchdog@.service" "$src/systemd/ctunnel-watchdog@.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now "ctunnel-watchdog@$name.timer"
echo 'Installed. Automatic restart arms only after the first successful tunnel probe.'
