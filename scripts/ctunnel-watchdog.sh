#!/usr/bin/env bash
# Opt-in end-to-end probe. No traffic counters: an idle tunnel is healthy.
set -euo pipefail
export LC_ALL=C
umask 077
name="${1:?watchdog name required}"
[[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || exit 2
config_dir="${CT_WATCHDOG_CONFIG_DIR:-/etc/ctunnel/watchdog}"
state_dir="${CT_WATCHDOG_STATE_DIR:-/run/ctunnel-watchdog}"
# Administrator-owned configuration, written by install-watchdog.sh using %q.
# shellcheck disable=SC1090
source "$config_dir/$name.env"
: "${WATCH_UNIT:?}" "${TUNNEL_URL:?}" "${ORIGIN_URL:?}" "${EXPECTED_BODY:?}"
[[ "$WATCH_UNIT" =~ ^(ctunnel-engine@[a-z0-9-]+|ctunnel@[a-z0-9-]+|frpc|frps)\.service$ ]] || exit 2
for url in "$TUNNEL_URL" "$ORIGIN_URL"; do
    [[ "$url" == http://* || "$url" == https://* ]] || exit 2
done
mkdir -p "$state_dir"
exec 9>"$state_dir/$name.lock"
flock -n 9 || exit 0
state="$state_dir/$name.state"
failures=0 last_restart=0 armed=0
if [[ -r "$state" ]]; then
    read -r failures last_restart armed < "$state"
    [[ "$failures $last_restart $armed" =~ ^[0-9]+\ [0-9]+\ [01]$ ]] || exit 2
fi
save() { printf '%s %s %s\n' "$failures" "$last_restart" "$armed" > "$state.tmp"; mv -f "$state.tmp" "$state"; }
probe() {
    local body
    # Do not inherit an HTTP proxy: the probe must use the configured route.
    body="$(curl --noproxy '*' --proto '=http,https' --fail --silent --show-error \
        --connect-timeout 3 --max-time 8 --max-filesize 4096 "$1" 2>/dev/null | head -c 4097)" || return 1
    [[ "${#body}" -le 4096 && "$body" == "$EXPECTED_BODY" ]]
}
# A deliberately stopped service must stay stopped.
if ! systemctl is-active --quiet "$WATCH_UNIT"; then failures=0; save; exit 0; fi
if probe "$TUNNEL_URL"; then failures=0; armed=1; save; exit 0; fi
# A never-working configuration or an unhealthy origin must not cause restart loops.
if [[ "$armed" -eq 0 ]] || ! probe "$ORIGIN_URL"; then failures=0; save; exit 0; fi
failures=$((failures + 1))
read -r uptime _ < /proc/uptime
now="${uptime%%.*}"
if (( failures >= 3 && (last_restart == 0 || now - last_restart >= 300) )); then
    # Reserve cooldown before invoking systemctl, including on restart failure.
    failures=0 last_restart="$now"
    save
    echo "watchdog $name: tunnel probe failed three times; origin healthy; restarting $WATCH_UNIT"
    systemctl --no-block restart "$WATCH_UNIT"
else
    save
fi
