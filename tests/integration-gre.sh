#!/usr/bin/env bash
# Run only inside a fresh network + mount + PID namespace on a disposable CI VM.
# The two peers use real kernel GRE devices and the actual ctunnel-engine binary.
set -euo pipefail
[[ "${CTUNNEL_TEST_NETNS:-}" == 1 && "$(id -u)" == 0 ]] || { echo 'isolated root test only' >&2; exit 1; }
# Loaded tunnel modules create inert fallback devices in every new namespace.
# Allow those, but reject any NIC, veth or non-loopback UP interface.
while IFS= read -r line; do
    name="${line#*: }"; name="${name%%:*}"; name="${name%%@*}"
    case "$name" in
        lo) ;;
        gre0|gretap0|erspan0|ip6tnl0|ip6gre0|tunl0|sit0)
            [[ "$line" != *",UP,"* && "$line" != *"<UP,"* ]] || exit 1 ;;
        *) echo 'refusing a namespace with external interfaces' >&2; exit 1 ;;
    esac
done < <(ip -o link show)
engine="$(realpath "${1:?engine binary required}")"
helper="$(realpath "${2:?kernel helper required}")"
work="$(mktemp -d)"
pids=()
cleanup() {
    local pid
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    ip netns del iran 2>/dev/null || true
    ip netns del kharej 2>/dev/null || true
    rm -rf -- "$work"
}
diagnostics() {
    local peer
    for peer in iran kharej; do
        echo "=== ${peer} links/routes/engine ==="
        ip -n "$peer" -s link show || true
        ip -n "$peer" route show || true
        if [[ -f "$work/$peer.log" ]]; then cat "$work/$peer.log"; fi
    done
}
trap cleanup EXIT
trap diagnostics ERR
# Keep ip-netns bind mounts private to this test, including its namespace names.
mkdir -p /run/netns
mount -t tmpfs -o size=1m tmpfs /run/netns
ip netns add iran
ip netns add kharej
ip link add name veth-iran type veth peer name veth-kharej
ip link set veth-iran netns iran
ip link set veth-kharej netns kharej
ip -n iran addr add 192.0.2.1/30 dev veth-iran
ip -n kharej addr add 192.0.2.2/30 dev veth-kharej
ip -n iran link set veth-iran up
ip -n kharej link set veth-kharej up
ip -n iran link set lo up
ip -n kharej link set lo up

config() {
    local peer="$1" reverse="$2" local_ip remote_ip tun_local tun_remote port=0
    local_ip=192.0.2.1 remote_ip=192.0.2.2 tun_local=10.77.1.1 tun_remote=10.77.1.2
    if [[ "$peer" == kharej ]]; then
        local_ip=192.0.2.2 remote_ip=192.0.2.1 tun_local=10.77.1.2 tun_remote=10.77.1.1
    fi
    if [[ "$reverse" == 1 ]]; then port=24001; fi
    mkdir -p "$work/$peer/tunnels"
    cat > "$work/$peer/tunnels/t1.env" <<ENV
NAME="t1"
INDEX="1"
DEV="ct-t1"
KIND="gre"
ROLE="$peer"
LOCAL_IP="$local_ip"
REMOTE_IP="$remote_ip"
TUN_LOCAL4="$tun_local"
TUN_REMOTE4="$tun_remote"
PORT="$port"
MTU="1400"
SECRET="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
GRE_KEY="12345"
LANES="1"
RATE_MBIT="0"
PADDING="16"
REVERSE="$reverse"
FORWARDS=""
ENV
}
up() { ip netns exec "$1" env CT_DIR="$work/$1" bash "$helper" up t1; }
down() { ip netns exec "$1" env CT_DIR="$work/$1" bash "$helper" down t1; }
probe() {
    ip netns exec iran ping -q -c 3 -W 1 -I ct-t1 10.77.1.2
    ip netns exec kharej ping -q -c 3 -W 1 -I ct-t1 10.77.1.1
}

# DIRECT GRE must work independently of the userspace engine.
config iran 0
config kharej 0
up iran
up kharej
probe
echo 'PASS: real DIRECT GRE, both directions'
down iran
down kharej

# REVERSE GRE traverses each peer's carrier TUN, TCP framing and AEAD.
config iran 1
config kharej 1
up iran
up kharej
for peer in iran kharej; do
    ip netns exec "$peer" "$engine" -config "$work/$peer/tunnels/t1.env" > "$work/$peer.log" 2>&1 &
    pids+=("$!")
done
# Let readers enter an idle Read before the first GRE packet is generated.
sleep 2
for pid in "${pids[@]}"; do kill -0 "$pid"; done
connected=0
for attempt in {1..6}; do
    if ip netns exec iran ping -q -c 1 -W 1 -I ct-t1 10.77.1.2; then
        connected=1
        break
    fi
    sleep 1
done
if [[ "$connected" != 1 ]]; then
    # Exit 42 is reserved for a live carrier with a failed GRE data plane.
    for pid in "${pids[@]}"; do kill -0 "$pid"; done
    diagnostics
    echo 'FAIL: live reverse engines did not carry GRE packets after idle' >&2
    exit 42
fi
probe
# A second idle period catches missed poll wakeups, rather than only startup traffic.
sleep 2
probe
echo 'PASS: real REVERSE GRE, both directions, after idle'
