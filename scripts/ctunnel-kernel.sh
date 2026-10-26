#!/usr/bin/env bash
# ctunnel-kernel: brings tunnel interfaces up and down from the env files written by
# `ctunnel` (/etc/ctunnel/tunnels/<name>.env). Called by the systemd units
# ctunnel@<name>.service and ctunnel-engine@<name>.service; not meant to be run by hand
# except for `optimize` and `doctor`.
set -euo pipefail

CT_DIR="${CT_DIR:-/etc/ctunnel}"
CT_TUNNELS_DIR="${CT_DIR}/tunnels"
CT_SYSCTL="/etc/sysctl.d/99-ctunnel.conf"

log() { echo "ctunnel-kernel: $*"; }
die() { echo "ctunnel-kernel: error: $*" >&2; exit 1; }

load_env() {
    local name="$1"
    [[ "${name}" =~ ^[a-z0-9][a-z0-9-]{0,8}$ ]] || die "invalid tunnel name '${name}'"
    local f="${CT_TUNNELS_DIR}/${name}.env"
    [[ -f "${f}" ]] || die "missing ${f}"
    # shellcheck disable=SC1090
    source "${f}"
    : "${NAME:?}" "${DEV:?}" "${KIND:?}" "${ROLE:?}" "${LOCAL_IP:?}" "${REMOTE_IP:?}" "${MTU:?}"
    INDEX="${INDEX:-1}" PORT="${PORT:-0}" LANES="${LANES:-1}" GRE_KEY="${GRE_KEY:-0}" RATE_MBIT="${RATE_MBIT:-0}"
    REVERSE="${REVERSE:-0}" FORWARDS="${FORWARDS:-}"
}

modload() { local m; for m in "$@"; do modprobe "${m}" 2>/dev/null || true; done; }

# Interfaces of this tunnel: the main device plus ECMP lanes.
lane_devs() {
    local i
    echo "${DEV}"
    for ((i = 1; i < LANES; i++)); do echo "${DEV}.${i}"; done
}

key_args() {
    if [[ "${GRE_KEY}" -gt 0 ]]; then echo "key $(( GRE_KEY + $1 ))"; fi
}

# FOU / GUE wrapping for kernel IPv4 tunnels when PORT > 0.
fou_args() {
    local ipproto="$1"
    [[ "${PORT}" -gt 0 ]] || return 0
    modload fou
    if [[ "${ipproto}" == "gue" ]]; then
        ip fou add port "${PORT}" gue 2>/dev/null || true
        echo "encap gue encap-sport auto encap-dport ${PORT}"
    else
        ip fou add port "${PORT}" ipproto "${ipproto}" 2>/dev/null || true
        echo "encap fou encap-sport auto encap-dport ${PORT}"
    fi
}

fw_comment() { echo "ctunnel:${NAME}"; }

# Remove every iptables rule tagged with this tunnel's comment.
fw_clear() {
    local table rule tag
    tag="$(fw_comment)"
    command -v iptables >/dev/null 2>&1 || return 0
    for table in raw filter nat mangle; do
        while read -r rule; do
            [[ -n "${rule}" ]] || continue
            rule="${rule//\"/}" # newer iptables quotes comments; ours contain no spaces
            # shellcheck disable=SC2086
            iptables -t "${table}" ${rule/#-A /-D } 2>/dev/null || true
        done < <(iptables -t "${table}" -S 2>/dev/null | grep -E -- "--comment \"?${tag}\"?( |$)" || true)
    done
}

fw_apply() {
    command -v iptables >/dev/null 2>&1 || { log "iptables not found: skipping MSS clamp and port forwards"; return 0; }
    local tag d entry src dst p
    tag="$(fw_comment)"
    if [[ "${LOCAL_IP}" != *:* && "${REMOTE_IP}" != *:* && "${REMOTE_IP}" != "0.0.0.0" ]]; then
        iptables -t raw -A PREROUTING -s "${REMOTE_IP}/32" -m comment --comment "${tag}" -j CT --notrack 2>/dev/null || true
        iptables -t raw -A OUTPUT -d "${REMOTE_IP}/32" -m comment --comment "${tag}" -j CT --notrack 2>/dev/null || true
    fi
    while read -r d; do
        iptables -t mangle -A FORWARD -o "${d}" -p tcp --tcp-flags SYN,RST SYN \
            -m comment --comment "${tag}" -j TCPMSS --clamp-mss-to-pmtu
        iptables -t mangle -A FORWARD -i "${d}" -p tcp --tcp-flags SYN,RST SYN \
            -m comment --comment "${tag}" -j TCPMSS --clamp-mss-to-pmtu
    done < <(lane_devs)

    [[ "${ROLE}" == "iran" && -n "${FORWARDS}" && -n "${TUN_REMOTE4:-}" ]] || return 0
    sysctl -qw net.ipv4.ip_forward=1
    for entry in ${FORWARDS}; do
        src="${entry%%=*}"
        dst="${entry#*=}"
        for p in tcp udp; do
            iptables -t nat -A PREROUTING -p "${p}" --dport "${src}" -m addrtype --dst-type LOCAL \
                -m comment --comment "${tag}" -j DNAT --to-destination "${TUN_REMOTE4}:${dst}"
        done
    done
    iptables -t nat -A POSTROUTING -d "${TUN_REMOTE4}/32" -m comment --comment "${tag}" -j SNAT --to-source "${TUN_LOCAL4}"
    iptables -I FORWARD -d "${TUN_REMOTE4}/32" -m comment --comment "${tag}" -j ACCEPT
    iptables -I FORWARD -s "${TUN_REMOTE4}/32" -m comment --comment "${tag}" -j ACCEPT
}

tune_dev() {
    local d="$1" cpus mask q
    ip link set dev "${d}" mtu "${MTU}" txqueuelen 10000 up
    sysctl -qw "net.ipv4.conf.${d//./\/}.rp_filter=2" 2>/dev/null || true
    if [[ "${RATE_MBIT}" -gt 0 ]]; then
        local rate="${RATE_MBIT}" burst
        [[ "${LANES}" -gt 1 ]] && rate=$(( (RATE_MBIT + LANES - 1) / LANES ))
        burst=$(( rate > 64 ? rate * 16 : 1024 ))
        tc qdisc replace dev "${d}" root tbf rate "${rate}mbit" burst "${burst}kbit" latency 50ms
    else
        tc qdisc del dev "${d}" root 2>/dev/null || true
    fi
    # Spread decapsulated/encapsulated packets over CPUs (RPS/XPS); masks above 32 CPUs need comma groups, so cap it.
    cpus="$(nproc 2>/dev/null || echo 1)"
    [[ "${cpus}" -gt 32 ]] && cpus=32
    mask="$(printf '%x' $(( (1 << cpus) - 1 )))"
    for q in /sys/class/net/"${d}"/queues/rx-*/rps_cpus /sys/class/net/"${d}"/queues/tx-*/xps_cpus; do
        if [[ -w "${q}" ]]; then echo "${mask}" > "${q}" 2>/dev/null || true; fi
    done
}

addr4() { ip addr add "${TUN_LOCAL4}" peer "${TUN_REMOTE4}/32" dev "$1"; }

ipsec_up() {
    local reqid_out="${IPSEC_SPI_OUT}" reqid_in="${IPSEC_SPI_IN}"
    ipsec_down
    ip xfrm state add src "${LOCAL_IP}" dst "${REMOTE_IP}" proto esp spi "${IPSEC_SPI_OUT}" reqid "${reqid_out}" \
        mode transport aead 'rfc4106(gcm(aes))' "${IPSEC_KEY_OUT}" 128 replay-window 1024
    ip xfrm state add src "${REMOTE_IP}" dst "${LOCAL_IP}" proto esp spi "${IPSEC_SPI_IN}" reqid "${reqid_in}" \
        mode transport aead 'rfc4106(gcm(aes))' "${IPSEC_KEY_IN}" 128 replay-window 1024
    # Only GRE between the two servers is encrypted; SSH and everything else stay untouched.
    ip xfrm policy add src "${LOCAL_IP}/32" dst "${REMOTE_IP}/32" proto gre dir out \
        tmpl src "${LOCAL_IP}" dst "${REMOTE_IP}" proto esp reqid "${reqid_out}" mode transport
    ip xfrm policy add src "${REMOTE_IP}/32" dst "${LOCAL_IP}/32" proto gre dir in \
        tmpl src "${REMOTE_IP}" dst "${LOCAL_IP}" proto esp reqid "${reqid_in}" mode transport
}

ipsec_down() {
    [[ -n "${IPSEC_SPI_OUT:-}" ]] || return 0
    ip xfrm policy delete src "${LOCAL_IP}/32" dst "${REMOTE_IP}/32" proto gre dir out 2>/dev/null || true
    ip xfrm policy delete src "${REMOTE_IP}/32" dst "${LOCAL_IP}/32" proto gre dir in 2>/dev/null || true
    ip xfrm state delete src "${LOCAL_IP}" dst "${REMOTE_IP}" proto esp spi "${IPSEC_SPI_OUT}" 2>/dev/null || true
    ip xfrm state delete src "${REMOTE_IP}" dst "${LOCAL_IP}" proto esp spi "${IPSEC_SPI_IN}" 2>/dev/null || true
}

links_down() {
    local i
    ip link del "${DEV}" 2>/dev/null || true
    ip link del "${DEV}-r" 2>/dev/null || true
    for ((i = 1; i < 8; i++)); do ip link del "${DEV}.${i}" 2>/dev/null || true; done
    ip link del "${DEV}-6" 2>/dev/null || true
    ip route del "${TUN_REMOTE4:-0.0.0.0}/32" proto 77 2>/dev/null || true
    if [[ "${KIND}" == "l2tpv3" ]]; then
        ip l2tp del session tunnel_id "${TUNNEL_ID}" session_id "${TUNNEL_ID}" 2>/dev/null || true
        ip l2tp del tunnel tunnel_id "${TUNNEL_ID}" 2>/dev/null || true
    fi
}

# GRE-family devices, with optional FOU and ECMP lanes.
gre_up() {
    local ktype="$1" fou="" i d nexthops=()
    [[ "${ktype}" == "gre" || "${ktype}" == "gretap" ]] && fou="$(fou_args 47)"
    for ((i = 0; i < LANES; i++)); do
        d="${DEV}"
        [[ "${i}" -gt 0 ]] && d="${DEV}.${i}"
        # shellcheck disable=SC2046,SC2086
        ip link add name "${d}" type "${ktype}" local "${LOCAL_IP}" remote "${REMOTE_IP}" ttl 255 $(key_args "${i}") ${fou}
        tune_dev "${d}"
        if [[ "${LANES}" -gt 1 ]]; then
            ip addr add "${TUN_LOCAL4}/32" dev "${d}"
            nexthops+=(nexthop dev "${d}" weight 1)
        else
            addr4 "${d}"
        fi
    done
    if [[ "${LANES}" -gt 1 ]]; then
        sysctl -qw net.ipv4.fib_multipath_hash_policy=1 || true
        ip route replace "${TUN_REMOTE4}/32" proto 77 src "${TUN_LOCAL4}" "${nexthops[@]}"
    fi
}

cmd_up() {
    load_env "$1"
    links_down
    fw_clear
    modload ip_gre ip6_gre ipip sit ip6_tunnel tun
    if [[ "${REVERSE}" == "1" ]]; then
        case "${KIND}" in
            6to4|6to4-gre|sit|ipip|gue-ipip|gre|fou-gre|ecmp-lanes|xfrm-ipsec|gretap|vxlan|geneve|l2tpv3)
                local rev_local="172.31.${INDEX}.1" rev_remote="172.31.${INDEX}.2"
                [[ "${ROLE}" == "kharej" ]] && { rev_local="172.31.${INDEX}.2"; rev_remote="172.31.${INDEX}.1"; }
                ip tuntap add dev "${DEV}-r" mode tun multi_queue 2>/dev/null || ip tuntap add dev "${DEV}-r" mode tun
                ip link set dev "${DEV}-r" mtu 1460 txqueuelen 10000 up
                ip addr add "${rev_local}" peer "${rev_remote}/32" dev "${DEV}-r"
                LOCAL_IP="${rev_local}"
                REMOTE_IP="${rev_remote}"
                case "${KIND}" in
                    vxlan) PORT=4789 ;;
                    geneve) PORT=6081 ;;
                    fou-gre) PORT=5555 ;;
                    gue-ipip) PORT=5556 ;;
                    *) PORT=0 ;;
                esac
                ;;
        esac
    fi
    local fou
    case "${KIND}" in
        6to4|6to4-gre)
            fou="$(fou_args 41)"
            # shellcheck disable=SC2086
            ip link add name "${DEV}-6" type sit local "${LOCAL_IP}" remote "${REMOTE_IP}" ttl 255 ${fou}
            ip link set "${DEV}-6" mtu $(( MTU + 40 )) up
            ip -6 addr add "${CARRIER_LOCAL6}/64" dev "${DEV}-6"
            if [[ "${KIND}" == "6to4" ]]; then
                ip -6 tunnel add "${DEV}" mode ipip6 local "${CARRIER_LOCAL6}" remote "${CARRIER_REMOTE6}" dev "${DEV}-6" encaplimit none
            else
                ip link add name "${DEV}" type ip6gre local "${CARRIER_LOCAL6}" remote "${CARRIER_REMOTE6}"
            fi
            tune_dev "${DEV}"; addr4 "${DEV}"
            ;;
        sit)
            fou="$(fou_args 41)"
            # shellcheck disable=SC2086
            ip link add name "${DEV}" type sit local "${LOCAL_IP}" remote "${REMOTE_IP}" ttl 255 ${fou}
            tune_dev "${DEV}"; ip -6 addr add "${CARRIER_LOCAL6}/64" dev "${DEV}"
            ;;
        ipip|gue-ipip)
            if [[ "${KIND}" == "gue-ipip" ]]; then fou="$(fou_args gue)"; else fou="$(fou_args 4)"; fi
            # shellcheck disable=SC2086
            ip link add name "${DEV}" type ipip local "${LOCAL_IP}" remote "${REMOTE_IP}" ttl 255 ${fou}
            tune_dev "${DEV}"; addr4 "${DEV}"
            ;;
        gre|fou-gre|ecmp-lanes|xfrm-ipsec) gre_up gre ;;
        gretap) gre_up gretap ;;
        ip6gre) gre_up ip6gre ;;
        ip6gretap) gre_up ip6gretap ;;
        ipip6)
            ip -6 tunnel add "${DEV}" mode ipip6 local "${LOCAL_IP}" remote "${REMOTE_IP}" encaplimit none
            tune_dev "${DEV}"; addr4 "${DEV}"
            ;;
        ip6ip6)
            ip -6 tunnel add "${DEV}" mode ip6ip6 local "${LOCAL_IP}" remote "${REMOTE_IP}" encaplimit none
            tune_dev "${DEV}"; ip -6 addr add "${CARRIER_LOCAL6}/64" dev "${DEV}"
            ;;
        vxlan)
            modload vxlan
            ip link add "${DEV}" type vxlan id "${VNI}" local "${LOCAL_IP}" remote "${REMOTE_IP}" dstport "${PORT}" nolearning
            tune_dev "${DEV}"; addr4 "${DEV}"
            ;;
        geneve)
            modload geneve
            ip link add "${DEV}" type geneve id "${VNI}" remote "${REMOTE_IP}" dstport "${PORT}"
            tune_dev "${DEV}"; addr4 "${DEV}"
            ;;
        l2tpv3)
            modload l2tp_core l2tp_netlink l2tp_eth l2tp_ip l2tp_udp
            if [[ "${PORT}" -gt 0 ]]; then
                ip l2tp add tunnel tunnel_id "${TUNNEL_ID}" peer_tunnel_id "${TUNNEL_ID}" encap udp \
                    local "${LOCAL_IP}" remote "${REMOTE_IP}" udp_sport "${PORT}" udp_dport "${PORT}"
            else
                ip l2tp add tunnel tunnel_id "${TUNNEL_ID}" peer_tunnel_id "${TUNNEL_ID}" encap ip \
                    local "${LOCAL_IP}" remote "${REMOTE_IP}"
            fi
            ip l2tp add session name "${DEV}" tunnel_id "${TUNNEL_ID}" session_id "${TUNNEL_ID}" peer_session_id "${TUNNEL_ID}"
            tune_dev "${DEV}"; addr4 "${DEV}"
            ;;
        wireguard)
            command -v wg >/dev/null 2>&1 || die "wireguard-tools is not installed (apt install wireguard-tools)"
            modload wireguard
            ip link add dev "${DEV}" type wireguard
            local keyfile
            keyfile="$(umask 077; mktemp)"
            printf '%s\n' "${WG_PRIVATE}" > "${keyfile}"
            if [[ "${REVERSE}" == "1" && "${ROLE}" == "iran" ]]; then
                wg set "${DEV}" listen-port "${PORT}" private-key "${keyfile}" \
                    peer "${WG_PEER_PUBLIC}" allowed-ips 0.0.0.0/0
            else
                wg set "${DEV}" listen-port "${PORT}" private-key "${keyfile}" \
                    peer "${WG_PEER_PUBLIC}" endpoint "${REMOTE_IP}:${PORT}" persistent-keepalive 15 allowed-ips 0.0.0.0/0
            fi
            rm -f "${keyfile}"
            tune_dev "${DEV}"; addr4 "${DEV}"
            ;;
        eoip|etherip)
            ip tuntap add dev "${DEV}" mode tap multi_queue 2>/dev/null || ip tuntap add dev "${DEV}" mode tap
            tune_dev "${DEV}"; addr4 "${DEV}"
            ;;
        dtls-1.3|quic-v1|srtp-direct|wg-stealth|rudp-fec|dnscrypt-udp|ntp-direct|openvpn-dco)
            ip tuntap add dev "${DEV}" mode tun multi_queue 2>/dev/null || ip tuntap add dev "${DEV}" mode tun
            tune_dev "${DEV}"; addr4 "${DEV}"
            ;;
        *) die "unknown KIND ${KIND}" ;;
    esac
    [[ "${KIND}" == "xfrm-ipsec" ]] && ipsec_up
    fw_apply
    if [[ "${REVERSE}" == "1" && "${ROLE}" == "kharej" && -n "${TUN_REMOTE4:-}" ]]; then
        (ping -c 3 -W 1 -I "${DEV}" "${TUN_REMOTE4}" >/dev/null 2>&1 || true) &
    fi
    log "${NAME} (${KIND}) up on ${DEV}: ${TUN_LOCAL4:-} -> ${TUN_REMOTE4:-}, MTU ${MTU}"
}

cmd_down() {
    load_env "$1"
    fw_clear
    ipsec_down
    links_down
    log "${NAME} down"
}

cmd_optimize() {
    modload tcp_bbr
    cat > "${CT_SYSCTL}" << 'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.fib_multipath_hash_policy = 1
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 2097152
net.core.netdev_max_backlog = 32768
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000
net.core.somaxconn = 16384
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.udp_rmem_min = 65536
net.ipv4.udp_wmem_min = 65536
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.netfilter.nf_conntrack_max = 1048576
EOF
    sysctl -q -p "${CT_SYSCTL}" 2>/dev/null || sysctl --system >/dev/null 2>&1 || true
    log "applied ${CT_SYSCTL} (BBR + fq, 64 MB socket buffers, forwarding)"
}

cmd_doctor() {
    local m t
    for m in sit ipip ip_gre ip6_gre ip6_tunnel fou vxlan geneve l2tp_eth wireguard tun xfrm_user tcp_bbr; do
        if modprobe -n "${m}" >/dev/null 2>&1; then echo "ok    module ${m}"; else echo "miss  module ${m}"; fi
    done
    for t in ip iptables tc wg systemctl; do
        if command -v "${t}" >/dev/null 2>&1; then echo "ok    tool ${t}"; else echo "miss  tool ${t}"; fi
    done
    echo "info  ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo ?)"
    echo "info  congestion=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo ?)"
}

case "${1:-}" in
    up)       cmd_up "${2:?tunnel name required}" ;;
    down)     cmd_down "${2:?tunnel name required}" ;;
    optimize) cmd_optimize ;;
    doctor)   cmd_doctor ;;
    *) echo "usage: ctunnel-kernel up|down <name> | optimize | doctor" >&2; exit 2 ;;
esac
