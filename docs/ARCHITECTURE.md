# Architecture

```mermaid
flowchart LR
  subgraph ctunnel["ctunnel (Go CLI + panel)"]
    CLI[pkg/cli menu] --> T[pkg/tunnel]
    WEB[pkg/webpanel HTTPS] --> T
    T --> CAT[pkg/catalog: methods, state.json, links]
  end
  T -- "writes" --> ENV[/etc/ctunnel/tunnels/NAME.env/]
  T -- "systemctl" --> U1[ctunnel@NAME]
  T -- "systemctl" --> U2[ctunnel-engine@NAME]
  U1 --> K[ctunnel-kernel up/down]
  U2 --> K
  U2 --> ENG[ctunnel-engine]
  K -- "reads" --> ENV
  ENG -- "reads" --> ENV
  K --> NL[ip link / ip xfrm / iptables / tc]
  ENG --> TUN[TUN/TAP device] & SOCK[UDP or raw IP socket]
```

## Packages

| Package | Role |
|---|---|
| `pkg/catalog` | method list, `TunnelConfig`, `state.json` store, `ctunnel://` links, RouterOS commands |
| `pkg/tunnel` | `Normalize` (validation + allocation of subnet, ports, keys), env files, systemd control, status |
| `pkg/crypto` | AES-256-GCM sealing with per-direction keys, clock-based sequence numbers, 2000-packet replay window |
| `pkg/dpi` | protocol headers for the UDP-Crypt methods, 2+1 XOR FEC |
| `pkg/eoip` | MikroTik EoIP and EtherIP framing |
| `pkg/speedtest` | link test responder and client |
| `pkg/sysinfo` | CPU, memory, disk, network numbers for the panel |
| `pkg/webpanel` | HTTPS panel, session cookie + CSRF, login rate limit |
| `cmd/ctunnel-engine` | userspace data plane: TUN ⇄ UDP (UDP-Crypt) or TAP ⇄ raw IP (EoIP, EtherIP) |
| `scripts/ctunnel-kernel.sh` | builds and removes interfaces, MSS clamp, port forwards, IPsec |

## One iran, many kharej

`tunnel.Normalize` gives each tunnel on a server a unique index `N`, and from it the
`10.77.N.0/30` subnet, `fd77:N::/64` carrier addresses, default UDP port (`24000+N`,
`51820+N` for WireGuard), VNI and L2TP/EoIP IDs. It rejects a second tunnel that would
reuse a subnet, an exclusive UDP port or a forwarded port. The setup link carries the same
values to the kharej side, mirrored.

Port forwards are iptables rules tagged `ctunnel:NAME`; `ctunnel-kernel down NAME`
removes exactly those, so stopping one tunnel never touches another.

## UDP-Crypt packet

```
[protocol header][8B seq ^ mask][AES-GCM( padLen | padding | IP packet )][16B tag]
```

Each direction (`iran>kharej`, `kharej>iran`) has its own key. The engine follows the
peer's address after any authenticated packet and sends an empty keepalive every 10 s,
so either side may be behind NAT.
