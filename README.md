<div align="center">

# C-Tunnel

**Connect one Iran server to many kharej servers: kernel tunnels or encrypted UDP, port forwarding, a terminal menu and a web panel.**

[![Release](https://img.shields.io/github/v/release/CIAUB/C-Tunnel?color=ef4444)](https://github.com/CIAUB/C-Tunnel/releases/latest)
[![CI](https://github.com/CIAUB/C-Tunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/CIAUB/C-Tunnel/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/Go-1.22-00ADD8)
![Platform](https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-555)
[![Telegram](https://img.shields.io/badge/Telegram-@CiAUB-26A5E4?logo=telegram&logoColor=white)](https://t.me/CiAUB)

**English** · [فارسی](README_FA.md)

<img src="docs/panel.png" alt="C-Tunnel web panel" width="900">

</div>

## What it does

You create a tunnel on the Iran server and get a one-line `ctunnel://` link. Paste the link on
the kharej server and both sides are configured: addresses, ports, keys and MTU all match.
Repeat for every kharej server. Each tunnel gets its own `10.77.N.0/30` subnet, interface and
UDP port, so they never collide.

Users connect to a port on the Iran server (for example `443`) and C-Tunnel forwards it through
the tunnel to the same port, or to another port, on the kharej server.

## Features

- **28 tunnel methods** in three families
  - **L3 kernel**: `gre` · `ipip` · `6to4` · `6to4-gre` · `sit` · `ip6gre` · `ipip6` · `ip6ip6` · `wireguard` · `xfrm-ipsec` · `fou-gre` · `gue-ipip` · `ecmp-lanes`
  - **L2**: `eoip` (MikroTik) · `gretap` · `ip6gretap` · `vxlan` · `geneve` · `l2tpv3` · `etherip`
  - **UDP-Crypt**: `dtls-1.3` · `quic-v1` · `srtp-direct` · `wg-stealth` · `rudp-fec` · `dnscrypt-udp` · `ntp-direct` · `openvpn-dco`
- **One Iran, many kharej**: subnets, ports and IDs are allocated automatically, and conflicts are refused
- **Port forwarding** on the Iran side: `443`, or `2053=8443` to map different ports
- **Encrypted UDP**: AES-256-GCM with a separate key per direction, an anti-replay window and random padding. Each method uses the packet header of the protocol it is named after.
- **Loss recovery**: `rudp-fec` sends one parity packet for every two data packets and rebuilds a lost one without retransmission
- **MikroTik**: prints ready-to-paste RouterOS 7 commands for `gre`, `ipip`, `6to4`, `eoip`, `vxlan` and `wireguard`
- **Web panel** over HTTPS: server gauges, live traffic, create, import, restart and delete tunnels, and a link test
- **Link test**: latency, jitter, loss and 4-stream speed, followed by a suggested method
- **Survives reboots**: every tunnel is a systemd unit and is rebuilt cleanly on restart

## Install

Linux with systemd, amd64 or arm64, as root:

```bash
curl -fL https://github.com/CIAUB/C-Tunnel/releases/latest/download/c-tunnel.tar.gz | tar -xz
sudo bash c-tunnel/install.sh
sudo ctunnel
```

<details>
<summary>Build from source</summary>

```bash
git clone https://github.com/CIAUB/C-Tunnel.git
cd C-Tunnel
sudo bash install.sh   # downloads Go 1.22 if it is missing
```
</details>

To update later, run `sudo ctunnel` → **Update**, or run the install command again.

## Quick start

**1. On the Iran server**, once per kharej server:

```
sudo ctunnel  →  1) Setup Iran
   method            gre          (dtls-1.3 if GRE is filtered)
   remote server IP  <kharej IP>
   forward ports     443
```

The menu prints a link:

```
ctunnel://eyJuYW1lIjoidDEiLCJyb2xlIjoia2hhcmVqIiwibWV0aG9kIjoiZ3JlIi...
```

**2. On the kharej server:**

```
sudo ctunnel  →  2) Setup Kharej  →  paste the link
```

or, in one command:

```bash
sudo ctunnel apply-link 'ctunnel://...'
```

**3. Check it:**

```bash
sudo ctunnel status
```

```
 NAME      METHOD       ROLE   REMOTE           TUNNEL IP      PORT   STATE    RX / TX
 t1        gre          iran   203.0.113.10     10.77.1.1      0      up       1.2 GiB / 310.4 MiB
 t2        dtls-1.3     iran   203.0.113.11     10.77.2.1      24002  up       842.7 MiB / 95.1 MiB
```

## Which method?

| Situation | Use |
|---|---|
| GRE / IPIP not filtered | `gre`, `6to4`, `ipip`: kernel speed, lowest CPU |
| Raw protocols filtered | `dtls-1.3`, `quic-v1`, `wireguard`, or `gre` with a FOU port |
| Lossy route | `rudp-fec` |
| Encryption at kernel speed | `xfrm-ipsec`, `wireguard` |
| MikroTik on the other side | `gre`, `ipip`, `eoip`, `vxlan`, `wireguard` |

Not sure? Run `ctunnel speedtest-server` on one server and `ctunnel linktest <its IP>` on the
other. The result suggests a method based on the measured loss and jitter.

## Web panel

`sudo ctunnel` → **5) Web Panel → Start**. Open `https://<server-ip>:8443` and enter the login
code shown in the same menu. The certificate is self-signed, so accept the browser warning once.
Five wrong codes block that IP for five minutes. You can change the port and rotate the code
from the menu.

## Commands

| Command | |
|---|---|
| `ctunnel` | interactive menu |
| `ctunnel status` | tunnels with state and traffic |
| `ctunnel up\|restart\|down NAME` | control one tunnel |
| `ctunnel link NAME` | setup link (and MikroTik commands) for the other side |
| `ctunnel apply-link 'ctunnel://…'` | create and start a tunnel from a link |
| `ctunnel linktest HOST` | latency, loss and speed to HOST |
| `ctunnel speedtest-server` | responder for `linktest` (TCP 7711) |
| `ctunnel optimize` | BBR + fq, 64 MB socket buffers, forwarding |
| `ctunnel panel` | run the web panel in the foreground |
| `ctunnel catalog` | list all methods |

## Files and logs

| Path | |
|---|---|
| `/etc/ctunnel/state.json` | all tunnels, panel port and login code |
| `/etc/ctunnel/tunnels/NAME.env` | per-tunnel settings |
| `/usr/local/lib/ctunnel/ctunnel-kernel` | builds interfaces, forwards and IPsec |
| `ctunnel@NAME.service` | kernel tunnels |
| `ctunnel-engine@NAME.service` | UDP-Crypt, EoIP and EtherIP |
| `ctunnel-panel.service` | web panel |

```bash
journalctl -u ctunnel@t1 -u ctunnel-engine@t1 -n 50
```

## Troubleshooting

- **State is `failed`**: read the log above. A missing kernel module (`modprobe ip_gre`) or a
  blocked protocol or port on the provider's firewall is the usual cause.
- **State is `up` but nothing passes**: the other side is not configured, or a firewall drops
  the tunnel. Open the UDP port for UDP-Crypt and WireGuard, or protocol 47 for GRE.
- **UDP-Crypt drops packets after a restart**: both servers need roughly correct time (NTP),
  because sequence numbers start from the clock.
- **`sit` / `ip6ip6`** carry IPv6 only. Use `6to4` to forward IPv4 ports over an IPv6-in-IPv4 path.

## Community

News, releases and support: Telegram channel [@CiAUB](https://t.me/CiAUB).
Bugs and feature requests: [GitHub Issues](https://github.com/CIAUB/C-Tunnel/issues).

## Development

```bash
go test ./...
bash scripts/build-release.sh 0.1.0      # dist/c-tunnel.tar.gz
```

Pushing a `v*` tag builds the release in GitHub Actions. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
for how the pieces fit together.

> The UDP-Crypt methods only make packets look like DTLS, QUIC, RTP and so on to simple filters.
> They are not full implementations of those protocols.
