# C-Tunnel

Point-to-point tunnels between an Iran server and one or more kharej servers, managed
from a terminal menu or a web panel. One iran server can carry many kharej servers at
once: each tunnel gets its own `10.77.N.0/30` subnet, its own interface and, where
needed, its own UDP port.

- **28 methods** in three families
  - L3 kernel: `6to4`, `6to4-gre`, `sit`, `ipip`, `gre`, `ip6gre`, `ipip6`, `ip6ip6`,
    `wireguard`, `xfrm-ipsec` (GRE + ESP), `fou-gre`, `gue-ipip`, `ecmp-lanes`
  - L2: `eoip` (MikroTik-compatible), `gretap`, `ip6gretap`, `vxlan`, `geneve`, `l2tpv3`, `etherip`
  - UDP-Crypt (AES-256-GCM, per-direction keys, anti-replay, random padding):
    `dtls-1.3`, `quic-v1`, `srtp-direct`, `wg-stealth`, `rudp-fec`, `dnscrypt-udp`,
    `ntp-direct`, `openvpn-dco` — the name is the protocol header the packets carry
- **Port forwarding** on the iran side: users connect to `iran:443`, traffic goes to
  `kharej:443` through the tunnel (`2053=8443` maps different ports)
- **Setup links**: create the tunnel on one server, paste one `ctunnel://` link on the other
- **MikroTik**: RouterOS 7 commands are printed for `gre`, `ipip`, `6to4`, `eoip`, `vxlan`, `wireguard`
- **rudp-fec**: 2+1 XOR parity, recovers any single lost packet in each group without retransmission
- Tunnels survive reboots (systemd units) and are rebuilt cleanly on restart

## Install

Linux with systemd, amd64 or arm64, as root:

```bash
curl -fL https://github.com/CIAUB/C-Tunnel/releases/latest/download/c-tunnel.tar.gz -o c-tunnel.tar.gz
tar -xzf c-tunnel.tar.gz
sudo bash c-tunnel/install.sh
sudo ctunnel
```

From source (needs Go 1.22+, or `install.sh` downloads it):

```bash
git clone https://github.com/CIAUB/C-Tunnel.git && cd C-Tunnel
sudo bash install.sh
```

## Quick start: one iran, two kharej

On the **iran** server, once per kharej server:

```
sudo ctunnel  →  1) Setup Iran
  method: gre (or dtls-1.3 if plain GRE is filtered)
  remote server IP: <kharej IP>
  forward ports: 443
```

It prints a `ctunnel://` link. On that **kharej** server:

```
sudo ctunnel  →  2) Setup Kharej  →  paste the link
```

or non-interactively: `sudo ctunnel apply-link 'ctunnel://...'`.

The second kharej server gets the next subnet (`10.77.2.0/30`), the next UDP port and its
own forwarded ports. A forwarded port can belong to only one tunnel.

## Commands

```
ctunnel                       interactive menu
ctunnel status                tunnels with state and traffic
ctunnel up|restart|down NAME  control one tunnel
ctunnel link NAME             setup link (and MikroTik commands) for the peer
ctunnel apply-link LINK       create and start the tunnel from a link
ctunnel linktest HOST         latency, loss, 4-stream speed (HOST runs `ctunnel speedtest-server`)
ctunnel panel                 run the web panel in the foreground
ctunnel optimize              BBR + fq, 64 MB socket buffers, forwarding
ctunnel catalog               list methods
```

## Web panel

Menu → **5) Web Panel → Start**. It listens on `https://<server-ip>:8443` with a
self-signed certificate (accept the browser warning once) and asks for the login code
shown in the same menu. Five wrong codes block that IP for five minutes.

## Choosing a method

| Link | Use |
|---|---|
| Clean, GRE/IPIP not filtered | `gre`, `6to4`, `ipip` — kernel speed, lowest CPU |
| Raw protocols filtered | `dtls-1.3`, `quic-v1`, `wireguard`, or `gre` with a FOU port |
| Lossy route | `rudp-fec` |
| Need encryption with kernel speed | `xfrm-ipsec` or `wireguard` |
| MikroTik on the other side | `gre`, `ipip`, `eoip`, `vxlan`, `wireguard` |

`ctunnel linktest` suggests one from measured loss and jitter.

## Files

| Path | What |
|---|---|
| `/etc/ctunnel/state.json` | all tunnels, panel port and login code |
| `/etc/ctunnel/tunnels/NAME.env` | per-tunnel settings read by the helper and the engine |
| `/usr/local/lib/ctunnel/ctunnel-kernel` | creates and removes interfaces, forwards, IPsec |
| `ctunnel@NAME.service` | kernel tunnels |
| `ctunnel-engine@NAME.service` | UDP-Crypt, EoIP and EtherIP (`/usr/local/bin/ctunnel-engine`) |
| `ctunnel-panel.service` | web panel |

Logs: `journalctl -u ctunnel@NAME -u ctunnel-engine@NAME`.

## Notes

- UDP-Crypt sequence numbers start from the clock, so both servers need a roughly correct
  time (NTP) to restart without the peer dropping packets as replays.
- `sit` and `ip6ip6` carry IPv6 only; use `6to4` to forward IPv4 ports over an IPv6-in-IPv4 path.
- The UDP-Crypt headers make packets look like the named protocol to simple filters; they
  are not full implementations of DTLS, QUIC and so on.

## Build a release

```bash
bash scripts/build-release.sh 0.1.0   # dist/c-tunnel.tar.gz
```

Pushing a tag `v*` runs the same script in GitHub Actions and attaches the archive to the release.

---

## راهنمای فارسی

یک سرور ایران را به یک یا چند سرور خارج وصل می‌کند. هر تانل subnet، اینترفیس و پورت
جدا می‌گیرد، پس چند خارج روی یک ایران بدون تداخل کار می‌کنند.

**نصب:**

```bash
curl -fL https://github.com/CIAUB/C-Tunnel/releases/latest/download/c-tunnel.tar.gz -o c-tunnel.tar.gz
tar -xzf c-tunnel.tar.gz && sudo bash c-tunnel/install.sh
```

**ساخت تانل:** روی سرور ایران `sudo ctunnel` ← `1) Setup Iran` ← روش، IP خارج و پورت‌هایی
که باید به خارج برسند (مثلاً `443`). لینک `ctunnel://` چاپ می‌شود؛ روی سرور خارج
`sudo ctunnel` ← `2) Setup Kharej` و لینک را بچسبانید. برای خارج بعدی همین کار را تکرار کنید.

**پنل وب:** منوی `5) Web Panel` ← Start، آدرس `https://IP:8443` و کد ورود در همان منو.

**انتخاب روش:** اگر GRE فیلتر نیست `gre` یا `6to4` سریع‌ترین است؛ اگر فیلتر است
`dtls-1.3` یا `quic-v1`؛ برای مسیر پر از packet loss از `rudp-fec` استفاده کنید.
