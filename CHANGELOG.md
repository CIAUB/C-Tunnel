# Changelog

## [2.0.1]

### Fixed — Layer-4 TCP & Direct/Reverse TCP Tunnel Reliability
- **Silent / Blackholed Pooled TCP Connections (`pkg/l4/tcp_linux.go`, `pkg/l4/peek_linux.go`, `cmd/ctunnel-engine/revcarrier.go`):**
  - Enabled Linux `TCP_USER_TIMEOUT` (`20s`) and tighter TCP keepalive (`Idle: 10s, Interval: 3s, Count: 3`) on all Layer-4 TCP carrier sockets and 8-stream TCP carrier streams (`frp+*` / `turbo+*`), eliminating ~15-minute blackholed TCP zombies when intermediate firewalls/NATs drop idle flows silently without FIN/RST.
  - Enhanced `socketClosed()` on Linux with `TCP_INFO` state and unacked-retransmit detection so half-open or stalled pooled sockets are evicted immediately before ever being handed to a user connection.
- **Keepalive Pool Starvation (`pkg/l4/server.go`):**
  - Fixed `keepPool` draining the entire connection pool (`takeAll`) and pinging sequentially with a 5s timeout per dead socket — which could leave the pool empty and drop incoming user traffic with `"no connection from the Kharej server"`.
  - Pings now run concurrently in bounded halves (`pingPoolOnce`, `2s` per-socket write deadline) while keeping at least half of the pool available to incoming users at all times and preserving `Links` counts during sweeps.
- **Reverse TCP Idle Connection Storm (`pkg/l4/client.go`):**
  - Fixed `runPool` comparing total `Links` (idle + busy) against `poolWant`, which multiplied idle Reverse TCP connections from 16 to 64 within 6 seconds with zero traffic (causing reconnect bursts to hit `maxPendingPerIP` and trigger ISP/firewall rate limits).
  - Idle and busy stream counts are now tracked separately; temporary burst workers spawn only when active traffic drains the idle pool and exit automatically once the pool recovers.
- **Direct L4 (`direct+tcp`) Connection Runaway, Socket Leak & Silent Dial Errors (`pkg/l4/server.go`, `pkg/l4/client.go`):**
  - Replaced polling refill in `dialDirect` with slot-bounded event-driven refill so idle Direct pools stay steady at `Pool` (16) without doubling on startup or growing every 20s ping cycle, closed rejected sockets when the pool is full, and added rate-limited error logging for dial, handshake, and forwarding failures.
- **Kharej Backend Local Address Fallback (`pkg/l4/client.go`, `cmd/ctunnel-engine/l4.go`):**
  - Services listening on `[::1]` (IPv6 loopback) or the Kharej server's local interface IP (instead of `127.0.0.1`) previously failed silently with `ECONNREFUSED` and zero traffic. Kharej now falls back across `127.0.0.1`, `[::1]`, and verified local-interface addresses on this host (never external IPs), with rate-limited error logs when a backend port is unreachable.
- **Live TCP Traffic Counters, Slow-Stream Idle Timeout & Half-Close Deadlines (`pkg/l4/l4.go`):**
  - Fixed swapped `SetReadDeadline(halfCloseIdle)` targets in `pipe()` so half-closed streams time out the still-reading peer in 30s instead of lingering for 10 minutes.
  - Lowered `copyChunk` from `1 MiB` to `64 KiB` (matching Linux's default pipe buffer for zero-copy `splice`), ensuring active connections under 1 MiB report live RX/TX traffic immediately and refresh idle deadlines smoothly.
- **Rolling Upgrade Compatibility with v1.x Peers (`pkg/l4/client.go`, `pkg/l4/peerauth.go`):**
  - Fixed `dialAndHandshake` falling back only to `CT4\x02` when talking to an unupgraded v1.x server that only accepts `CT4\x01`, while preserving strict `CT4\x03` downgrade protection whenever pinned or configured strict.
- **NAT VPS Setup Links, Port Conflicts, Health Diagnostics & PCK Fallback (`pkg/webpanel`, `pkg/cli`, `pkg/tunnel`, `pkg/health`, `pkg/pck`):**
  - On 1:1 NAT VPSes with RFC1918 interface IPs, Layer-4 / Reverse / Carrier tunnel creation now prefers the server's public IPv4 for `ctunnel://` setup links so peers do not dial private addresses.
  - Fixed `exclusivePort` in `pkg/tunnel/config.go` to catch Direct Layer-4 port collisions; fixed `deploy.go`/`linktest.go`/`index.html` Direct L4 detection for `game-kcp`; fixed CLI `applyAndReport` and `pkg/health` output for Layer-4 TCP/Direct tunnels (including warning when an Iran L4 tunnel has no forwarded ports); fixed `pkg/pck/pckconn_linux.go` `openTx` fallback to raw IP socket when `txFile.SyscallConn()` fails.

## [2.0.0]

### Security
- **Go 1.26.10 Toolchain & Zero Reachable CVEs:** Releases are built with Go 1.26.10 (pinned in `go.mod`) and updated `golang.org/x/net` (`v0.62.0`), `x/crypto`, and `x/sys`. Earlier `v1.1.x` releases used Go 1.22 where `govulncheck` reported 37 reachable standard-library vulnerabilities (`net/http`, `crypto/tls`, `crypto/x509`, `net/url`); `govulncheck` now reports **0 reachable vulnerabilities**.
- **Layer-4 Handshake Flood Protection:** The Iran end of a Layer-4 tunnel caps unauthenticated in-flight handshakes at **64 per source IP** and **1024 globally**, immediately closing excess flood connections before file descriptors or goroutines can be exhausted, and drops idle WebSocket keep-alive connections after **60 seconds**.
- **Web Panel TOTP 2FA, IP/CIDR Allowlist & Browser Isolation Headers:**
  - Optional **RFC 6238 TOTP Two-Factor Authentication** (`pkg/webpanel/totp.go`) compatible with Authenticator apps.
  - Optional **IP / CIDR Allowlist** restricting Web Panel access to trusted IPv4/IPv6 ranges.
  - Sends strict `Content-Security-Policy` (`media-src 'self'`), `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, and `Permissions-Policy` headers, and rate-limits failed login attempts per `/64` IPv6 prefix.
- **Cryptographic Telegram Web Panel Authentication (`pkg/notify/webapp_auth.go`):**
  - **HTTPS Mini App (`web_app`):** Verifies Telegram's signed `initData` using `HMAC-SHA256("WebAppData", botToken)`, checks `auth_date` freshness, and confirms numeric `user.id` belongs to a configured admin (`401 Unauthorized` otherwise).
  - **Default HTTP 1-Tap Login (`#tgToken`):** Issues 30-minute `HMAC-SHA256("CTunnelPanelLoginV1", botToken)` signed tokens bound to the admin's numeric Telegram User ID and removes `#tgToken` from browser history via `history.replaceState` upon sign-in.
- **Atomic Private Config Writes & Constant-Time Auth:** `telegram.json`, `telegram-state.json`, `panel.json`, and `state.json` are written atomically through `0600` temporary files; connection-test and peer handshake secrets are compared in constant time; self-update strictly validates `owner/repo`.

### Added — 21 New Transports (28 → 49 Methods Across 6 Families) & 3 Operating Modes
- **Three Tunnel Operating Modes (CLI & Web Panel):**
  1. **Reverse Mode (`1`):** Kharej dials in and Iran only listens (zero outbound connections from Iran to foreign IPs).
  2. **Direct Mode (`2`):** Iran dials Kharej directly for lowest latency.
  3. **8× BBR Turbo Direct Mode (`3`):** 8 parallel BBR-paced TCP carrier streams for maximum throughput over throttled routes.
- **9 Layer-4 Direct & Reverse Transports (`pkg/l4`, `FamilyReverseL4`):**
  - `tcp` — Pooled TCP connections (16-connection warm pool, zero-copy kernel `splice`, isolated stream per user connection so TCP never runs inside TCP).
  - `tcpmux` — Multiplexed `smux` v2 streams over 4 TCP connections (`16 MiB` stream window, `64 KiB` frames).
  - `pck` — Multiplexed `smux` over KCP inside hand-built raw-socket TCP segments (`pkg/pck`, classic BPF filter, no kernel TCP state on either side, AES-encrypted, automatic iptables RST suppression and cleanup).
  - `ws` — WebSocket transport (1 connection per user flow, optional custom `Host` / SNI).
  - `wsmux` — Multiplexed `smux` streams over WebSockets.
  - `wss` — WebSocket inside TLS (auto-generated or custom TLS certificate, optional `Host` / SNI).
  - `wssmux` — Multiplexed `smux` streams over TLS WebSockets.
  - `udp` — Pooled KCP sessions over UDP (AES-encrypted, explicit frame FIN signaling for immediate half-close/close propagation).
  - `udpmux` — Multiplexed `smux` streams over KCP-over-UDP sessions (AES-encrypted).
  - Supports both TCP and UDP port forwarding, manual or `ctunnel://` link setup on Kharej, and automatic Layer-4 Failover to a backup Layer-4 method.
- **4 Dedicated Gaming Protocols (`FamilyGaming`, Direct & Reverse):**
  - `game-udp` — Ultra-low-overhead encrypted UDP with `DSCP EF` (`0x2e`) and `SO_PRIORITY 6` QoS prioritization, `IP_MTU_DISCOVER=DO`, and zero head-of-line blocking for lowest possible ping and jitter.
  - `game-fec` — Gaming UDP with **0-RTT XOR Forward Error Correction** (1 parity packet per 2 data packets) reconstructing lost packets immediately without retransmission wait.
  - `game-dup` — Gaming UDP with dual-send redundancy for small latency-critical game packets (`<= 320 B`) to survive bursty loss.
  - `game-kcp` — Low-latency Layer-4 gaming port-forwarder using a tuned `5 ms` nodelay KCP loop (`NoDelay(1, 5, 2, 1)`) for TCP and UDP game ports.
  - Dedicated **Gaming** category in CLI and Web Panel with Direct and Reverse subcategories and per-protocol descriptions.
- **2 Stealth Layer-3 Transports (`FamilyStealth`, Direct & Reverse):**
  - `faketcp` — AES-256-GCM Layer-3 tunnel encapsulated in TLS records inside hand-built raw-socket TCP segments (`pck` carrier): middleboxes see one consistent TCP TLS connection while packets travel at UDP speed with no inner retransmission.
  - `icmp` — AES-256-GCM Layer-3 tunnel inside ICMP Echo Request/Reply (`ping`) with a secret-derived identifier and automatic kernel echo-reply suppression rule.
- **3 New UDP-Crypt Protocol Look-Alikes (`FamilyUDPCrypt`, Direct & Reverse):**
  - `stun-turn` — WebRTC TURN ChannelData header framing + AES-256-GCM (automatically selects UDP port `3478` when free).
  - `gtp-u` — 3GPP mobile core GTP-U G-PDU header framing + AES-256-GCM (automatically selects UDP port `2152` when free).
  - `esp-udp` — IPsec NAT-T ESP-in-UDP header framing + AES-256-GCM (automatically selects UDP port `4500` when free).
- **3 New High-Speed Kernel L3 Carriers (`FamilyKernelL3`):**
  - `bareudp` — Linux 5.7+ kernel BareUDP device encapsulating IPv4 directly in UDP with zero tunnel header overhead (automatically selects UDP port `6635` when free, locked to peer IP via iptables).
  - `xgre` — eXtended multi-lane keyed GRE with `ignore-df`, optional FOU UDP wrapping, ECMP lanes, and MikroTik RouterOS 7 compatibility.
  - `xgre-ip` — IPIP encapsulated inside a multi-lane keyed `xGRE` carrier.

### Added — Telegram Bot v2, Multi-Admin, Iran Tunnel Relay & Passwordless Web Panel
- **Bot Works on Both Kharej and Iran Servers (`pkg/tgrelay`):**
  - Iran servers where `api.telegram.org` is filtered automatically relay all Bot API requests, file uploads/downloads, and sponsor asset fetches through active Kharej tunnels (via L3 tunnel peer proxy or L4 reserved control stream `0xFFFF`).
- **Bot API 10.1+ Native Rich Tables & Live `/start` Network Health Probe:**
  - Uses `sendRichMessage` and `editMessageText` (`rich_message.html`) to render native Telegram `<table border="1">` tables (with automatic fallback to `<pre>` Unicode box-drawing tables).
  - `/start` runs a concurrent live network health test (`probeAllHealth`) across all tunnels and displays a focused table of tunnel status (`UP`/`DOWN`/`QUOTA`/`OFF`), live ping (`RTT ms`), packet loss / stability grade, and overall network health score.
- **Bot API 9.4+ Semantic Colored Inline Buttons (`style`):**
  - Buttons are color-coded by function: `primary` (blue: Web Panel, Traffic Report, Add Quota, Restart, Backup, Admins), `success` (green: Tunnels, Healthy tunnels, Start / Override Start, Send Backup, Add Admin, Active toggles), `danger` (red: Down/Quota-stopped tunnels, Stop, Reset Usage, Restart All, Overwrite Restore, Remove Admin, Cancel), and neutral default.
- **Dedicated `⚙️ Manage` Submenu:**
  - Keeps `/start` uncluttered by grouping administrative features under `Manage`: Backup & Restore, Admins, Alerts, Server Resources, Premium Animated Emojis, Language switch (`FA`/`EN`), and Restart All Tunnels.
- **Telegram Premium Animated Custom Emojis (`pkg/notify/emoji.go`):**
  - Automatically detects `User.is_premium` on the bot owner's Telegram account, dynamically resolves animated `.tgs` custom emoji IDs via `getStickerSet` (`RestrictedEmoji` by default, or any custom `t.me/addemoji/<pack>` set inside `Manage → Premium Emojis`), and renders `<tg-emoji>` in messages and `icon_custom_emoji_id` on buttons, with transparent fallback to standard Unicode emojis.
- **Multi-Admin Support:**
  - Configure up to 32 numeric Telegram User IDs via the bot (`Manage → Admins → Add Admin` interactive prompt or `/addadmin` / `/deladmin`), CLI (`Manage → Telegram alerts`), Web Panel, or `telegram.json`, with lockout prevention refusing removal of the last remaining admin.
- **Direct Passwordless Web Panel Button on `/start`:**
  - Shows a clickable `🌐 Open Web Panel` button on `/start` by default over plain HTTP (auto-detecting server IP, port, and private base path with a 30-minute signed `#tgToken` auto-login link), and automatically upgrades to a native Telegram Mini App (`web_app`) button when HTTPS or a public `MiniAppURL` is configured.
- **Expanded Traffic Report (`📊 Traffic Report` & Daily Report):**
  - Native table showing per-tunnel RX, TX, `Δ` delta since last report, Quota usage percentage, archived traffic from deleted tunnels, **Server Total Consumed Volume (`Σ`)**, and **configured Bot Admins**.

### Added — Backup, Restore & Scheduled Auto-Backup with Persistent Traffic
- **`ctunnel-backup/2` Persistent Traffic Accounting (`pkg/tunnel/backup.go`):**
  - Stores every tunnel's cumulative RX/TX bytes (`TrafficSeedRx`, `TrafficSeedTx` + live kernel interface / L4 counters) and server-wide `ArchivedRx`/`ArchivedTx` inside both `state.json` and every backup archive.
  - When a backup is restored or migrated to a new server, each tunnel's recorded traffic is restored and included in total cumulative server traffic (`TotalTrafficAll`).
- **Manual Backup, Safe/Overwrite Restore & Auto-Backup (`pkg/notify/backup.go`):**
  - Download a full JSON backup or upload a backup file directly in the Telegram bot (`Manage → Backup & Restore`), Web Panel, or CLI.
  - Two restore modes: **Safe Restore** (keeps existing tunnels with matching names) and **Overwrite Restore** (replaces matching tunnels).
  - Configurable **Auto-Backup** schedule in the bot (`Off`, `6h`, `12h`, `24h`, `48h`, `7d`, or `1–720h`) automatically delivering backup archives to all admins.

### Added — Per-Tunnel Traffic Quotas & Bandwidth Rate Limits
- **Configurable on Creation & Edit (CLI & Web Panel):**
  - Each tunnel can optionally set a **Traffic Quota (`GB`)**, a **Bandwidth Rate Limit (`Mbps`)**, **both**, or **Unlimited**.
  - Bandwidth limits are enforced via Linux `tc` on L3/L2 tunnel interfaces and a thread-safe token-bucket rate limiter (`pkg/l4/ratelimit.go`) on Layer-4 streams.
- **Automatic Quota Stop & 3 Recovery Actions (`pkg/tunnel/quota.go`):**
  - The agent continuously tracks cumulative RX+TX against `QuotaGB`. Upon exhaustion, it automatically stops the tunnel, marks `QuotaStopped=true`, and sends an interactive Telegram alert to all admins.
  - Stopped tunnels stay disabled until an admin triggers one of three recovery actions (available in Telegram Bot, Web Panel, and CLI):
    1. **Manual Start (Override Quota):** Sets `QuotaOverride=true` and starts the tunnel so it runs without being auto-stopped again.
    2. **Reset Usage:** Resets the tunnel's cumulative traffic counter to `0` and resumes normal quota enforcement.
    3. **Interactive Add Quota (`➕ افزودن حجم`):** Prompts the admin for how many GB to add (supporting both English `25.5` and Persian `۵۰` digits), increases `QuotaGB`, and automatically resumes the tunnel.

### Added — Web Panel v2, Connection Test v2, In-Place Peer IP & Multi-Format Sponsor Space
- **In-Place Change Peer IP (`pkg/tunnel/peer.go`):**
  - Change any tunnel's remote server IP in place from CLI (`Manage → Change Peer IP`) or Web Panel (Manage tab & tunnel card) without deleting or recreating the tunnel; validates IP conflicts, updates config, and restarts the service cleanly.
- **Active Data Probe (`pkg/tunnel/probe.go`) & Real ICMP Ping Cards:**
  - Before declaring an idle tunnel disconnected or triggering failover, the agent sends an active verification probe through the tunnel (L4 stream echo, TCP echo, or ICMP ping) so idle tunnels never cause false-down alerts.
  - Tunnel status cards in the Web Panel measure and display genuine ICMP echo RTT, jitter, and packet loss.
- **Connection Test v2 (`pkg/conntest`):**
  - Benchmarks real Layer-4 tunnels (`pkg/conntest/layer4.go`), `icmp` tunnel-sized echoes (`pkg/conntest/icmp.go`), `faketcp`, `rev+`, and `frp+` carriers alongside all L3/L2/UDP-Crypt methods.
  - Supports selective fast runs: `ctunnel conntest -new` (only methods new in v2.0), `-only udp,udpmux,icmp,game-udp` (any comma-separated list), and binary-search `DF=1` Path MTU discovery (`pkg/conntest/pmtu_search.go`).
  - Web Panel Connection Test features an Ookla-style animated sweep arc dial gauge with unified `Ping → Upload → Download` telemetry.
- **Web Panel UX, Live SSE Telemetry & Self-Update (`pkg/webpanel`):**
  - Light, Dark, and Auto themes; live Server-Sent Events (SSE) bandwidth and latency console; CSS-only skeleton shimmer loading states for cards, tables, and sponsor media; crisp button action spinners; and runtime HTML/CSS/JS minification (`pkg/webpanel/minify.go`).
  - **One-Click Self-Update (`pkg/webpanel/selfupdate.go`):** Runs `install.sh` inside a dedicated transient systemd unit so the update survives panel restarts and streams live progress logs.
  - **Smart Host IP Discovery (`pkg/hostip`):** Offers only usable local interface/public IPv4 & IPv6 addresses when creating tunnels.
- **Multi-Format Sponsor Space (`pkg/sponsor`, `pkg/notify/sponsor.go`):**
  - Supports images, animated GIFs, and videos: `.png`, `.jpg`, `.jpeg`, `.webp`, `.gif`, `.mp4`, `.webm`, `.mov` validated by magic bytes / ISOBMFF `ftyp` brands.
  - Case-insensitive `sponser*`/`sponsor*` file discovery across server-local `<storeDir>/sponsor/custom/`, `assets/`, remote manifest/GitHub repository, and embedded binary defaults (`default.png` + `136 KiB` fast-start looping `default_promo.mp4`).
  - Non-repeating random rotation on every Web Panel load (plus live `↻` switcher, `ETag` / `304 Not Modified` caching, and automatic `?prefer=image` fallback if `<video>` playback fails).
  - Weekly Friday `12:00 Asia/Tehran` Telegram push (`sendPhoto` / `sendAnimation` / `sendVideo`) with sanitized Telegram HTML captions from `spontext.txt`, inline CTA button from `sponlink.txt`, cached `file_id` reuse, and same-Friday asset pinning across retries.

### Changed — Engine & Kernel Performance Optimizations (Up to 2.5× Faster)
- **Zero-Copy Kernel TCP `splice`:** Layer-4 `tcp` transport splices payload bytes directly between sockets in the Linux kernel instead of copying through userspace buffers.
- **Batched 10 ms KCP ACKs & 4096 Flight Window:** KCP flushes ACKs once per `10 ms` tick instead of one packet per segment, and `pck` scales its in-flight window from `1024 → 4096` segments — accelerating `udp`, `udpmux`, and `pck` by **1.6× to 2.5×** between namespaces, **~25%** at `50 ms` RTT, and **10–20%** at `150 ms` RTT with identical latency.
- **16 MiB `smux` v2 Stream Window & 64 KiB Frames:** Per-stream mux flow window quadrupled (`4 MiB → 16 MiB`) with `64 KiB` frames for high-bandwidth long-RTT paths.
- **Vectorized Batch Socket I/O (`sendmmsg` / `recvmmsg`):** Batched packet transmission and reception in `pkg/pck/pckbatch_linux.go`, `pkg/l4/udpbatch.go`, and `cmd/ctunnel-engine/carrier_linux.go`.
- **UDP GSO/GRO, TUN Segmentation Offload & Multi-CPU Decapsulation:** Kernel helper and engine enable UDP Generic Segmentation/Receive Offload, TUN GSO/GRO, RPS multi-CPU tunnel decapsulation steering, and expanded `netdev_budget` / socket buffers.
- **Adaptive Path Controller (`pkg/pathctl`) & Userspace TCP MSS Clamping (`pkg/tcpmss`):** Real-time RTT/loss tracking dynamically adjusts FEC parity ratios, while userspace SYN MSS clamping prevents inner TCP fragmentation.
- **Kernel-Verified `TCP_INFO` Speedtest (`pkg/speedtest/acked_linux.go`):** Measures live throughput via Linux `TCP_INFO` `Bytes_acked` over a 1-second rolling window with peer-confirmed upload accounting.
- **Categorized 4-Step CLI Menu (`pkg/cli/categories.go`):** Terminal setup guides users through Mode → Family → Group → Method with clear descriptions instead of a flat list.

### Fixed
- **Idle Tunnel False-Down Prevention:** Idle tunnels with zero user traffic are probed actively via `pkg/tunnel/probe.go` before being reported down or triggering failover.
- **Busy Layer-4 Pool Health:** A Layer-4 tunnel whose pooled connections are all actively carrying user streams now counts busy connections as healthy links on both Iran and Kharej servers.
- **Connection Test Port Collisions:** When UDP `7712`, TCP `7711`, or Layer-4 `7714` is occupied by another process, Connection Test automatically moves to the next free port and displays the active ports.
- **Point-to-Point Default Route Guard (`pkg/pck/pckroute_linux.go`):** `pck` and `faketcp` skip point-to-point tunnel interfaces (`wg*`, `tun*`, `ct-*`) when resolving the underlay egress interface, and clean up `pck` iptables rules before engine exit.
- **Plain-HTTP Web Panel Clipboard Copy:** Copy buttons inside Web Panel dialogs include a reliable HTTP fallback and explicit failure notice when `navigator.clipboard` is unavailable over plain HTTP.
- **Sponsor Sync Resilience:** Fixed HTTP `304` handling so `spontext.txt` and `sponlink.txt` still refresh when media returns `304`, prevented legacy default overwrites on upgrade, stopped GitHub API `403`/`429` directory listings from wiping cached remote pools, and preserved embedded defaults on `404`.

## [1.1.2]

### Fixed
- Copy buttons in the panel's dialogs (setup link, update command, live log) copied nothing when the panel was opened over plain HTTP, while saying the text was copied. They copy again, and a copy that fails says so.

## [1.1.1]

### Fixed
- The sponsor banner never appeared: the image was lazy-loaded inside a hidden section, so the browser never fetched it. The banner now sits at the top of the panel, under the header, on every tab.
- The address buttons in Create tunnel and Test link no longer list tunnel devices (`ct-*`), point-to-point links or container bridges. The public address is shown once, marked when it is also set on the server, and an address behind NAT carries a warning.
- When every IPv4 service fails, the panel waits a minute before asking again instead of stalling each request for up to 6 seconds.

## [1.1.0]

### Added
- Sponsor banner in the web panel. The image is `assets/sponsor.png` in the GitHub repository, read again from GitHub on every login, and the section stays hidden if GitHub cannot be reached.
- The Create tunnel and Test link forms offer this server's public IPv4 and its own addresses as buttons. Nothing is filled in silently; the user picks the address a tunnel uses.

### Changed
- The public IPv4 comes from IPv4-only services (api4.ipify.org, ipv4.icanhazip.com, v4.ident.me, ifconfig.me), tried in order with a 3-second limit each and kept for 10 minutes. The server no longer reads its public address from the network interfaces.
- An empty "This server IP" still uses the address the engine binds to, so tunnels behind NAT keep starting as before.
- The panel certificate also lists the public and local addresses of the server.

## [1.0.0]

### Added
- Automatic failover. A tunnel can have a backup method; the new `ctunnel-agent` service on both servers switches both ends to it when the tunnel stops answering for 45 seconds, and tries the primary again every hour. The two ends agree through the clock, without talking to each other. Needs roughly correct time on both servers (NTP), as UDP-Crypt already does.
- Tunnel benchmark (Manage): download, upload, ping, jitter and loss of every running tunnel, measured through the tunnel, fastest marked. The other server answers on TCP 7719 of its tunnel IP (`ctunnel-agent`).
- Auto restart in the panel, with a 24-hour dial and a countdown, as in BackPack. Same schedule as the terminal menu's Auto Refresh.
- Built-in proxy card in the panel: turn the SOCKS5/HTTP proxy on or off, set the port and login, and see the forward to make on the Iran server.
- Colour themes: Ocean, Emerald, Violet, Amber, Rose and Red next to Mono, each light and dark.
- armv7 (32-bit ARM) servers: release binaries and building from source.
- The health check dials the Kharej end of every forwarded port through the tunnel, and says when nothing listens there or a forward is written the wrong way round.

### Changed
- Much faster UDP-Crypt. The TUN device now uses segmentation and receive offload: the kernel hands the engine TCP data in blocks of up to 64 KiB, which are cut into packets before encryption and merged again after decryption, so the device costs one system call per block instead of one per packet. Packets also move through the UDP socket in batches (`sendmmsg` / `recvmmsg`, UDP GSO and GRO) with an 8 MiB socket buffer. Between two network namespaces on 2 CPUs (dtls-1.3, MTU 1400, iperf3): one flow 1630 to 4470 Mbps, four flows 2185 to 4898 Mbps, compared with 0.4. Nothing changes on the wire, so 1.0 and 0.4 servers still work together; both servers need 1.0 for the full speed.
- Kernel tunnels: RPS is set on the network card that reaches the other server when the card has no mask of its own, so a one-queue VPS card no longer decapsulates every tunnel packet on one CPU. Optimize raises `net.core.netdev_budget` and the UDP socket minimums, and sets `net.ipv4.tcp_slow_start_after_idle = 0`, so the reverse carrier's TCP streams keep their speed after a pause.

### Fixed
- The connection test stopped with "the iran responder does not answer on UDP" when that UDP port was closed or filtered on the Iran server. It now marks the UDP and IP-protocol methods as skipped with the reason and still tests the TCP (frp+) methods.
- The built-in proxy could not be reached through a tunnel. A forwarded port arrives at the Kharej server's tunnel IP, but the proxy listened only on 127.0.0.1, so the connection was refused. It now also listens on the local tunnel IP of every tunnel on the server (added or removed tunnels are picked up within 5 seconds), and still never on a public address.
- SOCKS5 UDP through the built-in proxy did not work through a forwarded port: the relay sat on a port the forward does not carry. It now uses the proxy's own port, so forward the same port on both ends (for example `10800=10800`).
- The Built-in Proxy menu says which side of a forward is which: `443=<proxy port>` means Iran port 443 reaches the proxy.

### Upgrade note
- Update both servers to use failover and the benchmark: the agent runs only on 1.0 or newer.

[1.0.0]: https://github.com/CIAUB/C-Tunnel/compare/v0.4.1...v1.0.0

## [0.4.1] - 2026-11-02

### Fixed
- README panel screenshots show the 0.4 panel (desktop, mobile and settings) instead of the 0.2.1 ones.

## [0.4.0] - 2026-11-02

### Added
- Web panel rebuilt after BackPack's current panel: server strip with processor, memory, disk, swap, download and upload meters and their recent history; a dock with Overview, Connection test, Tunnels and Manage; light, dark and automatic appearance.
- Hash routes for every screen (`#/tunnels`, `#/t/<name>/logs`, `#/t/<name>/edit`, `#/health`, `#/settings`…). Dialogs open over their section and closing one returns there.
- Tunnel cards with state colour, live rate, traffic history and Start/Stop, Restart, Live log, Setup link, Edit and Delete.
- Live log per tunnel (`GET /api/tunnels/{name}/logs`): journal lines coloured by level, filter, line count, follow, copy.
- Start and stop a tunnel (`POST /api/tunnels/{name}/start`, `/stop`). A stopped tunnel stays stopped after a reboot.
- Health check in the panel (`GET /api/health`), the same checks as the CLI. They moved to `pkg/health`.
- Backup and restore (`GET /api/backup`, `POST /api/backup/restore`): every tunnel in one JSON file; restore creates and starts the tunnels a server does not have and leaves the others alone.
- Restart all (`POST /api/restart-all`), update check from Manage, random padding field for UDP-Crypt methods in the tunnel form.
- `GET /api/session`, so the page finds out it is signed out without an error in the browser console.
- Traffic totals survive restarts, edits and reboots. `ctunnel-kernel down` folds the interface counters into `/etc/ctunnel/traffic/<name>` before the interface is deleted, and the panel checkpoints them every minute, so a power cut loses at most a minute. Deleting a tunnel deletes its total.
- New tunnels are named after their end and port: `ir-24001` on Iran, `kh-24001` on Kharej (the tunnel's port, or the first forwarded port for a portless kernel tunnel; `ir-t3` when there is none or the name is taken). A setup link from `ir-24001` builds `kh-24001` on the other server. Names may be up to 10 characters. Existing tunnels keep their names.
- Chart history is sampled by the panel service in the background every 4 seconds, so the charts are already filled when the panel is opened.
- The panel reads every tunnel's state with one `systemctl` call per refresh instead of one per tunnel, and the health check tests tunnels side by side.
- `cmd/ctunnel-local`: runs the panel on a desktop with simulated tunnels, for trying the UI (`go run ./cmd/ctunnel-local`).

### Fixed
- Restarting a tunnel named `all` restarted every tunnel on the server.
- Copy buttons failed on a plain-HTTP panel, where the browser clipboard API is not available.
- Busy buttons replaced their label and icon with "Working…" and lost the icon afterwards.
- Delete used the browser's native confirm box; Stop, Delete, Restart all and Restore now ask in the panel.
- The tunnel form offered GRE lanes and tunnel ID for every method; they now show only for methods that use them.
- The header could push the page wider than a phone screen when an update was available.

### Upgrade note
- Traffic totals start counting from this version; what tunnels carried before the update is not in them.

[0.4.0]: https://github.com/CIAUB/C-Tunnel/compare/v0.3.0...v0.4.0

## [0.3.0] - 2026-11-01

### Fixed
- Reverse carrier: each TCP stream now has its own keys and replay window, derived from a random stream ID in the handshake. With one shared window, a stream stalled by a TCP retransmit fell behind the other streams and its whole backlog was dropped as replays once traffic passed about 8,000 packets in the stall, which collapsed throughput on lossy links. A recorded connection is still refused, because its handshake is checked against the carrier-wide window.

### Upgrade note
- Update the Iran server before the Kharej servers. A new Iran server still accepts old Kharej servers; an old Iran server cannot read traffic from a new Kharej server.

[0.3.0]: https://github.com/CIAUB/C-Tunnel/compare/v0.2.7...v0.3.0

## [0.2.7] - 2026-10-30

### Added
- Real-time telemetry backend in `pkg/webpanel/telemetry.go`: per-tunnel and aggregate RX/TX rates computed from live tunnel counters, with a 60-sample sliding history, counter-reset handling, and pruning when a tunnel disappears.
- Segmented workspace shell: `Overview` and `Tunnels` are ARIA tabs with `aria-selected`/`aria-controls`, while `Connection Test` and `Settings` open their existing consoles from the same navigation bar.
- Overview telemetry strip: active tunnels (`UP / TOTAL`), aggregate download and upload rates, cumulative data, host IP, and load average.
- Aggregate dual-series RX/TX SVG area chart plus inline per-tunnel sparklines that update their existing DOM nodes in place on every poll, so hover and focus state survive refreshes.
- Instant filter pills (`All`, `Iran`, `Kharej`, `Direct`, `Reverse`, `Up`, `Down`) and a search field matching name, IP, method and port, with an explicit empty state when nothing matches.
- Server-side GitHub release checker at `GET /api/version`: 4-second timeout, 30-minute in-memory cache, 64 KiB response cap, and a silent `update_available: false` fallback on networks without GitHub access. When a newer tag exists the panel shows an update pill and a modal with the release link and the install command.

### Changed
- Tunnel cards keep their existing Edit modal (`PUT /api/tunnels/{name}`) and Copy link action, now inside the Tunnels workspace behind the filters.
- Panel surfaces use frosted translucent cards with 1px specular borders, tabular-numeral telemetry, and system UI/monospace fonts only. No external fonts, CDNs or bundled assets, so the panel still renders on isolated networks.

### Security
- `GET /api/version` is authenticated, calls one fixed GitHub URL, and only returns a release link that starts with `https://github.com/`.
- Telemetry history is mutex-guarded and bounded to 60 samples per tunnel; the inline CSP hashes stay generated from the LF-normalized style and script blocks.

[0.2.7]: https://github.com/CIAUB/C-Tunnel/compare/v0.2.6...v0.2.7

## [0.2.6] - 2026-10-30

### Added
- Two-mode Connection Test: Iran listener with a generated `ctunnel-test://` link, live status, one-click copy, open UDP/TCP ports and a 15-minute self-closing lifecycle; Kharej async live tester with method table, Path MTU, and Best Direct / Best Reverse deployment.
- Tunnel Edit modal backed by `PUT /api/tunnels/{name}`, plus a quick Copy Setup Link action on every tunnel card.
- Operations-grade dark panel: tabular-nums telemetry, role/family badges, status badges, responsive benchmark tables, and clear loading/error states.

### Security
- Bounded login-limiter eviction, an 8 KiB setup-link cap, HSTS on HTTPS, and ownership/TTL bounds for test listeners and async test jobs.

[0.2.6]: https://github.com/CIAUB/C-Tunnel/compare/v0.2.5...v0.2.6

## [0.2.5] - 2026-10-30

### Fixed
- Stop an existing tunnel before replacing its env file, so old xfrm, L2TP, FOU and route state is torn down with the old config.
- Keep tunnel state and env when teardown fails; deletion no longer loses the only record of leftover interfaces and iptables rules.
- Fail `ctunnel-kernel down` when an iptables rule cannot be removed, and delete FOU/GUE receive ports during teardown.
- Fail tunnel startup when port forwards are configured but iptables is unavailable.
- Verify old systemd units are inactive before starting, restarting or deleting a tunnel.

[0.2.5]: https://github.com/CIAUB/C-Tunnel/compare/v0.2.4...v0.2.5

## [0.2.4] - 2026-10-30

### Fixed
- Normalize inline CSP hashes for CRLF checkouts so the web panel is not blocked on Windows builds.
- Fix the duplicate import field ID and keep tunnel action buttons attached across status refreshes.
- Retry atomic file replacement on Windows and serialize env reads and writes.
- Reject FOU and duplicate forward-port collisions; trim IP fields before writing env files.
- Invalidate sessions on logout and fall back to an interface IPv4 address when no default route exists.

### Changed
- Automated panel screenshot commits use the `CIAUB` identity instead of `github-actions[bot]`.
- Repository checkout enforces LF line endings except for `.bat` files.

[0.2.4]: https://github.com/CIAUB/C-Tunnel/compare/v0.2.3...v0.2.4

## [0.2.3] - 2026-10-28

### Hotfix - 2026-10-29
- Isolate panel session cookies by HTTP/HTTPS, host, port and base path so legacy Secure cookies cannot block HTTP login.
- Wait for any pre-login overview request before loading the authenticated dashboard; show dashboard-loading failures instead of silently returning to login.
- Open the menu automatically after installation in a terminal, releasing the install lock and cleaning temporary files first. Set `CTUNNEL_NO_MENU=1` for automation.
- Rebuild the existing v0.2.3 release assets and tag after validation; no new version is introduced.

### Fixed
- A version appended to the documented `sudo bash -c "$(curl ...)" v0.2.1` command is now recognized, including Bash's special `$0` handling. Script arguments also work, with or without the leading `v`.
- Explicit version arguments take precedence over `CTUNNEL_VERSION`; invalid tags or extra arguments fail before installation.

### Changed
- No version selects GitHub's latest stable release, excluding draft and pre-release entries. All assets remain pinned to one resolved tag and verified against SHA256SUMS.
- Release titles contain only the tag/version.

[0.2.3]: https://github.com/CIAUB/C-Tunnel/compare/v0.2.2...v0.2.3

## [0.2.2] - 2026-10-28

### Changed
- The initial web panel port is now **6969** instead of 8443. New installations and stores without a configured panel port use this default.
- Updated the panel URL examples in the English, Persian and Russian documentation.
- Existing saved panel ports are preserved; change an existing installation through the terminal Web Panel menu if needed.

[0.2.2]: https://github.com/CIAUB/C-Tunnel/compare/v0.2.1...v0.2.2

## [0.2.1] - 2026-10-28

### Added
- Persisted, random panel base paths with editable routing and custom domain settings.
- Validated custom TLS certificate/key paths and PEM uploads; automatic HTTPS with graceful listener reload.
- Measured per-method testing and session-bound, expiring, idempotent **Deploy Best Tunnel**.
- Desktop/mobile Chromium interaction checks and real DIRECT/REVERSE GRE integration tests.

### Changed
- Rebuilt the web panel with a restrained dark design, compact telemetry, accessible forms, keyboard navigation, loading states and toast feedback.
- Initial panel startup now uses **HTTP**. Open the exact random URL printed by the CLI; configure a domain and valid certificate pair in **Panel settings** for HTTPS.
- Added reproducible panel screenshots using synthetic data.

### Fixed
- Settings menu clipping and overlap with telemetry cards.
- Create validation hidden inside advanced fields, missing failure feedback and duplicate creation after failed startup.
- Reverse GRE idle-read stalls by attaching the TUN device before registering its descriptor with Go's network poller.
- Cross-origin mutation handling, strict JSON validation, session expiration, session invalidation after panel address/transport changes, and CSP without unsafe-inline scripts.

### Upgrade notes
- Update both endpoints to 0.2.1, then restart the panel and the affected tunnel services.
- Existing panel URLs change to a persisted random base path. Obtain the current URL and login code from the terminal Web Panel menu.
- Certificate uploads containing a private key require HTTPS or a loopback connection; over HTTP, configure existing certificate paths on the server.
- Deployment creates the local endpoint and returns a setup link for the peer. Carrier-shape tests do not prove kernel tunnel connectivity.
- No kernel throughput improvement is claimed without measurements on the deployed route.

### Validation
Go tests, vet, race checks, ShellCheck, Python automation tests, Chromium desktop/mobile flows, and isolated real-kernel GRE tests passed for the implementation. The GRE job verifies both directions after idle and reproduces the 0.2.0 regression before checking the fix.

[0.2.1]: https://github.com/CIAUB/C-Tunnel/compare/v0.2.0...v0.2.1
