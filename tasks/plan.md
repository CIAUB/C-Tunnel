# C-Tunnel 2.0.0 — Full Recovery & Next-Gen Overhaul Plan

## Overview
1. Recover all Nov 14 (`c292c3b`) changes into the source repository (`/home/cia/c-tunnel/src/ctunnel`).
2. Fix the Telegram bot / agent false-disconnection bug on idle tunnels by adding an **Active Data Probe** (sending real test data through the tunnel and verifying return before declaring a tunnel down), plus fixing KCP/L4 idle drops, `ctunnel-kernel.sh` lane cleanup, and `udpcrypt.go` keepalive lifecycle.
3. Add **Ultra-Fast Direct Tunnel Methods** matching Reverse throughput:
   - Support **Direct mode** on Layer-4 transports (`tcp`, `tcpmux`, `pck`, `ws`, `wsmux`, `wss`, `wssmux`, `udp`, `udpmux`) with Linux kernel zero-copy `splice()`.
   - Add **Multi-Stream BBR TCP Carrier (`direct+` / `turbo`)** and multi-queue batched UDP offload for Direct L2/L3 & UDP-Crypt tunnels.
4. Upgrade **Connection Test** in both CLI and Web Panel:
   - 3-way method selection in both CLI and Web Panel: `1: All`, `2: New in 2.0`, `3: Custom Select` (interactive multi-select in CLI and visual chip/checkbox selector in Web Panel).
   - Dedicated **Graphical Connection Test UI** in the Web Panel replacing raw terminal `<pre>` output with interactive cards, throughput bars, latency/jitter pills, probe rings, and Path/Tunnel MTU badges.
5. Upgrade **Web Panel Tunnel Cards**:
   - Smart forwarded-port summary (show 2–3 port pills + `+N more` interactive searchable popover/dialog with quick copy).
   - Live background **Tunnel Ping (RTT & Jitter)** tailored to tunnel type (L3/L2 tunnel IP probe + L4 stream/socket RTT) with color-coded badges and latency sparkline.
6. **Security Hardening** (Web Panel + Tunnels):
   - Optional TOTP 2FA (RFC 6238), IP/CIDR allowlist, Stealth mode for unknown paths, progressive rate limiting, session lock/revocation, and strict tunnel handshake/replay/firewall hardening.

## Phases & Checkpoints

### Phase 1 — Foundation: Recover Nov 14 (`c292c3b`) Source Additions
- **Task 1**: Add `pkg/hostip`, `pkg/tcpmss`, `pkg/tgrelay`, and update `pkg/webpanel/hostip.go` & `pkg/cli/menu.go`.
- **Task 2**: Add `pkg/notify/i18n.go`, `pkg/notify/menu.go`, `pkg/notify/relay.go`, `pkg/cli/telegram.go`, and update `pkg/notify/{config,notifier,telegram}.go` & `pkg/webpanel/telegram.go`.
- **Task 3**: Update `pkg/l4` (`peek_linux.go`, `kcpconn.go`, `server.go`, `client.go`, `l4.go`, `transport.go`), `pkg/agent/agent.go`, `pkg/speedtest/speedtest.go`, and `pkg/conntest/layer4.go`.
- **Checkpoint 1**: `go test ./...` passes on recovered baseline.

### Phase 2 — Core Bug Fixes & Active Data Probe Before Disconnection Alert
- **Task 4**: Fix KCP/L4 idle connection drops and implement `tunnel.ProbeAlive(tc)` active data probe (L3/L2 wakeup + TCP/ICMP data echo, L4 local unix / stream echo probe) used by both `notify.Notifier` and `agent.Monitor` before declaring any tunnel down. Fix `ctunnel-kernel.sh` lane teardown and `udpcrypt.go` keepalive exit.
- **Checkpoint 2**: Unit tests for idle tunnel active-probing and zero false-positive down alerts pass.

### Phase 3 — High-Throughput Direct Methods (Direct L4 + Multi-Stream Direct Carrier)
- **Task 5**: Enable Direct mode for L4 transports (`tcp`, `tcpmux`, `pck`, `ws`, `wsmux`, `wss`, `wssmux`, `udp`, `udpmux`) and multi-stream parallel TCP carrier (`turbo` / `MultiStream`) for Direct L2/L3 tunnels so Direct achieves full multi-stream BBR + zero-copy `splice()` bandwidth.
- **Checkpoint 3**: `go test ./pkg/l4/... ./pkg/tunnel/... ./cmd/ctunnel-engine/...` passes.

### Phase 4 — Connection Test Selection (1/2/3) & Graphical Web UI
- **Task 6**: Implement 3-mode method selection (`All`, `New in 2.0`, `Select`) in CLI (`connTestKharej` interactive selector) and Web Panel API (`/api/linktest/jobs`, `/api/linktest/methods`).
- **Task 7**: Build the graphical Connection Test dashboard in `pkg/webpanel/index.html` (visual method cards, speed bars, RTT/Jitter badges, Path/Tunnel MTU summary, live progress & responder report graphics).

### Phase 5 — Professional Tunnel Cards, Smart Port Summary & Live Ping
- **Task 8**: Add per-tunnel RTT (ms), Jitter (ms), and Ping history to `pkg/webpanel/telemetry.go` (measuring L3/L2 tunnel IP RTT and L4 peer/socket RTT) and upgrade `pkg/webpanel/index.html` tunnel cards with Ping badges, latency sparklines, and smart `2-3 ports + N more` searchable port modal.

### Phase 6 — Security Upgrade, Release Build & Security Audit
- **Task 9**: Add Web Panel security enhancements (optional TOTP 2FA, IP allowlist, Stealth mode, hardened sessions) and tunnel crypto/firewall hardening.
- **Task 10**: Run full test suite, update Graphify knowledge graph, build `amd64`/`arm64`/`armv7` release binaries, package `/home/cia/Downloads/c-tunnel-2.0.0-update.zip`, and run final security audit check.
