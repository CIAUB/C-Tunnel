# C-Tunnel v2 Upgrade Plan

## Overview
Native C-Tunnel v2 upgrade covering:
1. Core transport security, send-side delay-based window control, L4 pool & UDP batching, per-socket BBR, and PCK/raw-socket resilience.
2. Connection test speed/peak upgrades (5 ms batched upload ACKs, per-socket BBR, dual-stage 4/16 stream saturation, whole-second peak rate, PMTU outage protection) and sub-24h restart schedule divisor alignment.
3. CLI tunnel categorization and grouped navigation/status/selection views.
4. Web Panel 1100px desktop layout, serve-time asset minification + gzip + ETag, strict-CSP same-origin Sponsor Space backend cache + weekly Tehran-Friday Telegram push, square Overview Sponsor Space card, and a new square native C-Tunnel sponsor image asset.

## Architecture Decisions
- **L4 Session Sealing (`CT4\x03`)**: Extend `pkg/l4` handshake with a transport-bound mutual challenge-response (`CT4\x03`) deriving a per-connection session key to HMAC-seal `[kind, port]` target headers, with automatic peer-upgrade pinning and backward compatibility with `CT4\x01`/`CT4\x02`.
- **Send-Side Path Control (`pkg/pathctl`)**: Implement a self-contained delay-based KCP send-window controller (SRTT smoothing, rolling 20s base RTT, periodic queue-drain probes, ENOBUFS overflow detection, dynamic ACK/write batching hysteresis) with zero wire changes.
- **PCK Carrier Recovery (`pkg/pck`)**: Clamp KCP MTU to the actual egress interface MTU when `< 1402`; absorb transient `ENETDOWN`/`ENETUNREACH`/`EHOSTUNREACH` drops and transparently reopen sockets on `ENXIO`/`ENODEV` interface recreation.
- **Connection Test Parity (`pkg/speedtest`, `pkg/conntest`)**: Keep smooth 1s rolling-window `Ping -> Upload -> Download` live telemetry while switching server upload ACKs to a 5 ms ticker, enabling per-socket BBR on Linux, recording best whole-second `Max` (peak) alongside sustained rate, and guarding PMTU binary search against transient outages.
- **CLI Categorization (`pkg/cli/categories.go`)**: Group tunnels by transport family & direction (`Layer 4 · Reverse`, `Layer 4 · Direct`, `UDP-Crypt`, `Stealth`, `L3 Kernel`, `L2 Kernel`) across `manageTunnels`, `printStatusTable`, and `tunnelMetrics` with category counts, status badges, and inline filter codes.
- **Sponsor Space (`pkg/sponsor`, `pkg/webpanel`, `pkg/notify`, `assets/sponsor.png`)**: Server-side cached manifest (`image`, `link`, `title`) + image store (30m TTL, ETag/Last-Modified revalidation, magic-byte MIME check <= 15 MiB, `http(s)` link check, relay fallback, embedded native square fallback) served from panel origin (`GET /api/sponsor`, `GET /api/sponsor/image`), rendered as a fixed `252px` square card beside the Overview traffic card, plus Friday Tehran-noon Telegram delivery.

## Phased Task Breakdown

### Phase 1: Core Networking, Security & Resilience
- **Task 1**: Add Linux per-socket BBR (`TCP_CONGESTION`) helper in `pkg/tcpmss` and wire into TCP dialers/listeners and `pkg/speedtest`.
  - Acceptance: `Control` sets both `TCP_MAXSEG` and best-effort `TCP_CONGESTION="bbr"`; builds on Linux and non-Linux; tests pass.
  - Scope: S (`pkg/tcpmss/`)
- **Task 2**: Implement `CT4\x03` transport-bound mutual handshake + HMAC-sealed target headers + peer upgrade pinning, isolated per-port bind retry, L4 pool burst refill, async header write timeout, UDP datagram batching queue (`256` cap, `32 KiB` batch, drop-oldest), and quieter expected-disconnect logs in `pkg/l4`.
  - Acceptance: Tampered `[kind, port]` header rejected under `CT4\x03`; one busy forwarded port does not block other ports; batched UDP forwarding passes round-trip tests; `go test -race ./pkg/l4` passes.
  - Scope: M (`pkg/l4/`)
- **Task 3**: Build `pkg/pathctl` delay-based KCP window controller + wire into `pkg/l4` KCP/PCK sessions; add PCK egress MTU clamping, `ENETDOWN`/`ENETUNREACH` absorption, and `ENXIO`/`ENODEV` async relink in `pkg/pck`.
  - Acceptance: `pkg/pathctl` unit tests cover slow-start, queue cut, ENOBUFS overflow, probe drain, and batching hysteresis; `pkg/pck` tests cover MTU clamping and link-down/relink handling; `go test -race ./pkg/pathctl ./pkg/pck` passes.
  - Scope: M (`pkg/pathctl/`, `pkg/pck/`, `pkg/l4/transport.go`)
- **Checkpoint 1**: `go test -race ./pkg/tcpmss ./pkg/l4 ./pkg/pathctl ./pkg/pck`

### Phase 2: Connection Test, PMTU Guard & Schedule Alignment
- **Task 4**: Upgrade `pkg/speedtest` with 5 ms batched upload ACKs, per-socket BBR, best whole-second peak tracking, and staged multi-stream throughput; propagate `UpPeakMbps`/`DownPeakMbps` into `pkg/conntest` & `pkg/webpanel/linktest.go`; raise raw ICMP socket buffer in `pkg/conntest/icmp.go`.
  - Acceptance: Upload ACK batcher flushes final count cleanly; peak >= avg reported accurately; existing `pkg/speedtest` and `pkg/conntest` tests pass.
  - Scope: M (`pkg/speedtest/`, `pkg/conntest/`, `pkg/webpanel/linktest.go`)
- **Task 5**: Add transient outage protection to `pkg/conntest/pmtu_linux.go` and sub-24h divisor alignment to `pkg/schedule/schedule.go`.
  - Acceptance: `EffectiveHours` maps `5->4, 7->6, 9..11->8, 13..23->12`; PMTU search verifies small probe before shrinking on outage; tests pass.
  - Scope: S (`pkg/conntest/`, `pkg/schedule/`)
- **Checkpoint 2**: `go test -race ./pkg/speedtest ./pkg/schedule` + targeted `go test ./pkg/conntest`

### Phase 3: CLI Tunnel Categorization
- **Task 6**: Build `pkg/cli/categories.go` and refactor `manageTunnels`, `printStatusTable`, `tunnelMetrics`, and method picker summaries in `pkg/cli/`.
  - Acceptance: Tunnels grouped clearly by category with counts and running/stopped summaries; category filter input works cleanly; `go test -race ./pkg/cli` passes with new categorization unit tests.
  - Scope: M (`pkg/cli/`)
- **Checkpoint 3**: `go test -race ./pkg/cli`

### Phase 4: Sponsor Space, New Square Image Asset, Web Panel & Telegram Delivery
- **Task 7**: Generate a clean square (`1024x1024`) native C-Tunnel Sponsor Space banner image (`assets/sponsor.png` + `pkg/sponsor/default.png`) and visually verify crisp typography and contrast.
  - Acceptance: Exact 1:1 square aspect ratio, readable `@CiAsAgent` call-to-action, zero artifacts or typos, visually inspected via `read_file`.
  - Scope: S (`assets/sponsor.png`, `pkg/sponsor/default.png`)
- **Task 8**: Build `pkg/sponsor` (manifest fetch, 30m cache, ETag/Last-Modified, magic-byte MIME validation <= 15 MiB, `http(s)` URL guard, relay fallback, embedded default fallback, 404/empty withdrawal) and weekly Friday Tehran-noon Telegram push in `pkg/notify/sponsor.go`.
  - Acceptance: Unit tests cover manifest caching, 304 revalidation, bad MIME rejection, non-http link stripping, 404 withdrawal, and Friday Tehran schedule; `go test -race ./pkg/sponsor ./pkg/notify` passes.
  - Scope: M (`pkg/sponsor/`, `pkg/notify/`)
- **Task 9**: Add serve-time HTML/CSS/JS minifier + gzip + ETag (`pkg/webpanel/minify.go`), wire `/api/sponsor` and `/api/sponsor/image`, tighten CSP to `img-src 'self' data:`, update `.shell` to `1100px`, integrate the fixed `252px` square Overview Sponsor Space card + responsive tablet/mobile layout + Connection Test `Max` peak display in `pkg/webpanel/index.html`.
  - Acceptance: All `pkg/webpanel` security/route/CSP tests pass; headless Chrome screenshots verified at desktop (`1280px`), tablet (`820px`), and mobile (`390px`) with zero console errors and WCAG AA contrast.
  - Scope: M (`pkg/webpanel/`)
- **Checkpoint 4**: `go vet ./...`, `go test -race ./...`, JS syntax check, headless Chrome visual audit.

### Phase 5: Review, Security Check & Release Packaging
- **Task 10**: Zero-attribution diff scan, two-axis code review, `security-audit` check on changed files, clean up temporary files, commit, build `amd64`/`arm64`/`armv7` release artifacts + `SHA256SUMS` + zips + git bundle, sync desktop repo.
  - Acceptance: Zero attribution leaks in diff; `go vet` and tests pass; security check report completed; all multi-arch binaries and checksums verified.

## Risks & Mitigations
- **CSP Inline Hash Mismatch after Minification**: Compute `inlineHash("style")` and `inlineHash("script")` from the exact minified `servedIndexHTML` bytes once via `sync.Once`, and test in `pkg/webpanel/minify_test.go`.
- **Backward Compatibility with Existing L4 Tunnels**: Keep `CT4\x01`/`CT4\x02` accepted until `CT4\x03` succeeds (or strict mode is explicitly configured), avoiding upgrade lockouts.
- **Connection Test Live Telemetry Regression**: Preserve the exact `Ping -> Upload -> Download` sequencing, 1s rolling window smoothing, and single dial gauge while adding 5 ms ACK batching, BBR, and Peak (`Max`) stats.
