# C-Tunnel 2.0.0 Task Checklist

- [x] Task 1: Recover `pkg/hostip`, `pkg/tcpmss`, `pkg/tgrelay`
- [x] Task 2: Recover `pkg/notify` (`i18n.go`, `menu.go`, `relay.go`, `config.go`, `notifier.go`, `telegram.go`) & `pkg/cli/telegram.go`
- [x] Task 3: Recover `pkg/l4` (`peek_linux.go`, `kcpconn.go`, `server.go`, `client.go`, `l4.go`, `transport.go`), `pkg/agent`, `pkg/speedtest`, `pkg/conntest`
- [x] Task 4: Fix Telegram bot / agent idle false-down bug with active data probe (`tunnel.ProbeAlive`) + fix `ctunnel-kernel.sh` & `udpcrypt.go` bugs
- [x] Task 5: Add high-speed Direct methods (Direct L4 zero-copy splice + 8-Stream BBR TCP Turbo Carrier `turbo+<method>`)
- [x] Task 6: Add 3-option method selector (`1: All`, `2: New in 2.0`, `3: Select`) in CLI & Web Panel API
- [x] Task 7: Build dedicated Graphical Connection Test UI in Web Panel
- [x] Task 8: Upgrade Web Panel tunnel cards (smart forwarded-ports summary + live tunnel Ping & Jitter per tunnel type)
- [x] Task 9: Upgrade Web Panel & Tunnel security (TOTP 2FA, IP allowlist, Stealth mode, tunnel hardening)
- [x] Task 10: Run all tests, build `amd64`/`arm64`/`armv7` binaries, update `c-tunnel-2.0.0-update.zip`, and run security audit

## Verification & Audit Summary
- **Unit & Integration Tests**: `go test ./...` passes across all packages (`pkg/catalog`, `pkg/tunnel`, `pkg/notify`, `pkg/agent`, `pkg/l4`, `pkg/conntest`, `pkg/webpanel`, `pkg/cli`, `cmd/ctunnel-engine`, etc.).
- **Security Check (`code-pro` / `web-pro` / `security-audit`)**:
  - Strict CSP (`default-src 'none'; style-src 'self' 'sha256-...'; script-src 'self' 'sha256-...'`) preserved without `unsafe-inline` or `unsafe-eval`.
  - Zero `innerHTML` with untrusted data; all DOM updates use safe `textContent` / `el(...)`.
  - TOTP 2FA (RFC 6238) verified with constant-time comparison and masked secret in API responses (`SafeView()`).
  - IP/CIDR allowlist enforced at outer HTTP handler with stealth `404` response and automatic loopback safety bypass.
  - All state-changing routes protected by session cookie + `X-CSRF-Token` + same-origin check (`TestEveryRouteNeedsASession` & `TestRouteListMatchesHandler` pass).
