# Changelog

## [Unreleased]

### Fixed
- Reverse carrier: each TCP stream now has its own keys and replay window, derived from a random stream ID in the handshake. With one shared window, a stream stalled by a TCP retransmit fell behind the other streams and its whole backlog was dropped as replays once traffic passed about 8,000 packets in the stall, which collapsed throughput on lossy links. A recorded connection is still refused, because its handshake is checked against the carrier-wide window.

### Upgrade note
- Update the Iran server before the Kharej servers. A new Iran server still accepts old Kharej servers; an old Iran server cannot read traffic from a new Kharej server.

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
