# Changelog

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
