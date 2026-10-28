# Changelog

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
