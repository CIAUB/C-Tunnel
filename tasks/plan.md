# C-Tunnel v2.1 Major Upgrade Plan

## Overview
Native C-Tunnel upgrade across five subsystems:
1. Telegram Bot overhaul: multi-admin numeric User ID management, professional `<pre>` monospace tables, and passwordless direct Web Panel access via Telegram Mini App (`initData` HMAC-SHA256 verification).
2. Backup, Restore & Scheduled Auto-Backup (`ctunnel-backup/2`) with persistent per-tunnel and cumulative server-wide traffic accounting across migrations.
3. Optional per-tunnel Traffic Quota (GB) and Bandwidth Limit (Mbps — on both Kernel/TUN and Layer-4 tunnels) with automatic stop + Telegram alert and 3 recovery actions (Manual Override Start, Reset Usage, Add Extra Quota).
4. Dedicated **Gaming** protocol family (`Direct` & `Reverse`) with 4 tailored transports: `game-udp`, `game-fec`, `game-dup`, and `game-kcp`.
5. Multi-format Sponsor Space (`png/jpg/jpeg/webp/gif/mp4/webm/mov`), `sponser*`/`sponsor*` auto-discovery (local + remote GitHub Contents API + manifest), random non-repeating rotation, lightweight embedded promo video (`<400 KB`), Telegram `sendPhoto`/`sendAnimation`/`sendVideo`, and polished CSS-only Web Panel loading UX.

## Phases & Checkpoints
- **Phase 1**: Persistent traffic accounting, `ctunnel-backup/2` backup/restore, L4 rate limiting, quota model & agent enforcement (`pkg/catalog`, `pkg/tunnel`, `pkg/l4`, `pkg/agent`). Checkpoint: `go test -race ./pkg/catalog ./pkg/tunnel ./pkg/l4 ./pkg/agent`.
- **Phase 2**: Dedicated Gaming protocols (`game-udp`, `game-fec`, `game-dup`, `game-kcp`) across `pkg/catalog`, `pkg/dpi`, `cmd/ctunnel-engine`, `pkg/l4`, `pkg/tunnel`, `scripts/ctunnel-kernel.sh`, `pkg/cli`. Checkpoint: `go test -race ./pkg/catalog ./pkg/dpi ./pkg/tunnel ./pkg/l4 ./cmd/ctunnel-engine ./pkg/cli`.
- **Phase 3**: Multi-format Sponsor Space, random rotation, `tgrelay` `api.github.com:443` allowlist, lightweight square promo video (`assets/sponsor_promo.mp4` + `pkg/sponsor/default_promo.mp4`), Telegram `sendVideo`/`sendAnimation`/`sendPhoto`. Checkpoint: `go test -race ./pkg/tgrelay ./pkg/sponsor ./pkg/notify`.
- **Phase 4**: Telegram Bot overhaul (multi-admin, monospace `<pre>` tables, Mini App `initData` HMAC auth, Backup/Restore/Auto-Backup via bot, Quota & Gaming controls). Checkpoint: `go test -race ./pkg/notify ./pkg/agent`.
- **Phase 5**: Web Panel integration (`POST /api/auth/telegram`, quota APIs, multi-format `<video>` Sponsor Space, Gaming category, multi-admin/auto-backup settings, polished CSS loading UX) + CLI integration. Checkpoint: `go vet ./...`, full `go test -race`, `node --check`, headless Chrome visual check (0 console errors).
- **Phase 6**: Targeted `security-audit`, zero-attribution scan, multi-arch `amd64`/`arm64`/`armv7` release build, binary + source ZIP packaging, repo sync.
