# C-Tunnel v2 Upgrade Checklist

- [x] Task 1: Linux per-socket BBR (`TCP_CONGESTION`) in `pkg/tcpmss`
- [x] Task 2: L4 `CT4\x03` sealed target auth, peer pinning, busy-port isolation, pool burst refill, UDP batching & quieter logs (`pkg/l4`)
- [x] Task 3: Delay-based KCP path controller (`pkg/pathctl`) & PCK MTU clamp + `ENETDOWN`/`ENXIO` recovery (`pkg/pck`)
- [x] Task 4: Speedtest 5 ms upload ACKs, BBR, Peak (`Max`) & staged streams (`pkg/speedtest`, `pkg/conntest`, `pkg/webpanel/linktest.go`) + raw ICMP buffers
- [x] Task 5: PMTU outage guard (`pkg/conntest/pmtu_linux.go`) & sub-24h schedule divisor (`pkg/schedule`)
- [x] Task 6: CLI tunnel categorization & grouped navigation/status (`pkg/cli`)
- [x] Task 7: New square native C-Tunnel Sponsor Space image asset (`assets/sponsor.png`, `pkg/sponsor/default.png`)
- [x] Task 8: Sponsor manifest/cache backend (`pkg/sponsor`) & Friday Tehran-noon Telegram delivery (`pkg/notify`)
- [x] Task 9: Web Panel 1100px shell, asset minification+gzip+ETag, Overview square Sponsor Space UI, strict CSP & Peak UI (`pkg/webpanel`)
- [x] Task 10: Full verification, visual screenshots, security check, zero-attribution diff check, multi-arch release build & repo sync
