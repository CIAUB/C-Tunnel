#!/usr/bin/env bash
# Builds static linux/amd64 and linux/arm64 binaries into bin/ and writes bin/SHA256SUMS,
# which install.sh checks before installing. GitHub Actions runs this on every push to main
# and commits the result, so the main branch always carries ready-to-install binaries.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p bin
for arch in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath -ldflags="-s -w" -o "bin/ctunnel-linux-${arch}" ./cmd/ctunnel
    CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath -ldflags="-s -w" -o "bin/ctunnel-engine-linux-${arch}" ./cmd/ctunnel-engine
done
sha256sum bin/ctunnel-linux-* bin/ctunnel-engine-linux-* scripts/ctunnel-kernel.sh systemd/*.service > bin/SHA256SUMS
cat bin/SHA256SUMS
