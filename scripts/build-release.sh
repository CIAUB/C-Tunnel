#!/usr/bin/env bash
# Builds static linux/amd64 and linux/arm64 binaries and the release archive
# dist/c-tunnel.tar.gz (the file `ctunnel` → Update downloads).
# Usage: scripts/build-release.sh [version]   e.g. scripts/build-release.sh 0.1.0
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
VERSION="${1:-$(sed -n 's/^var Version = "\(.*\)"/\1/p' pkg/version/version.go)}"
LDFLAGS="-s -w -X ctunnel/pkg/version.Version=${VERSION}"

rm -rf dist
mkdir -p dist/c-tunnel/bin
for arch in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath -ldflags="${LDFLAGS}" -o "dist/c-tunnel/bin/ctunnel-linux-${arch}" ./cmd/ctunnel
    CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath -ldflags="${LDFLAGS}" -o "dist/c-tunnel/bin/ctunnel-engine-linux-${arch}" ./cmd/ctunnel-engine
done
cp -r install.sh README.md scripts systemd dist/c-tunnel/
tar -C dist -czf dist/c-tunnel.tar.gz c-tunnel
(cd dist && sha256sum c-tunnel.tar.gz > c-tunnel.tar.gz.sha256)
echo "dist/c-tunnel.tar.gz (v${VERSION})"
