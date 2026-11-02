#!/usr/bin/env bash
# Builds the release assets into dist/: static linux/amd64, linux/arm64 and linux/arm (armv7) binaries,
# the kernel helper, the systemd units and SHA256SUMS, which install.sh verifies.
# GitHub Actions runs this when a v* tag is pushed and attaches dist/* to the release.
# Usage: scripts/build-release.sh [version]
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
VERSION="${1:-$(sed -n 's/^var Version = "\(.*\)"/\1/p' pkg/version/version.go)}"
LDFLAGS="-s -w -X ctunnel/pkg/version.Version=${VERSION}"

rm -rf dist
mkdir -p dist
# Asset name, then GOARCH and GOARM.
for target in "amd64 amd64 -" "arm64 arm64 -" "armv7 arm 7"; do
    read -r name goarch goarm <<< "${target}"
    [[ "${goarm}" == "-" ]] && goarm=""
    CGO_ENABLED=0 GOOS=linux GOARCH="${goarch}" GOARM="${goarm}" go build -trimpath -ldflags="${LDFLAGS}" -o "dist/ctunnel-linux-${name}" ./cmd/ctunnel
    CGO_ENABLED=0 GOOS=linux GOARCH="${goarch}" GOARM="${goarm}" go build -trimpath -ldflags="${LDFLAGS}" -o "dist/ctunnel-engine-linux-${name}" ./cmd/ctunnel-engine
done
cp scripts/ctunnel-kernel.sh systemd/*.service install.sh dist/
(cd dist && sha256sum ctunnel-linux-* ctunnel-engine-linux-* ctunnel-kernel.sh ./*.service install.sh | sed 's#  \./#  #' > SHA256SUMS)
cat dist/SHA256SUMS
