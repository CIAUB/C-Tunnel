#!/usr/bin/env bash
# Builds the release assets into dist/: static linux/amd64, linux/arm64 and linux/arm (armv7) binaries,
# the kernel helper, the systemd units, universal offline bundles (.zip and .tar.gz),
# and SHA256SUMS, which install.sh verifies.
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

# Build universal all-architecture offline bundles (amd64 + arm64 + armv7).
STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT
BUNDLE_DIR="${STAGE}/ctunnel-offline"
mkdir -p "${BUNDLE_DIR}"
cp dist/ctunnel-linux-* dist/ctunnel-engine-linux-* dist/ctunnel-kernel.sh dist/*.service dist/install.sh dist/SHA256SUMS "${BUNDLE_DIR}/"
chmod 0755 "${BUNDLE_DIR}"/ctunnel-linux-* "${BUNDLE_DIR}"/ctunnel-engine-linux-* "${BUNDLE_DIR}/ctunnel-kernel.sh" "${BUNDLE_DIR}/install.sh"
chmod 0644 "${BUNDLE_DIR}"/*.service "${BUNDLE_DIR}/SHA256SUMS"
cat > "${BUNDLE_DIR}/OFFLINE.txt" <<EOF
C-Tunnel v${VERSION} — Universal Offline Bundle (linux/amd64, linux/arm64, linux/armv7)

Install or update (no GitHub / internet access required):
  sudo bash ctunnel-offline/install.sh

Install and immediately connect a tunnel from a setup link:
  sudo bash ctunnel-offline/install.sh --apply-link 'ctunnel://...'
EOF

OUT_ZIP="${PWD}/dist/ctunnel-offline.zip"
OUT_TGZ="${PWD}/dist/ctunnel-offline.tar.gz"
if command -v zip >/dev/null 2>&1; then
    (cd "${STAGE}" && zip -9 -rq "${OUT_ZIP}" ctunnel-offline)
else
    python3 - "${STAGE}" "${OUT_ZIP}" <<'PYTHON'
import os
import stat
import sys
import zipfile

stage, out_zip = sys.argv[1], sys.argv[2]
root = os.path.join(stage, "ctunnel-offline")
with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for name in sorted(os.listdir(root)):
        full = os.path.join(root, name)
        st = os.stat(full)
        zi = zipfile.ZipInfo(f"ctunnel-offline/{name}")
        zi.compress_type = zipfile.ZIP_DEFLATED
        zi.external_attr = (stat.S_IMODE(st.st_mode) & 0xFFFF) << 16
        with open(full, "rb") as fh:
            zf.writestr(zi, fh.read())
PYTHON
fi
tar -C "${STAGE}" -czf "${OUT_TGZ}" ctunnel-offline

(cd dist && sha256sum ctunnel-offline.zip ctunnel-offline.tar.gz >> SHA256SUMS)
cat dist/SHA256SUMS
