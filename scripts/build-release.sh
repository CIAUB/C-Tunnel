#!/usr/bin/env bash
# Builds the release assets into dist/: static linux/amd64, linux/arm64 and linux/arm (armv7) binaries,
# the kernel helper, the systemd units, lightweight per-arch + universal offline bundles,
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

pack_zip() {
    local stage_dir="$1" out_zip="$2"
    if command -v zip >/dev/null 2>&1; then
        (cd "${stage_dir}" && zip -9 -rq "${out_zip}" ctunnel-offline)
    else
        python3 - "${stage_dir}" "${out_zip}" <<'PYTHON'
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
}

make_offline_bundle() {
    local label="$1" zip_name="$2" tgz_name="$3"
    shift 3
    local stage bundle_dir
    stage="$(mktemp -d)"
    bundle_dir="${stage}/ctunnel-offline"
    mkdir -p "${bundle_dir}"
    cp dist/ctunnel-kernel.sh dist/*.service dist/install.sh dist/SHA256SUMS "${bundle_dir}/"
    local a
    for a in "$@"; do
        cp "dist/ctunnel-linux-${a}" "dist/ctunnel-engine-linux-${a}" "${bundle_dir}/"
    done
    chmod 0755 "${bundle_dir}"/ctunnel-linux-* "${bundle_dir}"/ctunnel-engine-linux-* "${bundle_dir}/ctunnel-kernel.sh" "${bundle_dir}/install.sh"
    chmod 0644 "${bundle_dir}"/*.service "${bundle_dir}/SHA256SUMS"
    cat > "${bundle_dir}/OFFLINE.txt" <<EOF
C-Tunnel v${VERSION} — Offline Bundle (${label})

Install or update (no GitHub / internet access required):
  sudo bash ctunnel-offline/install.sh

Install and immediately connect a tunnel from a setup link:
  sudo bash ctunnel-offline/install.sh --apply-link 'ctunnel://...'
EOF
    pack_zip "${stage}" "${PWD}/dist/${zip_name}"
    if [[ -n "${tgz_name}" ]]; then
        tar -C "${stage}" -czf "${PWD}/dist/${tgz_name}" ctunnel-offline
    fi
    rm -rf "${stage}"
}

# Lightweight per-architecture offline bundles (~7.5-8.5 MB each).
make_offline_bundle "linux/amd64" "ctunnel-offline-amd64.zip" "ctunnel-offline-amd64.tar.gz" amd64
make_offline_bundle "linux/arm64" "ctunnel-offline-arm64.zip" "" arm64
make_offline_bundle "linux/armv7" "ctunnel-offline-armv7.zip" "" armv7
# Universal all-architecture bundle (~24 MB) for mixed/unknown CPUs.
make_offline_bundle "linux/amd64, linux/arm64, linux/armv7" "ctunnel-offline.zip" "ctunnel-offline.tar.gz" amd64 arm64 armv7

(cd dist && sha256sum ctunnel-offline-*.zip ctunnel-offline-*.tar.gz ctunnel-offline.zip ctunnel-offline.tar.gz >> SHA256SUMS)
cat dist/SHA256SUMS
