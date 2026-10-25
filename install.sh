#!/usr/bin/env bash
# C-Tunnel installer.
#
#   sudo bash -c "$(curl -sL https://raw.githubusercontent.com/CIAUB/C-Tunnel/main/install.sh)"
#
# Downloads the latest GitHub Release, checks every file against the release's SHA256SUMS
# and installs only if all of them match. Set CTUNNEL_VERSION=v0.1.0 to pick a version.
# From a git checkout (sudo bash install.sh) it installs the local files instead.
set -euo pipefail

REPO="${CTUNNEL_REPO:-CIAUB/C-Tunnel}"
VERSION="${CTUNNEL_VERSION:-latest}"
GO_VERSION="1.22.12"

die() { echo "error: $*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "run as root: sudo bash -c \"\$(curl -sL https://raw.githubusercontent.com/${REPO}/main/install.sh)\""
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

case "$(uname -m)" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "unsupported architecture $(uname -m) (amd64 and arm64 only)" ;;
esac

missing=()
command -v ip >/dev/null 2>&1        || missing+=(iproute2)
command -v iptables >/dev/null 2>&1  || missing+=(iptables)
command -v curl >/dev/null 2>&1      || missing+=(curl)
command -v sha256sum >/dev/null 2>&1 || missing+=(coreutils)
if [[ "${#missing[@]}" -gt 0 ]]; then
    command -v apt-get >/dev/null 2>&1 || die "please install: ${missing[*]}"
    echo "Installing ${missing[*]}..."
    apt-get update -qq && apt-get install -y -qq "${missing[@]}"
fi

ASSETS=(
    "ctunnel-linux-${ARCH}"
    "ctunnel-engine-linux-${ARCH}"
    "ctunnel-kernel.sh"
    "ctunnel@.service"
    "ctunnel-engine@.service"
    "ctunnel-panel.service"
)

# fetch_release downloads the assets and SHA256SUMS of one release into WORK and stops
# before installing anything if a file is missing from SHA256SUMS or its hash differs.
fetch_release() {
    local base a line
    if [[ "${VERSION}" == "latest" ]]; then
        base="https://github.com/${REPO}/releases/latest/download"
    else
        [[ "${VERSION}" == v* ]] || VERSION="v${VERSION}"
        base="https://github.com/${REPO}/releases/download/${VERSION}"
    fi
    echo "Downloading C-Tunnel (${VERSION}) from github.com/${REPO}..."
    for a in SHA256SUMS "${ASSETS[@]}"; do
        curl -fsSL --retry 3 --connect-timeout 15 "${base}/${a}" -o "${WORK}/${a}" \
            || die "download failed: ${base}/${a}"
    done

    echo "Verifying SHA-256..."
    for a in "${ASSETS[@]}"; do
        line="$(grep -F "  ${a}" "${WORK}/SHA256SUMS" | grep -E "  ${a//./\\.}\$" || true)"
        [[ -n "${line}" ]] || die "${a} is not listed in SHA256SUMS. Nothing was installed."
        (cd "${WORK}" && echo "${line}" | sha256sum -c --status) \
            || die "checksum mismatch for ${a}: the download is corrupt or was modified. Nothing was installed."
    done
    echo "All ${#ASSETS[@]} files verified."
}

# use_checkout lays out a local source tree like a release, building binaries if needed.
use_checkout() {
    local src="$1"
    echo "Installing from ${src}..."
    if [[ ! -f "${src}/bin/ctunnel-linux-${ARCH}" || ! -f "${src}/bin/ctunnel-engine-linux-${ARCH}" ]]; then
        if ! command -v go >/dev/null 2>&1; then
            echo "Go not found; downloading Go ${GO_VERSION}..."
            curl -fL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -o "${WORK}/go.tgz"
            rm -rf /usr/local/go && tar -C /usr/local -xzf "${WORK}/go.tgz"
            export PATH="/usr/local/go/bin:${PATH}"
        fi
        echo "Building from source..."
        (cd "${src}" && mkdir -p bin \
            && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "bin/ctunnel-linux-${ARCH}" ./cmd/ctunnel \
            && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "bin/ctunnel-engine-linux-${ARCH}" ./cmd/ctunnel-engine)
    fi
    cp "${src}/bin/ctunnel-linux-${ARCH}" "${src}/bin/ctunnel-engine-linux-${ARCH}" "${src}/scripts/ctunnel-kernel.sh" "${src}"/systemd/*.service "${WORK}/"
}

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

script="${BASH_SOURCE[0]:-}"
if [[ -n "${script}" && -f "${script}" && -f "$(dirname "${script}")/scripts/ctunnel-kernel.sh" ]]; then
    use_checkout "$(cd "$(dirname "${script}")" && pwd)"
else
    fetch_release
fi

install -m 0755 "${WORK}/ctunnel-linux-${ARCH}" /usr/local/bin/ctunnel
install -m 0755 "${WORK}/ctunnel-engine-linux-${ARCH}" /usr/local/bin/ctunnel-engine
ln -sf /usr/local/bin/ctunnel /usr/local/bin/c-tunnel
install -d -m 0755 /usr/local/lib/ctunnel
sed 's/\r$//' "${WORK}/ctunnel-kernel.sh" > /usr/local/lib/ctunnel/ctunnel-kernel
chmod 0755 /usr/local/lib/ctunnel/ctunnel-kernel
for unit in ctunnel@.service ctunnel-engine@.service ctunnel-panel.service; do
    sed 's/\r$//' "${WORK}/${unit}" > "/etc/systemd/system/${unit}"
    chmod 0644 "/etc/systemd/system/${unit}"
done
install -d -m 0700 /etc/ctunnel /etc/ctunnel/tunnels
systemctl daemon-reload

# Pick up the new engine and panel binaries on update.
systemctl try-restart 'ctunnel-engine@*.service' ctunnel-panel.service 2>/dev/null || true

echo
echo "C-Tunnel $(/usr/local/bin/ctunnel version | awk '{print $2}') installed."
echo "Run: sudo ctunnel"
