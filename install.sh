#!/usr/bin/env bash
# C-Tunnel installer.
#
# Online, always the latest code on the main branch:
#   bash <(curl -fsSL https://raw.githubusercontent.com/CIAUB/C-Tunnel/main/install.sh)
#
# Every file is checked against bin/SHA256SUMS from the same commit before anything is
# installed. From a git checkout (sudo bash install.sh) the local files are used instead.
set -euo pipefail

REPO="${CTUNNEL_REPO:-CIAUB/C-Tunnel}"
REF="${CTUNNEL_REF:-main}"
GO_VERSION="1.22.12"

die() { echo "error: $*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "run as root (sudo -i first, or: sudo bash install.sh)"
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

FILES=(
    "bin/ctunnel-linux-${ARCH}"
    "bin/ctunnel-engine-linux-${ARCH}"
    "scripts/ctunnel-kernel.sh"
    "systemd/ctunnel@.service"
    "systemd/ctunnel-engine@.service"
    "systemd/ctunnel-panel.service"
)

# Downloads FILES and bin/SHA256SUMS from one commit, so all files come from the same
# build, and refuses to continue if any checksum differs.
fetch_online() {
    local commit url f
    # Pin the branch to a commit; raw files of a branch can be served stale for a few minutes.
    commit="$(curl -fsSL --connect-timeout 15 -H 'Accept: application/vnd.github.sha' \
        "https://api.github.com/repos/${REPO}/commits/${REF}" 2>/dev/null || true)"
    [[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || commit="${REF}"
    echo "Downloading C-Tunnel from github.com/${REPO} (${REF} @ ${commit:0:7})..."

    SRC_DIR="$(mktemp -d)"
    trap 'rm -rf "${SRC_DIR}"' EXIT
    for f in bin/SHA256SUMS "${FILES[@]}"; do
        url="https://raw.githubusercontent.com/${REPO}/${commit}/${f}"
        mkdir -p "${SRC_DIR}/$(dirname "${f}")"
        curl -fsSL --retry 3 --connect-timeout 15 "${url}" -o "${SRC_DIR}/${f}" || die "download failed: ${url}"
    done

    echo "Verifying SHA-256..."
    local sums="${SRC_DIR}/bin/SHA256SUMS" line
    for f in "${FILES[@]}"; do
        line="$(grep -E "  ${f//./\\.}\$" "${sums}" || true)"
        [[ -n "${line}" ]] || die "${f} is not listed in bin/SHA256SUMS. Nothing was installed."
        (cd "${SRC_DIR}" && echo "${line}" | sha256sum -c --status) \
            || die "checksum mismatch for ${f}: the download is corrupt or was modified. Nothing was installed."
    done
    echo "All ${#FILES[@]} files verified."
}

build_from_source() {
    if ! command -v go >/dev/null 2>&1; then
        echo "Go not found; downloading Go ${GO_VERSION}..."
        local tgz
        tgz="$(mktemp)"
        curl -fL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -o "${tgz}"
        rm -rf /usr/local/go && tar -C /usr/local -xzf "${tgz}" && rm -f "${tgz}"
        export PATH="/usr/local/go/bin:${PATH}"
    fi
    echo "Building from source..."
    (cd "${SRC_DIR}" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "bin/ctunnel-linux-${ARCH}" ./cmd/ctunnel \
        && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "bin/ctunnel-engine-linux-${ARCH}" ./cmd/ctunnel-engine)
}

script="${BASH_SOURCE[0]:-}"
if [[ -n "${script}" && -f "${script}" && -f "$(dirname "${script}")/scripts/ctunnel-kernel.sh" ]]; then
    SRC_DIR="$(cd "$(dirname "${script}")" && pwd)"
    echo "Installing from ${SRC_DIR}..."
    [[ -f "${SRC_DIR}/bin/ctunnel-linux-${ARCH}" && -f "${SRC_DIR}/bin/ctunnel-engine-linux-${ARCH}" ]] || build_from_source
else
    fetch_online
fi

install -m 0755 "${SRC_DIR}/bin/ctunnel-linux-${ARCH}" /usr/local/bin/ctunnel
install -m 0755 "${SRC_DIR}/bin/ctunnel-engine-linux-${ARCH}" /usr/local/bin/ctunnel-engine
ln -sf /usr/local/bin/ctunnel /usr/local/bin/c-tunnel
install -d -m 0755 /usr/local/lib/ctunnel
sed 's/\r$//' "${SRC_DIR}/scripts/ctunnel-kernel.sh" > /usr/local/lib/ctunnel/ctunnel-kernel
chmod 0755 /usr/local/lib/ctunnel/ctunnel-kernel
for unit in ctunnel@.service ctunnel-engine@.service ctunnel-panel.service; do
    sed 's/\r$//' "${SRC_DIR}/systemd/${unit}" > "/etc/systemd/system/${unit}"
    chmod 0644 "/etc/systemd/system/${unit}"
done
install -d -m 0700 /etc/ctunnel /etc/ctunnel/tunnels
systemctl daemon-reload

# Pick up the new engine and panel binaries on update.
systemctl try-restart 'ctunnel-engine@*.service' ctunnel-panel.service 2>/dev/null || true

echo
echo "C-Tunnel $(/usr/local/bin/ctunnel version | awk '{print $2}') installed."
echo "Run: sudo ctunnel"
