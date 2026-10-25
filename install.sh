#!/usr/bin/env bash
# Installs or updates C-Tunnel from a release archive or a source checkout.
set -euo pipefail

GO_VERSION="1.22.12"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "Run as root: sudo bash install.sh" >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemd is required" >&2; exit 1; }

case "$(uname -m)" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

missing=()
command -v ip >/dev/null 2>&1       || missing+=(iproute2)
command -v iptables >/dev/null 2>&1 || missing+=(iptables)
command -v curl >/dev/null 2>&1     || missing+=(curl)
if [[ "${#missing[@]}" -gt 0 ]]; then
    if command -v apt-get >/dev/null 2>&1; then
        echo "Installing ${missing[*]}..."
        apt-get update -qq && apt-get install -y -qq "${missing[@]}"
    else
        echo "Please install: ${missing[*]}" >&2
        exit 1
    fi
fi

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
    mkdir -p "${SRC_DIR}/bin"
    (cd "${SRC_DIR}" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "bin/ctunnel-linux-${ARCH}" ./cmd/ctunnel \
        && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "bin/ctunnel-engine-linux-${ARCH}" ./cmd/ctunnel-engine)
}

if [[ ! -f "${SRC_DIR}/bin/ctunnel-linux-${ARCH}" || ! -f "${SRC_DIR}/bin/ctunnel-engine-linux-${ARCH}" ]]; then
    build_from_source
fi

install -m 0755 "${SRC_DIR}/bin/ctunnel-linux-${ARCH}" /usr/local/bin/ctunnel
install -m 0755 "${SRC_DIR}/bin/ctunnel-engine-linux-${ARCH}" /usr/local/bin/ctunnel-engine
ln -sf /usr/local/bin/ctunnel /usr/local/bin/c-tunnel
install -d -m 0755 /usr/local/lib/ctunnel
sed 's/\r$//' "${SRC_DIR}/scripts/ctunnel-kernel.sh" > /usr/local/lib/ctunnel/ctunnel-kernel
chmod 0755 /usr/local/lib/ctunnel/ctunnel-kernel
for unit in ctunnel@.service ctunnel-engine@.service ctunnel-panel.service; do
    install -m 0644 "${SRC_DIR}/systemd/${unit}" "/etc/systemd/system/${unit}"
done
install -d -m 0700 /etc/ctunnel /etc/ctunnel/tunnels
systemctl daemon-reload

# Pick up the new engine and panel binaries on update.
systemctl try-restart 'ctunnel-engine@*.service' ctunnel-panel.service 2>/dev/null || true

echo
echo "C-Tunnel $(/usr/local/bin/ctunnel version | awk '{print $2}') installed."
echo "Run: sudo ctunnel"
