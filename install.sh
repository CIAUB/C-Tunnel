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
GO_VERSION="${CTUNNEL_GO_VERSION:-}"
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "invalid repository" >&2; exit 1; }
[[ "$VERSION" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "invalid version" >&2; exit 1; }

die() { echo "error: $*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "run as root: sudo bash -c \"\$(curl -sL https://raw.githubusercontent.com/${REPO}/main/install.sh)\""
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

case "$(uname -m)" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "unsupported architecture $(uname -m) (amd64 and arm64 only)" ;;
esac

# Serialize package installation and binary/unit replacement across invocations.
command -v flock >/dev/null 2>&1 || die "install util-linux (flock) first"
exec 9>/run/ctunnel-install.lock
flock -w 120 9 || die "another installation is running"

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
        # Resolve latest once: all assets must belong to the same immutable tag.
        local resolved
        resolved="$(curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")"
        VERSION="${resolved##*/}"
        [[ "$VERSION" =~ ^v[0-9][A-Za-z0-9_.-]*$ ]] || die "cannot resolve release tag"
        base="https://github.com/${REPO}/releases/download/${VERSION}"
    else
        [[ "${VERSION}" == v* ]] || VERSION="v${VERSION}"
        base="https://github.com/${REPO}/releases/download/${VERSION}"
    fi
    echo "Downloading C-Tunnel (${VERSION}) from github.com/${REPO}..."
    for a in SHA256SUMS "${ASSETS[@]}"; do
        curl -fsSL --retry 3 --connect-timeout 15 --max-time 300 "${base}/${a}" -o "${WORK}/${a}" \
            || die "download failed: ${base}/${a}"
    done

    echo "Verifying SHA-256..."
    for a in "${ASSETS[@]}"; do
        line="$(awk -v name="$a" '$2 == name && length($1) == 64 && $1 !~ /[^0-9a-fA-F]/ {print}' "${WORK}/SHA256SUMS")"
        [[ "$(printf '%s\n' "$line" | wc -l)" -eq 1 ]] || die "duplicate checksum for ${a}"
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
    if ! command -v go >/dev/null 2>&1; then
        if [[ -z "$GO_VERSION" ]]; then
            local version_info
            version_info="$(curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 'https://go.dev/VERSION?m=text')"
            GO_VERSION="${version_info%%$'\n'*}"
            GO_VERSION="${GO_VERSION#go}"
        fi
        [[ "$GO_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid Go version"
        echo "Go not found; downloading Go ${GO_VERSION}..."
        local archive="go${GO_VERSION}.linux-${ARCH}.tar.gz" digest
        curl -fsSL --retry 3 --connect-timeout 15 --max-time 300 "https://go.dev/dl/${archive}" -o "${WORK}/go.tgz"
        digest="$(curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 "https://go.dev/dl/${archive}.sha256")"
        [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die "invalid Go checksum"
        printf '%s  %s\n' "$digest" "${WORK}/go.tgz" | sha256sum -c --status || die "Go checksum mismatch"
        tar -C "$WORK" -xzf "${WORK}/go.tgz"
        export PATH="${WORK}/go/bin:${PATH}"
    fi
    echo "Building from source..."
    (cd "${src}" && mkdir -p bin \
        && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "bin/ctunnel-linux-${ARCH}" ./cmd/ctunnel \
        && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "bin/ctunnel-engine-linux-${ARCH}" ./cmd/ctunnel-engine)
    cp "${src}/bin/ctunnel-linux-${ARCH}" "${src}/bin/ctunnel-engine-linux-${ARCH}" "${src}/scripts/ctunnel-kernel.sh" "${src}"/systemd/*.service "${WORK}/"
}

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

script="${BASH_SOURCE[0]:-}"
if [[ "${CTUNNEL_LOCAL:-0}" == "1" && -n "${script}" && -f "${script}" && -f "$(dirname "${script}")/scripts/ctunnel-kernel.sh" ]]; then
    use_checkout "$(cd "$(dirname "${script}")" && pwd)"
else
    fetch_release
fi

# Rename on the same filesystem: running executables remain intact until restart.
atomic_binary() {
    local staged
    staged="$(mktemp "$(dirname "$2")/.ctunnel-install.XXXXXX")"
    if ! install -m "${3:-0755}" "$1" "$staged" || ! mv -f "$staged" "$2"; then
        rm -f "$staged"
        die "cannot install $2"
    fi
}
atomic_binary "${WORK}/ctunnel-linux-${ARCH}" /usr/local/bin/ctunnel
atomic_binary "${WORK}/ctunnel-engine-linux-${ARCH}" /usr/local/bin/ctunnel-engine
ln -sf /usr/local/bin/ctunnel /usr/local/bin/c-tunnel
install -d -m 0755 /usr/local/lib/ctunnel
sed 's/\r$//' "${WORK}/ctunnel-kernel.sh" > "${WORK}/kernel-normalized"
atomic_binary "${WORK}/kernel-normalized" /usr/local/lib/ctunnel/ctunnel-kernel
for unit in ctunnel@.service ctunnel-engine@.service ctunnel-panel.service; do
    sed 's/\r$//' "${WORK}/${unit}" > "${WORK}/unit-normalized"
    atomic_binary "${WORK}/unit-normalized" "/etc/systemd/system/${unit}" 0644
done
install -d -m 0700 /etc/ctunnel /etc/ctunnel/tunnels
systemctl daemon-reload

# Pick up the new engine and panel binaries on update.
systemctl try-restart 'ctunnel-engine@*.service' ctunnel-panel.service || die "files installed, but service restart failed; inspect journalctl"

echo
echo "C-Tunnel $(/usr/local/bin/ctunnel version | awk '{print $2}') installed."
echo "Run: sudo ctunnel"
