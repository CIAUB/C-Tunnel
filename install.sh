#!/usr/bin/env bash
# C-Tunnel installer.
#
#   sudo bash -c "$(curl -sL https://raw.githubusercontent.com/CIAUB/C-Tunnel/main/install.sh)"
#
# A trailing version also works with bash -c (where it becomes $0):
#   sudo bash -c "$(curl -sL https://raw.githubusercontent.com/CIAUB/C-Tunnel/main/install.sh)" v0.2.1
# To install and immediately apply a setup link on a peer server:
#   sudo bash -c "$(curl -sL https://raw.githubusercontent.com/CIAUB/C-Tunnel/main/install.sh)" -- --apply-link 'ctunnel://...'
# Offline installation (no GitHub / internet access required):
#   sudo bash ctunnel-offline/install.sh
#   sudo bash install.sh --offline ctunnel-offline.zip
# Downloads the latest stable GitHub Release by default and verifies SHA256SUMS.
# Explicit arguments override CTUNNEL_VERSION; source mode uses CTUNNEL_LOCAL=1.
# When run from an extracted offline bundle, offline mode is enabled automatically.
set -euo pipefail

REPO="${CTUNNEL_REPO:-CIAUB/C-Tunnel}"
GO_VERSION="${CTUNNEL_GO_VERSION:-}"
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "invalid repository" >&2; exit 1; }

die() { echo -e "\033[1;31m✗ error:\033[0m $*" >&2; exit 1; }
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RST='\033[0m'; C_BOLD='\033[1m'; C_CYAN='\033[96m'; C_GREEN='\033[92m'; C_YELLOW='\033[93m'; C_GRAY='\033[90m'
else
    C_RST=''; C_BOLD=''; C_CYAN=''; C_GREEN=''; C_YELLOW=''; C_GRAY=''
fi
step() { printf '%b▸%b %b%s%b\n' "${C_CYAN}" "${C_RST}" "${C_BOLD}" "$*" "${C_RST}"; }
ok()   { printf '%b✓%b %s\n' "${C_GREEN}" "${C_RST}" "$*"; }
warn() { printf '%b!%b %s\n' "${C_YELLOW}" "${C_RST}" "$*" >&2; }

# bash -c SCRIPT VERSION puts VERSION in $0, whereas bash install.sh VERSION
# and bash -c SCRIPT -- VERSION put it in $1. Never treat a file path as a tag.
resolve_installer_version() {
    local launch_name="$1" source_path="$2"
    shift 2
    local positional=()
    APPLY_LINK="${CTUNNEL_APPLY_LINK:-}"
    OFFLINE_PATH="${CTUNNEL_OFFLINE:-}"
    if [[ -z "$source_path" && "$launch_name" == "--apply-link" ]]; then
        [[ "$#" -ge 1 && -n "$1" ]] || die "--apply-link requires a ctunnel:// setup link"
        APPLY_LINK="$1"
        shift
    elif [[ -z "$source_path" && "$launch_name" == --apply-link=* ]]; then
        APPLY_LINK="${launch_name#--apply-link=}"
        [[ -n "$APPLY_LINK" ]] || die "--apply-link requires a ctunnel:// setup link"
    elif [[ -z "$source_path" && "$launch_name" == "--offline" ]]; then
        [[ "$#" -ge 1 && -n "$1" ]] || die "--offline requires a bundle path (.zip, .tar.gz, or directory)"
        OFFLINE_PATH="$1"
        shift
    elif [[ -z "$source_path" && "$launch_name" == --offline=* ]]; then
        OFFLINE_PATH="${launch_name#--offline=}"
        [[ -n "$OFFLINE_PATH" ]] || die "--offline requires a bundle path (.zip, .tar.gz, or directory)"
    fi
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --apply-link)
                [[ "$#" -ge 2 && -n "$2" ]] || die "--apply-link requires a ctunnel:// setup link"
                APPLY_LINK="$2"
                shift 2
                ;;
            --apply-link=*)
                APPLY_LINK="${1#--apply-link=}"
                [[ -n "$APPLY_LINK" ]] || die "--apply-link requires a ctunnel:// setup link"
                shift
                ;;
            --offline)
                [[ "$#" -ge 2 && -n "$2" ]] || die "--offline requires a bundle path (.zip, .tar.gz, or directory)"
                OFFLINE_PATH="$2"
                shift 2
                ;;
            --offline=*)
                OFFLINE_PATH="${1#--offline=}"
                [[ -n "$OFFLINE_PATH" ]] || die "--offline requires a bundle path (.zip, .tar.gz, or directory)"
                shift
                ;;
            *)
                positional+=("$1")
                shift
                ;;
        esac
    done
    [[ "${#positional[@]}" -le 1 ]] || die "expected at most one version argument"
    VERSION="${CTUNNEL_VERSION:-latest}"
    if [[ "${#positional[@]}" -eq 1 ]]; then
        VERSION="${positional[0]}"
    elif [[ -z "$source_path" && ( "$launch_name" == latest || "$launch_name" =~ ^v?[0-9] ) ]]; then
        VERSION="$launch_name"
    fi
    [[ "$VERSION" == latest || "$VERSION" =~ ^v?[0-9][A-Za-z0-9_.-]*$ ]] || die "invalid version"
    if [[ "$VERSION" != latest && "$VERSION" != v* ]]; then
        VERSION="v${VERSION}"
    fi
    if [[ -n "$APPLY_LINK" ]]; then
        [[ "${#APPLY_LINK}" -le 8192 && "$APPLY_LINK" =~ ^ctunnel://[A-Za-z0-9_-]+$ ]] || die "invalid setup link"
    fi
}
resolve_installer_version "$0" "${BASH_SOURCE[0]:-}" "$@"

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "run as root: sudo bash -c \"\$(curl -sL https://raw.githubusercontent.com/${REPO}/main/install.sh)\""
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

# ARCH names the release assets; GO_TARGET is for building from source, where
# Go calls 32-bit ARM GOARCH=arm.
GO_TARGET=()
case "$(uname -m)" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7l|armv7|armv8l|armhf) ARCH="armv7"; GO_TARGET=(GOARCH=arm GOARM=7) ;;
    *) die "unsupported architecture $(uname -m) (amd64, arm64 and armv7 only)" ;;
esac

# Auto-detect an extracted offline bundle when install.sh is launched directly from it.
script="${BASH_SOURCE[0]:-}"
OFFLINE_SRC="${OFFLINE_PATH:-}"
if [[ -z "${OFFLINE_SRC}" && "${CTUNNEL_LOCAL:-0}" != "1" && -n "${script}" && -f "${script}" ]]; then
    script_dir="$(cd "$(dirname "${script}")" && pwd)"
    if [[ -f "${script_dir}/SHA256SUMS" && -f "${script_dir}/ctunnel-linux-${ARCH}" && -f "${script_dir}/ctunnel-engine-linux-${ARCH}" && -f "${script_dir}/ctunnel-kernel.sh" ]]; then
        OFFLINE_SRC="${script_dir}"
    fi
fi

# Serialize package installation and binary/unit replacement across invocations.
if command -v flock >/dev/null 2>&1; then
    exec 9>/run/ctunnel-install.lock
    flock -w 120 9 || die "another installation is running"
elif [[ -z "${OFFLINE_SRC}" ]]; then
    die "install util-linux (flock) first"
fi

if [[ -n "${OFFLINE_SRC}" ]]; then
    command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || command -v openssl >/dev/null 2>&1 \
        || die "sha256sum, shasum, or openssl is required to verify the offline bundle"
    command -v ip >/dev/null 2>&1 || warn "iproute2 (ip) is not installed — Layer-4 tunnels work; install iproute2 for Layer-3/L2 tunnels"
    command -v iptables >/dev/null 2>&1 || warn "iptables is not installed — Layer-4 tunnels work; install iptables for L3 NAT/port-forwarding"
else
    missing=()
    command -v ip >/dev/null 2>&1        || missing+=(iproute2)
    command -v iptables >/dev/null 2>&1  || missing+=(iptables)
    command -v wg >/dev/null 2>&1        || missing+=(wireguard-tools)
    command -v curl >/dev/null 2>&1      || missing+=(curl)
    command -v sha256sum >/dev/null 2>&1 || missing+=(coreutils)
    if ! command -v go >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
        missing+=(python3)
    fi
    if [[ "${#missing[@]}" -gt 0 ]]; then
        command -v apt-get >/dev/null 2>&1 || die "please install: ${missing[*]}"
        echo "Installing ${missing[*]}..."
        apt-get update -qq && apt-get install -y -qq "${missing[@]}"
    fi

    command -v wg >/dev/null 2>&1 || die "wireguard-tools installation failed; install wireguard-tools and retry"
fi

ASSETS=(
    "ctunnel-linux-${ARCH}"
    "ctunnel-engine-linux-${ARCH}"
    "ctunnel-kernel.sh"
    "ctunnel@.service"
    "ctunnel-engine@.service"
    "ctunnel-panel.service"
    "ctunnel-agent.service"
)

# fetch_release downloads the assets and SHA256SUMS of one release into WORK and stops
# before installing anything if a file is missing from SHA256SUMS or its hash differs.
fetch_release() {
    local base a line
    if [[ "${VERSION}" == "latest" ]]; then
        # GitHub /releases/latest excludes draft and pre-release entries.
        # Resolve it once so every asset belongs to the same stable tag.
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

# Go publishes archive hashes in its download JSON, not per-archive .sha256 files.
bootstrap_go() {
    local metadata_url='https://go.dev/dl/?mode=json' selection archive digest dl_arch="$ARCH"
    # Go ships one 32-bit ARM archive, for armv6l, which runs on armv7.
    [[ "$ARCH" == "armv7" ]] && dl_arch="armv6l"
    if [[ -n "$GO_VERSION" ]]; then
        [[ "$GO_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid Go version"
        metadata_url+='&include=all'
    fi
    curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 "$metadata_url" -o "${WORK}/go-releases.json"
    selection="$(python3 - "${WORK}/go-releases.json" "$GO_VERSION" "$dl_arch" <<'PYTHON'
import json
import re
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        releases = json.load(stream)
    requested, arch = sys.argv[2:]
    for release in releases:
        version = release["version"]
        if requested:
            if version != "go" + requested:
                continue
        elif not release.get("stable"):
            continue
        if not re.fullmatch(r"go[0-9]+\.[0-9]+\.[0-9]+", version):
            continue
        filename = f"{version}.linux-{arch}.tar.gz"
        for asset in release["files"]:
            if asset.get("filename") != filename or asset.get("kind") != "archive":
                continue
            digest = asset.get("sha256", "")
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("invalid Go SHA-256 in download metadata")
            print(version[2:], digest)
            sys.exit(0)
    raise ValueError("requested Linux Go archive not found in download metadata")
except (OSError, ValueError, TypeError, KeyError) as error:
    print(f"Go download metadata: {error}", file=sys.stderr)
    sys.exit(1)
PYTHON
)" || die "cannot select a verified Go archive"
    read -r GO_VERSION digest <<< "$selection"
    archive="go${GO_VERSION}.linux-${dl_arch}.tar.gz"
    echo "Go not found; downloading Go ${GO_VERSION}..."
    curl -fsSL --retry 3 --connect-timeout 15 --max-time 300 "https://go.dev/dl/${archive}" -o "${WORK}/go.tgz"
    printf '%s  %s\n' "$digest" "${WORK}/go.tgz" | sha256sum -c --status || die "Go checksum mismatch"
    tar -C "$WORK" -xzf "${WORK}/go.tgz"
    export PATH="${WORK}/go/bin:${PATH}"
}

# use_checkout lays out a local source tree like a release, building binaries if needed.
use_checkout() {
    local src="$1"
    echo "Installing from ${src}..."
    if ! command -v go >/dev/null 2>&1; then
        bootstrap_go
    fi
    echo "Building from source..."
    (cd "${src}" && mkdir -p bin \
        && env CGO_ENABLED=0 "${GO_TARGET[@]}" go build -trimpath -ldflags="-s -w" -o "bin/ctunnel-linux-${ARCH}" ./cmd/ctunnel \
        && env CGO_ENABLED=0 "${GO_TARGET[@]}" go build -trimpath -ldflags="-s -w" -o "bin/ctunnel-engine-linux-${ARCH}" ./cmd/ctunnel-engine)
    cp "${src}/bin/ctunnel-linux-${ARCH}" "${src}/bin/ctunnel-engine-linux-${ARCH}" "${src}/scripts/ctunnel-kernel.sh" "${src}"/systemd/*.service "${WORK}/"
}

verify_sha256_file() {
    local expected="$1" file="$2" actual=""
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$file" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$file" | awk '{print $1}')"
    elif command -v openssl >/dev/null 2>&1; then
        actual="$(openssl dgst -sha256 "$file" | awk '{print $NF}')"
    else
        die "no SHA-256 tool available (sha256sum, shasum, or openssl)"
    fi
    [[ "${actual,,}" == "${expected,,}" ]]
}

# use_offline installs verified release assets from a local directory, .zip, or .tar.gz
# without making any network or package-manager calls.
use_offline() {
    local src="$1" bundle_dir="" extract_dir a line expected
    if [[ -d "$src" ]]; then
        if [[ -f "${src}/SHA256SUMS" ]]; then
            bundle_dir="$src"
        elif [[ -f "${src}/ctunnel-offline/SHA256SUMS" ]]; then
            bundle_dir="${src}/ctunnel-offline"
        else
            die "invalid offline directory: SHA256SUMS not found in ${src}"
        fi
    elif [[ -f "$src" ]]; then
        extract_dir="${WORK}/offline-extract"
        mkdir -p "${extract_dir}"
        step "Extracting offline bundle (${src})..."
        case "$src" in
            *.zip|*.ZIP)
                if command -v unzip >/dev/null 2>&1; then
                    unzip -qo "$src" -d "${extract_dir}" || die "failed to extract ${src}"
                elif command -v python3 >/dev/null 2>&1; then
                    python3 -m zipfile -e "$src" "${extract_dir}" || die "failed to extract ${src}"
                elif command -v busybox >/dev/null 2>&1; then
                    busybox unzip -qo "$src" -d "${extract_dir}" || die "failed to extract ${src}"
                elif command -v bsdtar >/dev/null 2>&1; then
                    bsdtar -xf "$src" -C "${extract_dir}" || die "failed to extract ${src}"
                else
                    die "no zip extractor found (install unzip or python3, or use ctunnel-offline.tar.gz)"
                fi
                ;;
            *.tar.gz|*.tgz|*.TAR.GZ|*.TGZ)
                tar -xzf "$src" -C "${extract_dir}" || die "failed to extract ${src}"
                ;;
            *.tar|*.TAR)
                tar -xf "$src" -C "${extract_dir}" || die "failed to extract ${src}"
                ;;
            *)
                die "unsupported offline archive: ${src} (expected .zip, .tar.gz, or directory)"
                ;;
        esac
        if [[ -f "${extract_dir}/SHA256SUMS" ]]; then
            bundle_dir="${extract_dir}"
        elif [[ -f "${extract_dir}/ctunnel-offline/SHA256SUMS" ]]; then
            bundle_dir="${extract_dir}/ctunnel-offline"
        else
            local cand
            for cand in "${extract_dir}"/*; do
                if [[ -d "$cand" && -f "${cand}/SHA256SUMS" ]]; then
                    bundle_dir="$cand"
                    break
                fi
            done
        fi
        [[ -n "${bundle_dir}" ]] || die "invalid offline archive: SHA256SUMS not found inside ${src}"
    else
        die "offline bundle not found: ${src}"
    fi

    step "Installing C-Tunnel offline (linux/${ARCH})..."
    tr -d '\r' < "${bundle_dir}/SHA256SUMS" > "${WORK}/SHA256SUMS"
    for a in "${ASSETS[@]}"; do
        [[ -f "${bundle_dir}/${a}" ]] || die "missing ${a} in offline bundle (${bundle_dir})"
        cp "${bundle_dir}/${a}" "${WORK}/${a}"
    done

    step "Verifying SHA-256..."
    for a in "${ASSETS[@]}"; do
        line="$(awk -v name="$a" '$2 == name && length($1) == 64 && $1 !~ /[^0-9a-fA-F]/ {print}' "${WORK}/SHA256SUMS")"
        [[ -n "${line}" ]] || die "${a} is not listed in SHA256SUMS. Nothing was installed."
        [[ "$(printf '%s\n' "$line" | wc -l)" -eq 1 ]] || die "duplicate checksum for ${a}"
        expected="${line%% *}"
        verify_sha256_file "${expected}" "${WORK}/${a}" \
            || die "checksum mismatch for ${a}: the offline bundle is corrupt or was modified. Nothing was installed."
    done
    ok "Offline bundle verified (${#ASSETS[@]} files for linux/${ARCH})."
}

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

if [[ -n "${OFFLINE_SRC:-}" ]]; then
    use_offline "${OFFLINE_SRC}"
elif [[ "${CTUNNEL_LOCAL:-0}" == "1" && -n "${script}" && -f "${script}" && -f "$(dirname "${script}")/scripts/ctunnel-kernel.sh" ]]; then
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
for unit in ctunnel@.service ctunnel-engine@.service ctunnel-panel.service ctunnel-agent.service; do
    sed 's/\r$//' "${WORK}/${unit}" > "${WORK}/unit-normalized"
    atomic_binary "${WORK}/unit-normalized" "/etc/systemd/system/${unit}" 0644
done
install -d -m 0700 /etc/ctunnel /etc/ctunnel/tunnels
systemctl daemon-reload

# Pick up the new engine and panel binaries on update.
systemctl try-restart 'ctunnel-engine@*.service' ctunnel-panel.service || die "files installed, but service restart failed; inspect journalctl"
# The agent answers the tunnel benchmark and runs failover; idle without tunnels.
systemctl enable ctunnel-agent.service >/dev/null 2>&1 || die "cannot enable ctunnel-agent.service"
systemctl restart ctunnel-agent.service || die "files installed, but ctunnel-agent did not start; inspect journalctl -u ctunnel-agent"

echo
INSTALLED_VER="$(/usr/local/bin/ctunnel version | awk '{print $2}')"
ok "C-Tunnel ${INSTALLED_VER} installed."

apply_setup_link() {
    [[ -n "${APPLY_LINK:-}" ]] || return 0
    step "Connecting tunnel from setup link..."
    /usr/local/bin/ctunnel apply-link "$APPLY_LINK" || die "C-Tunnel installed, but applying the setup link failed"
}
apply_setup_link

if [[ -z "${APPLY_LINK:-}" ]]; then
    printf '%bRun:%b sudo ctunnel\n' "${C_GRAY}" "${C_RST}"
fi

# Only open the interactive menu in a terminal. Never leave the installation lock
# or temporary release files attached to the menu's long-running process.
launch_menu() {
    [[ -z "${APPLY_LINK:-}" && "${CTUNNEL_NO_MENU:-0}" != 1 && -t 0 && -t 1 ]] || return 0
    if command -v flock >/dev/null 2>&1; then
        flock -u 9 2>/dev/null || true
    fi
    exec 9>&- 2>/dev/null || true
    rm -rf -- "$WORK"
    trap - EXIT
    exec /usr/local/bin/ctunnel
}
launch_menu
