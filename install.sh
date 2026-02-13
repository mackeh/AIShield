#!/bin/sh
# install.sh -- cross-platform installer for AIShield CLI
#
# Usage:
#   curl -sSfL https://raw.githubusercontent.com/mackeh/AIShield/main/install.sh | sh
#
# Environment variables:
#   AISHIELD_INSTALL_DIR  Override install directory (default: /usr/local/bin or ~/.local/bin)
#   AISHIELD_VERSION      Pin a specific version tag (default: latest)
#   AISHIELD_REPO         Override GitHub owner/repo (default: mackeh/AIShield)

set -eu

REPO="${AISHIELD_REPO:-mackeh/AIShield}"
INSTALL_DIR="${AISHIELD_INSTALL_DIR:-}"
BINARY_NAME="aishield"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { printf '  \033[1;34m==>\033[0m %s\n' "$*"; }
err()  { printf '  \033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "required tool not found: $1"; }

# ---------------------------------------------------------------------------
# Detect OS and architecture
# ---------------------------------------------------------------------------

detect_platform() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "${OS}" in
    Linux*)   PLATFORM_OS="linux"   ;;
    Darwin*)  PLATFORM_OS="macos"   ;;
    CYGWIN*|MINGW*|MSYS*) PLATFORM_OS="windows" ;;
    *)        err "Unsupported operating system: ${OS}" ;;
  esac

  case "${ARCH}" in
    x86_64|amd64)   PLATFORM_ARCH="x86_64"  ;;
    aarch64|arm64)   PLATFORM_ARCH="aarch64" ;;
    *)               err "Unsupported architecture: ${ARCH}" ;;
  esac

  # Map to Rust target triple
  case "${PLATFORM_OS}-${PLATFORM_ARCH}" in
    linux-x86_64)   TARGET="x86_64-unknown-linux-gnu"  ; EXT="tar.gz" ;;
    linux-aarch64)   TARGET="aarch64-unknown-linux-gnu" ; EXT="tar.gz" ;;
    macos-x86_64)    TARGET="x86_64-apple-darwin"       ; EXT="tar.gz" ;;
    macos-aarch64)   TARGET="aarch64-apple-darwin"      ; EXT="tar.gz" ;;
    windows-x86_64)  TARGET="x86_64-pc-windows-msvc"    ; EXT="zip"    ;;
    *)               err "No pre-built binary for ${PLATFORM_OS}/${PLATFORM_ARCH}" ;;
  esac

  log "Detected platform: ${PLATFORM_OS}/${PLATFORM_ARCH} (${TARGET})"
}

# ---------------------------------------------------------------------------
# Resolve the latest version tag from GitHub Releases API
# ---------------------------------------------------------------------------

resolve_version() {
  if [ -n "${AISHIELD_VERSION:-}" ]; then
    VERSION="${AISHIELD_VERSION}"
    log "Using pinned version: ${VERSION}"
    return
  fi

  need curl
  VERSION="$(
    curl -sSfL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
  )"

  [ -n "${VERSION}" ] || err "Could not determine latest release version"
  log "Latest release: ${VERSION}"
}

# ---------------------------------------------------------------------------
# Download, verify, and install
# ---------------------------------------------------------------------------

download_and_install() {
  VERSION_NUM="${VERSION#v}"
  ARCHIVE="aishield-${VERSION_NUM}-${TARGET}.${EXT}"
  CHECKSUM_FILE="${ARCHIVE}.sha256"
  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

  TMPDIR="$(mktemp -d)"
  trap 'rm -rf "${TMPDIR}"' EXIT

  log "Downloading ${ARCHIVE} ..."
  curl -sSfL -o "${TMPDIR}/${ARCHIVE}" "${BASE_URL}/${ARCHIVE}" \
    || err "Failed to download ${BASE_URL}/${ARCHIVE}"

  log "Downloading checksum ..."
  curl -sSfL -o "${TMPDIR}/${CHECKSUM_FILE}" "${BASE_URL}/${CHECKSUM_FILE}" \
    || err "Failed to download checksum file"

  # Verify SHA256
  log "Verifying SHA256 checksum ..."
  cd "${TMPDIR}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "${CHECKSUM_FILE}" || err "Checksum verification failed"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c "${CHECKSUM_FILE}" || err "Checksum verification failed"
  else
    log "WARNING: No sha256sum or shasum found; skipping checksum verification"
  fi
  cd - >/dev/null

  # Extract
  log "Extracting ..."
  case "${EXT}" in
    tar.gz)
      tar xzf "${TMPDIR}/${ARCHIVE}" -C "${TMPDIR}"
      SRC="${TMPDIR}/aishield-${VERSION_NUM}-${TARGET}/${BINARY_NAME}"
      ;;
    zip)
      need unzip
      unzip -q "${TMPDIR}/${ARCHIVE}" -d "${TMPDIR}"
      SRC="${TMPDIR}/aishield-${VERSION_NUM}-${TARGET}/${BINARY_NAME}.exe"
      ;;
  esac

  [ -f "${SRC}" ] || err "Binary not found after extraction: ${SRC}"

  # Determine install directory
  if [ -n "${INSTALL_DIR}" ]; then
    DEST="${INSTALL_DIR}"
  elif [ -w /usr/local/bin ]; then
    DEST="/usr/local/bin"
  else
    DEST="${HOME}/.local/bin"
    mkdir -p "${DEST}"
  fi

  log "Installing to ${DEST}/${BINARY_NAME} ..."
  cp "${SRC}" "${DEST}/${BINARY_NAME}"
  chmod +x "${DEST}/${BINARY_NAME}"

  # Verify installation
  if "${DEST}/${BINARY_NAME}" --version >/dev/null 2>&1; then
    log "Successfully installed $("${DEST}/${BINARY_NAME}" --version)"
  else
    log "Binary installed at ${DEST}/${BINARY_NAME}"
  fi

  # Warn if not on PATH
  case ":${PATH}:" in
    *":${DEST}:"*) ;;
    *)
      printf '\n'
      log "NOTE: ${DEST} is not in your PATH."
      log "Add it with:  export PATH=\"${DEST}:\$PATH\""
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  log "AIShield CLI installer"
  detect_platform
  resolve_version
  download_and_install
  printf '\n'
  log "Done. Run 'aishield --help' to get started."
}

main
