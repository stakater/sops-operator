#!/usr/bin/env bash
# Installs pinned operator-sdk and opm into ./bin, verifying the release checksums.
set -euo pipefail

OPERATOR_SDK_VERSION="${OPERATOR_SDK_VERSION:-v1.42.3}"
OPM_VERSION="${OPM_VERSION:-v1.74.0}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${ROOT}/bin"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
mkdir -p "${BIN_DIR}"

# install <release base URL> <asset name> <target name>
install_verified() {
  local base="$1" asset="$2" target="$3"
  curl -fsSL -o "${TMP}/${asset}" "${base}/${asset}"
  curl -fsSL -o "${TMP}/checksums.txt" "${base}/checksums.txt"
  if ! grep -E "[[:space:]]${asset}\$" "${TMP}/checksums.txt" > "${TMP}/expected.txt"; then
    echo "no checksum for ${asset} in ${base}/checksums.txt" >&2
    exit 1
  fi
  (cd "${TMP}" && shasum -a 256 -c expected.txt)
  install -m 0755 "${TMP}/${asset}" "${BIN_DIR}/${target}"
}

install_verified \
  "https://github.com/operator-framework/operator-sdk/releases/download/${OPERATOR_SDK_VERSION}" \
  "operator-sdk_${OS}_${ARCH}" operator-sdk
install_verified \
  "https://github.com/operator-framework/operator-registry/releases/download/${OPM_VERSION}" \
  "${OS}-${ARCH}-opm" opm

"${BIN_DIR}/operator-sdk" version
"${BIN_DIR}/opm" version
