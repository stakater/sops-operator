#!/usr/bin/env bash
# Renders the file-based catalog from catalog/channels.yaml.
#
# channels.yaml is the upgrade graph: a version is released by adding sops-operator.vX.Y.Z to a
# channel in a reviewed change. Every bundle any channel lists is rendered, so older versions stay
# installable. When VERSION is listed in no channel, nothing is released and no index is written.
#
# Environment: CATALOG_DIR, CHANNELS (channels file; default $CATALOG_DIR/channels.yaml), VERSION, BUNDLE_REPO (published bundles, tagged vX.Y.Z), BUNDLE_IMG
# (bundle for VERSION; default $BUNDLE_REPO:v$VERSION), ICON, OPM, YQ, BUNDLE_IMG_RENDER_FLAGS (opm render flags for BUNDLE_IMG only,
# e.g. --use-http for a local test registry; published bundles are always pulled over TLS).
set -euo pipefail

: "${CATALOG_DIR:?}" "${VERSION:?}" "${BUNDLE_REPO:?}" "${ICON:?}"
OPM=${OPM:-opm}
YQ=${YQ:-yq}
PACKAGE=sops-operator
BUNDLE_IMG=${BUNDLE_IMG:-${BUNDLE_REPO}:v${VERSION}}
CHANNELS=${CHANNELS:-${CATALOG_DIR}/channels.yaml}
release="${CATALOG_DIR}/release"
bundles="${CATALOG_DIR}/bundles"

rm -rf "${release}" "${bundles}"
mkdir -p "${bundles}"
entries=$("${YQ}" ea 'select(.schema == "olm.channel") | .entries[].name' "${CHANNELS}" \
  | grep -v '^---$' | sort -u)

if ! grep -qx "${PACKAGE}.v${VERSION}" <<<"${entries}"; then
  echo "${PACKAGE}.v${VERSION} is not listed in ${CHANNELS}: not promoted, no catalog built"
  exit 0
fi

# opm pulls through containers/image, which refuses to pull without a signature policy. When the
# system has none (e.g. macOS), give opm the default accept-all policy in a temporary HOME; an
# existing user or system policy is never overridden. Registry credentials are passed through.
opm_env=()
if [ ! -f "${HOME}/.config/containers/policy.json" ] && [ ! -f /etc/containers/policy.json ]; then
  opm_home=$(mktemp -d)
  trap 'rm -rf "${opm_home}"' EXIT
  mkdir -p "${opm_home}/.config/containers"
  echo '{"default":[{"type":"insecureAcceptAnything"}]}' > "${opm_home}/.config/containers/policy.json"
  opm_env=(HOME="${opm_home}")
  docker_auth="${DOCKER_CONFIG:-${HOME}/.docker}/config.json"
  [ -f "${docker_auth}" ] && opm_env+=(REGISTRY_AUTH_FILE="${REGISTRY_AUTH_FILE:-${docker_auth}}")
fi

for entry in ${entries}; do
  version=${entry#"${PACKAGE}.v"}
  ref="${BUNDLE_REPO}:v${version}"
  flags=""
  [ "${version}" = "${VERSION}" ] && ref="${BUNDLE_IMG}" && flags=${BUNDLE_IMG_RENDER_FLAGS:-}
  # One file per bundle: yq joins them as separate documents whether or not opm starts its
  # output with a separator; concatenated output would merge bundles or leave empty documents.
  # shellcheck disable=SC2086 # flags holds separate flags
  env ${opm_env[@]+"${opm_env[@]}"} "${OPM}" render "${ref}" --output=yaml ${flags} > "${bundles}/${entry}.yaml"
  echo "rendered ${ref}"
done

mkdir -p "${release}"
ICON_DATA=$(base64 < "${ICON}" | tr -d '\n') "${YQ}" \
  '.icon = {"base64data": strenv(ICON_DATA), "mediatype": "image/svg+xml"}' "${CATALOG_DIR}/package.yaml" \
  > "${release}/index.yaml"
{ echo '---'; "${YQ}" ea '.' "${CHANNELS}" "${bundles}"/*.yaml; } >> "${release}/index.yaml"
"${OPM}" validate "${release}"
echo "wrote ${release}/index.yaml"
