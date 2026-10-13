#!/usr/bin/env bash
# Renders the file-based catalog from catalog/channels.yaml (Hestia's promotion flow).
#
# channels.yaml is the upgrade graph: a version is released by adding sops-operator.vX.Y.Z to a
# channel in a reviewed change. Every bundle any channel lists is rendered, so older versions stay
# installable. When VERSION is listed in no channel, nothing is released and no index is written.
#
# Environment: CATALOG_DIR, CHANNELS (channels file; default $CATALOG_DIR/channels.yaml), VERSION, BUNDLE_REPO (published bundles, tagged vX.Y.Z), BUNDLE_IMG
# (bundle for VERSION; default $BUNDLE_REPO:v$VERSION), ICON, OPM, YQ, INSECURE_REGISTRIES (space-separated hosts reached over plain HTTP, e.g. a local test registry), OPM_RENDER_FLAGS (e.g. --use-http).
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
tmp_dirs=()
trap 'rm -rf ${tmp_dirs[@]+"${tmp_dirs[@]}"}' EXIT
if [ ! -f "${HOME}/.config/containers/policy.json" ] && [ ! -f /etc/containers/policy.json ]; then
  opm_home=$(mktemp -d)
  tmp_dirs+=("${opm_home}")
  mkdir -p "${opm_home}/.config/containers"
  echo '{"default":[{"type":"insecureAcceptAnything"}]}' > "${opm_home}/.config/containers/policy.json"
  opm_env=(HOME="${opm_home}")
  docker_auth="${DOCKER_CONFIG:-${HOME}/.docker}/config.json"
  [ -f "${docker_auth}" ] && opm_env+=(REGISTRY_AUTH_FILE="${REGISTRY_AUTH_FILE:-${docker_auth}}")
fi

# Registries named in INSECURE_REGISTRIES (e.g. a local test registry) are reached over plain HTTP;
# every other registry keeps TLS, unlike opm's --use-http, which drops TLS for all of them.
if [ -n "${INSECURE_REGISTRIES:-}" ]; then
  conf_dir=$(mktemp -d)
  tmp_dirs+=("${conf_dir}")
  for host in ${INSECURE_REGISTRIES}; do
    printf '[[registry]]\nlocation = "%s"\ninsecure = true\n\n' "${host}" >> "${conf_dir}/registries.conf"
  done
  opm_env+=(CONTAINERS_REGISTRIES_CONF="${conf_dir}/registries.conf")
fi

for entry in ${entries}; do
  version=${entry#"${PACKAGE}.v"}
  ref="${BUNDLE_REPO}:v${version}"
  [ "${version}" = "${VERSION}" ] && ref="${BUNDLE_IMG}"
  # One file per bundle: yq joins them as separate documents whether or not opm starts its
  # output with a separator; concatenated output would merge bundles or leave empty documents.
  # shellcheck disable=SC2086 # OPM_RENDER_FLAGS holds separate flags
  env ${opm_env[@]+"${opm_env[@]}"} "${OPM}" render "${ref}" --output=yaml ${OPM_RENDER_FLAGS:-} > "${bundles}/${entry}.yaml"
  echo "rendered ${ref}"
done

mkdir -p "${release}"
ICON_DATA=$(base64 < "${ICON}" | tr -d '\n') "${YQ}" \
  '.icon = {"base64data": strenv(ICON_DATA), "mediatype": "image/svg+xml"}' "${CATALOG_DIR}/package.yaml" \
  > "${release}/index.yaml"
{ echo '---'; "${YQ}" ea '.' "${CHANNELS}" "${bundles}"/*.yaml; } >> "${release}/index.yaml"
"${OPM}" validate "${release}"
echo "wrote ${release}/index.yaml"
