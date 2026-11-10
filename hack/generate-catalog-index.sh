#!/usr/bin/env bash
# Renders and validates the file-based catalog OUT_DIR/index.yaml (make catalog-render).
#
# SOURCE_DIR holds the catalog metadata: package.yaml and channels.yaml, the upgrade graph. Every version it
# lists is rendered from its published bundle, BUNDLE_REPO:v<version>, except VERSION, the version of this
# build, which is rendered from BUNDLE_IMG, or from the bundle directory BUNDLE_DIR when it is set (a bundle
# that is not published yet) and referenced as BUNDLE_IMG. opm validate checks the result, so a bundle that
# cannot be pulled or a broken graph fails.
#
# Environment: SOURCE_DIR, OUT_DIR, VERSION, BUNDLE_IMG, BUNDLE_DIR (optional), BUNDLE_REPO, PACKAGE, ICON,
# OPM, YQ.
set -euo pipefail

: "${SOURCE_DIR:?}" "${OUT_DIR:?}" "${VERSION:?}" "${BUNDLE_IMG:?}" "${BUNDLE_REPO:?}" "${PACKAGE:?}" "${ICON:?}"
OPM=${OPM:-opm}
YQ=${YQ:-yq}
bundles=$(mktemp -d)
trap 'rm -rf "${bundles}"' EXIT

entries=$("${YQ}" ea 'select(.schema == "olm.channel") | .entries[].name' "${SOURCE_DIR}/channels.yaml" \
  | grep -v '^---$' | sort -u)
if ! grep -qx "${PACKAGE}.v${VERSION}" <<<"${entries}"; then
  echo "${SOURCE_DIR}/channels.yaml does not list ${PACKAGE}.v${VERSION}" >&2
  exit 1
fi

# opm pulls through containers/image, which refuses to pull without a signature policy. When the
# system has none (e.g. macOS), give opm the default accept-all policy in a temporary HOME; an
# existing user or system policy is never overridden. Registry credentials are passed through.
opm_env=()
if [ ! -f "${HOME}/.config/containers/policy.json" ] && [ ! -f /etc/containers/policy.json ]; then
  opm_home=$(mktemp -d)
  trap 'rm -rf "${bundles}" "${opm_home}"' EXIT
  mkdir -p "${opm_home}/.config/containers"
  echo '{"default":[{"type":"insecureAcceptAnything"}]}' > "${opm_home}/.config/containers/policy.json"
  opm_env=(HOME="${opm_home}")
  docker_auth="${DOCKER_CONFIG:-${HOME}/.docker}/config.json"
  [ -f "${docker_auth}" ] && opm_env+=(REGISTRY_AUTH_FILE="${REGISTRY_AUTH_FILE:-${docker_auth}}")
fi
render() { env ${opm_env[@]+"${opm_env[@]}"} "${OPM}" render "$1" --output=yaml; }

# One file per bundle: yq joins them as separate documents whether or not opm starts its output with a
# separator; concatenated output would merge bundles or leave empty documents.
for entry in ${entries}; do
  version=${entry#"${PACKAGE}.v"}
  if [ "${version}" != "${VERSION}" ]; then
    render "${BUNDLE_REPO}:v${version}" > "${bundles}/${entry}.yaml"
    echo "rendered ${BUNDLE_REPO}:v${version}"
  elif [ -n "${BUNDLE_DIR:-}" ]; then
    # A directory renders without an image: reference it as BUNDLE_IMG, as a render of the image does.
    render "${BUNDLE_DIR}" | IMG="${BUNDLE_IMG}" "${YQ}" \
      '.image = strenv(IMG) | .relatedImages += [{"image": strenv(IMG), "name": ""}]' > "${bundles}/${entry}.yaml"
    echo "rendered ${BUNDLE_DIR} as ${BUNDLE_IMG}"
  else
    render "${BUNDLE_IMG}" > "${bundles}/${entry}.yaml"
    echo "rendered ${BUNDLE_IMG}"
  fi
done

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"
ICON_DATA=$(base64 < "${ICON}" | tr -d '\n') "${YQ}" \
  '.icon = {"base64data": strenv(ICON_DATA), "mediatype": "image/svg+xml"}' "${SOURCE_DIR}/package.yaml" \
  > "${OUT_DIR}/index.yaml"
{ echo '---'; "${YQ}" ea '.' "${SOURCE_DIR}/channels.yaml" "${bundles}"/*.yaml; } >> "${OUT_DIR}/index.yaml"
"${OPM}" validate "${OUT_DIR}"
echo "wrote and validated ${OUT_DIR}/index.yaml"
