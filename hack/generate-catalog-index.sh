#!/usr/bin/env bash
# Renders the file-based catalog from catalog/channels.yaml (Hestia's promotion flow).
#
# channels.yaml is the upgrade graph: a version is released by adding sops-operator.vX.Y.Z to a
# channel in a reviewed change. Every bundle any channel lists is rendered, so older versions stay
# installable. When VERSION is listed in no channel, nothing is released and no index is written.
#
# Environment: CATALOG_DIR, VERSION, BUNDLE_REPO (published bundles, tagged vX.Y.Z), BUNDLE_IMG
# (bundle for VERSION; default $BUNDLE_REPO:v$VERSION), ICON, OPM, YQ, OPM_RENDER_FLAGS (e.g. --use-http).
set -euo pipefail

: "${CATALOG_DIR:?}" "${VERSION:?}" "${BUNDLE_REPO:?}" "${ICON:?}"
OPM=${OPM:-opm}
YQ=${YQ:-yq}
PACKAGE=sops-operator
BUNDLE_IMG=${BUNDLE_IMG:-${BUNDLE_REPO}:v${VERSION}}
release="${CATALOG_DIR}/release"
bundles="${CATALOG_DIR}/bundles"

rm -rf "${release}" "${bundles}"
mkdir -p "${bundles}"
entries=$("${YQ}" ea 'select(.schema == "olm.channel") | .entries[].name' "${CATALOG_DIR}/channels.yaml" \
  | grep -v '^---$' | sort -u)

if ! grep -qx "${PACKAGE}.v${VERSION}" <<<"${entries}"; then
  echo "${PACKAGE}.v${VERSION} is not listed in ${CATALOG_DIR}/channels.yaml: not promoted, no catalog built"
  exit 0
fi

for entry in ${entries}; do
  version=${entry#"${PACKAGE}.v"}
  ref="${BUNDLE_REPO}:v${version}"
  [ "${version}" = "${VERSION}" ] && ref="${BUNDLE_IMG}"
  # One file per bundle: yq joins them as separate documents whether or not opm starts its
  # output with a separator; concatenated output would merge bundles or leave empty documents.
  # shellcheck disable=SC2086 # OPM_RENDER_FLAGS holds separate flags
  "${OPM}" render "${ref}" --output=yaml ${OPM_RENDER_FLAGS:-} > "${bundles}/${entry}.yaml"
  echo "rendered ${ref}"
done

mkdir -p "${release}"
ICON_DATA=$(base64 < "${ICON}" | tr -d '\n') "${YQ}" \
  '.icon = {"base64data": strenv(ICON_DATA), "mediatype": "image/svg+xml"}' "${CATALOG_DIR}/package.yaml" \
  > "${release}/index.yaml"
{ echo '---'; "${YQ}" ea '.' "${CATALOG_DIR}/channels.yaml" "${bundles}"/*.yaml; } >> "${release}/index.yaml"
"${OPM}" validate "${release}"
echo "wrote ${release}/index.yaml"
