#!/usr/bin/env bash
# Writes the catalog metadata of a pull request build to OUT_DIR (make catalog-render): the files of
# SOURCE_DIR (catalog/), with the version TAG replaced by the build's version VERSION (TAG-PR_TAG) wherever it
# is referenced, so the pull request catalog has the same graph and upgrade path as the release of TAG.
# SOURCE_DIR is never changed.
#
# Environment: SOURCE_DIR, OUT_DIR, PACKAGE, TAG, VERSION, YQ.
set -euo pipefail

: "${SOURCE_DIR:?}" "${OUT_DIR:?}" "${PACKAGE:?}" "${TAG:?}" "${VERSION:?}"
YQ=${YQ:-yq}
release="${PACKAGE}.v${TAG}"

if ! "${YQ}" ea 'select(.schema == "olm.channel") | .entries[].name' "${SOURCE_DIR}/channels.yaml" | grep -qx "${release}"; then
  echo "${SOURCE_DIR}/channels.yaml does not list ${release}" >&2
  exit 1
fi
rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"
for file in package.yaml channels.yaml; do
  RELEASE="${release}" BUILD="${PACKAGE}.v${VERSION}" "${YQ}" \
    '(.. | select(tag == "!!str" and . == strenv(RELEASE))) = strenv(BUILD)' "${SOURCE_DIR}/${file}" > "${OUT_DIR}/${file}"
done
echo "wrote ${OUT_DIR}: ${release} replaced by ${PACKAGE}.v${VERSION}"
