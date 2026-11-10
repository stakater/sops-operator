#!/usr/bin/env bash
# Builds the bundle and catalog images of a pull request for the operator image OPERATOR_REF, and
# saves them with the operator image to OUT, so a job without a write token builds all three and a
# job that runs no pull-request code only pushes them.
#
# The bundle is the pre-release VERSION-PR_SUFFIX (e.g. 0.0.5-pr.19.257c50b): it never has the name or
# version of a release, sorts below VERSION, and tells pull requests apart. It points at OPERATOR_REF,
# and the catalog at BUNDLE_REF, the references the push job gives them. The catalog is rendered from
# catalog/channels.yaml like a release, with this bundle in place of VERSION, so it upgrades from the
# same version VERSION does; when channels.yaml does not list VERSION, it lists only this bundle. opm
# renders the bundle from a throwaway local registry, since BUNDLE_REF does not exist yet.
#
# Environment: OPERATOR_IMG (local operator image), OPERATOR_REF, BUNDLE_REF, OUT, REGISTRY_IMAGE,
# VERSION, PR_SUFFIX, OPERATOR_NAME, CATALOG_DIR, MAKE, YQ.
set -euo pipefail

: "${OPERATOR_IMG:?}" "${OPERATOR_REF:?}" "${BUNDLE_REF:?}" "${OUT:?}" "${REGISTRY_IMAGE:?}"
: "${VERSION:?}" "${PR_SUFFIX:?}" "${OPERATOR_NAME:?}" "${CATALOG_DIR:?}"
MAKE=${MAKE:-make}
YQ=${YQ:-yq}
pr_version="${VERSION}-${PR_SUFFIX}"
registry=localhost:5099
local_bundle="${registry}/${OPERATOR_NAME}-bundle:pr"

docker run -d --rm --name pr-images-registry -p 5099:5000 "${REGISTRY_IMAGE}" >/dev/null
trap 'docker rm -f pr-images-registry >/dev/null 2>&1 || true' EXIT

"${MAKE}" bundle VERSION="${pr_version}" IMG="${OPERATOR_REF}"
docker build -f bundle.Dockerfile -t "${local_bundle}" .
docker push "${local_bundle}"

channels=$(mktemp)
if grep -q "name: ${OPERATOR_NAME}.v${VERSION}$" "${CATALOG_DIR}/channels.yaml"; then
  RELEASE="${OPERATOR_NAME}.v${VERSION}" PR="${OPERATOR_NAME}.v${pr_version}" "${YQ}" \
    '(.. | select(tag == "!!str" and . == strenv(RELEASE))) = strenv(PR)' "${CATALOG_DIR}/channels.yaml" > "${channels}"
else
  printf 'schema: olm.channel\npackage: %s\nname: alpha\nentries:\n  - name: %s.v%s\n' \
    "${OPERATOR_NAME}" "${OPERATOR_NAME}" "${pr_version}" > "${channels}"
fi
"${MAKE}" catalog-render VERSION="${pr_version}" CATALOG_CHANNELS="${channels}" BUNDLE_IMG="${local_bundle}" \
  BUNDLE_IMG_RENDER_FLAGS=--use-http
sed -i.bak "s#${local_bundle}#${BUNDLE_REF}#g" "${CATALOG_DIR}/release/index.yaml"
rm -f "${CATALOG_DIR}/release/index.yaml.bak"
if grep -q "${registry}" "${CATALOG_DIR}/release/index.yaml"; then
  echo "the catalog still references the local registry ${registry}" >&2
  exit 1
fi
docker build -f catalog.Dockerfile -t "${OPERATOR_NAME}-catalog:pr" .
docker tag "${local_bundle}" "${OPERATOR_NAME}-bundle:pr"

mkdir -p "${OUT}"
docker save "${OPERATOR_IMG}" -o "${OUT}/operator.tar"
docker save "${OPERATOR_NAME}-bundle:pr" -o "${OUT}/bundle.tar"
docker save "${OPERATOR_NAME}-catalog:pr" -o "${OUT}/catalog.tar"
echo "saved the operator, bundle and catalog images to ${OUT}"
