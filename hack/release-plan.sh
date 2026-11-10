#!/usr/bin/env bash
# Decides what a push to main publishes. catalog/channels.yaml is the only source of truth, and one pull
# request releases one version: the highest version it lists.
#
# - A push that does not change catalog/ publishes nothing.
# - When the highest listed version's bundle is not published, its operator, bundle and catalog images
#   are built and published. Every other listed bundle must be published already: rendering the catalog
#   pulls them, so a missing one fails the release.
# - Otherwise (e.g. a published version promoted to another channel), only a new catalog is published.
#
# Catalogs are tagged v<version>-<commit sha7> and latest, plus v<version> for a newly released version.
#
# Environment: CHANGED_FILES (newline-separated paths), BEFORE_UNKNOWN (true when the previous commit is
# unknown, e.g. the first push), CHANNELS, BUNDLE_REPO, SHA (the commit), IMAGE_INSPECT (optional; default
# `docker manifest inspect`), YQ.
# Output: publish=, build=, version=, catalog_tags= lines for $GITHUB_OUTPUT; the reason goes to stderr.
set -euo pipefail

: "${CHANNELS:?}" "${BUNDLE_REPO:?}" "${SHA:?}"
YQ=${YQ:-yq}
PACKAGE=sops-operator

decide() { # decide PUBLISH BUILD VERSION CATALOG_TAGS REASON
  echo "publish=$1"; echo "build=$2"; echo "version=$3"; echo "catalog_tags=$4"; echo "$5" >&2; exit 0
}

if [ "${BEFORE_UNKNOWN:-false}" != true ] && ! grep -q '^catalog/' <<<"${CHANGED_FILES:-}"; then
  decide false false "" "" "catalog/ did not change: nothing to publish"
fi

version=$("${YQ}" ea 'select(.schema == "olm.channel") | .entries[].name' "${CHANNELS}" | grep -v '^---$' \
  | sed "s/^${PACKAGE}\.v//" | sort -uV | tail -n1)
[ -n "${version}" ] || { echo "${CHANNELS} lists no versions" >&2; exit 1; }
commit_tag="v${version}-${SHA:0:7}"

# Only "manifest unknown" means unpublished; any other registry error stops the release.
ref="${BUNDLE_REPO}:v${version}"
if err=$(if [ -n "${IMAGE_INSPECT:-}" ]; then "${IMAGE_INSPECT}" "${ref}"; else docker manifest inspect "${ref}"; fi \
  2>&1 >/dev/null); then
  decide true false "${version}" "${commit_tag} latest" "v${version} is published: publishing a new catalog only"
fi
if ! grep -qiE 'manifest unknown|not found|name unknown' <<<"${err}"; then
  echo "cannot tell whether ${ref} is published: ${err}" >&2
  exit 1
fi
decide true true "${version}" "v${version} ${commit_tag} latest" "v${version} is not published yet: building and publishing it"
