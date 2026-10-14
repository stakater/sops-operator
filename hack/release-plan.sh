#!/usr/bin/env bash
# Decides what a push to main publishes. catalog/channels.yaml is the only source of truth, so version
# rollout is a reviewed change to it:
#
# - A push that does not change catalog/ publishes nothing.
# - The one version listed in a channel whose bundle is not published yet is built and published
#   (operator and bundle images) together with a new catalog.
# - When every listed version is published (e.g. a promotion from alpha to stable), nothing is rebuilt;
#   only a new catalog is published.
# - No existing tag is ever overwritten: a release that would rewrite an operator, bundle or catalog tag
#   fails. Every catalog publish is tagged v<highest listed version>-<commit sha7> and moves latest;
#   v<version> is added only for a newly released version.
# - More than one unpublished version, or a registry that cannot be read, fails the release.
#
# Environment: CHANGED_FILES (newline-separated paths), BEFORE_UNKNOWN (true when the previous commit is
# unknown, e.g. the first push), CHANNELS, OPERATOR_REPO, BUNDLE_REPO, CATALOG_REPO, SHA (the commit),
# IMAGE_INSPECT (optional; default `docker manifest inspect`), YQ.
# Output: publish=, build=, version=, catalog_tags= lines for $GITHUB_OUTPUT; the reason goes to stderr.
set -euo pipefail

: "${CHANNELS:?}" "${OPERATOR_REPO:?}" "${BUNDLE_REPO:?}" "${CATALOG_REPO:?}" "${SHA:?}"
YQ=${YQ:-yq}
PACKAGE=sops-operator

inspect() {
  if [ -n "${IMAGE_INSPECT:-}" ]; then "${IMAGE_INSPECT}" "$1"; else docker manifest inspect "$1"; fi
}

# exists REF: succeeds when REF is published, fails when it is not, and stops the release on any
# other registry error (fail loud: only "manifest unknown" means unpublished).
exists() {
  local err
  if err=$(inspect "$1" 2>&1 >/dev/null); then
    return 0
  fi
  if grep -qiE 'manifest unknown|not found|name unknown' <<<"${err}"; then
    return 1
  fi
  echo "cannot tell whether $1 is published: ${err}" >&2
  exit 1
}

decide() { # decide PUBLISH BUILD VERSION CATALOG_TAGS REASON
  echo "publish=$1"; echo "build=$2"; echo "version=$3"; echo "catalog_tags=$4"; echo "$5" >&2; exit 0
}

if [ "${BEFORE_UNKNOWN:-false}" != true ] && ! grep -q '^catalog/' <<<"${CHANGED_FILES:-}"; then
  decide false false "" "" "catalog/ did not change: nothing to publish"
fi

versions=$("${YQ}" ea 'select(.schema == "olm.channel") | .entries[].name' "${CHANNELS}" \
  | grep -v '^---$' | sed "s/^${PACKAGE}\.v//" | sort -uV)
[ -n "${versions}" ] || { echo "${CHANNELS} lists no versions" >&2; exit 1; }

unpublished=()
for v in ${versions}; do
  exists "${BUNDLE_REPO}:v${v}" || unpublished+=("${v}")
done
if [ ${#unpublished[@]} -gt 1 ]; then
  echo "more than one listed version is unpublished (${unpublished[*]}): release them one at a time" >&2
  exit 1
fi

highest=$(tail -n1 <<<"${versions}")
commit_tag="v${highest}-${SHA:0:7}"
if exists "${CATALOG_REPO}:${commit_tag}"; then
  echo "${CATALOG_REPO}:${commit_tag} already exists: this commit's catalog was published before" >&2
  exit 1
fi

if [ ${#unpublished[@]} -eq 0 ]; then
  decide true false "${highest}" "${commit_tag} latest" \
    "every listed version is published: publishing a new catalog only"
fi

v=${unpublished[0]}
for ref in "${OPERATOR_REPO}:v${v}" "${CATALOG_REPO}:v${v}"; do
  if exists "${ref}"; then
    echo "${ref} exists although bundle v${v} does not: an earlier release stopped partway; remove the" \
      "partial tags after checking them, or release a new version" >&2
    exit 1
  fi
done
decide true true "${v}" "v${v} ${commit_tag} latest" "v${v} is not published yet: building and publishing it"
