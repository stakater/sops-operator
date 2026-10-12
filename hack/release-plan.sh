#!/usr/bin/env bash
# Decides what a push to main publishes. catalog/channels.yaml is the only source of truth, so version
# rollout is a reviewed change to it:
#
# - A push that does not change catalog/ publishes nothing.
# - The one version listed in a channel whose bundle is not published yet is built and published
#   (operator and bundle images), and the catalog is rendered and published as catalog:v<version>.
# - When every listed version is published (e.g. a promotion from alpha to stable), nothing is rebuilt;
#   the catalog is republished, tagged with the highest listed version. A published version is never
#   overwritten.
# - More than one unpublished version, or a registry that cannot be read, fails the release.
#
# Environment: CHANGED_FILES (newline-separated paths), BEFORE_UNKNOWN (true when the previous commit is
# unknown, e.g. the first push), CHANNELS, BUNDLE_REPO, IMAGE_INSPECT (optional; default
# `docker manifest inspect`), YQ.
# Output: publish=, build=, version= lines for $GITHUB_OUTPUT; the reason goes to stderr.
set -euo pipefail

: "${CHANNELS:?}" "${BUNDLE_REPO:?}"
YQ=${YQ:-yq}
PACKAGE=sops-operator

inspect() {
  if [ -n "${IMAGE_INSPECT:-}" ]; then "${IMAGE_INSPECT}" "$1"; else docker manifest inspect "$1"; fi
}
decide() { echo "publish=$1"; echo "build=$2"; echo "version=$3"; echo "$4" >&2; exit 0; }

if [ "${BEFORE_UNKNOWN:-false}" != true ] && ! grep -q '^catalog/' <<<"${CHANGED_FILES:-}"; then
  decide false false "" "catalog/ did not change: nothing to publish"
fi

versions=$("${YQ}" ea 'select(.schema == "olm.channel") | .entries[].name' "${CHANNELS}" \
  | grep -v '^---$' | sed "s/^${PACKAGE}\.v//" | sort -uV)
[ -n "${versions}" ] || { echo "${CHANNELS} lists no versions" >&2; exit 1; }

# Fail loud: only "manifest unknown" means unpublished; any other error stops the release.
unpublished=()
for v in ${versions}; do
  if err=$(inspect "${BUNDLE_REPO}:v${v}" 2>&1 >/dev/null); then
    continue
  fi
  if ! grep -qiE 'manifest unknown|not found|name unknown' <<<"${err}"; then
    echo "cannot tell whether ${BUNDLE_REPO}:v${v} is published: ${err}" >&2
    exit 1
  fi
  unpublished+=("${v}")
done

case ${#unpublished[@]} in
  0) decide true false "$(tail -n1 <<<"${versions}")" "every listed version is published: republishing the catalog only" ;;
  1) decide true true "${unpublished[0]}" "v${unpublished[0]} is not published yet: building and publishing it" ;;
  *) echo "more than one listed version is unpublished (${unpublished[*]}): release them one at a time" >&2; exit 1 ;;
esac
