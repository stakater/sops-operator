#!/usr/bin/env bash
# Prints the next version to release: the highest version CHANNELS lists, when its bundle is not published
# yet. Prints nothing when it is published, so there is nothing to build and a published version is never
# overwritten. One pull request releases one version; every other listed bundle must be published, which
# rendering the catalog checks.
#
# Environment: CHANNELS, BUNDLE_REPO (published bundles, tagged vX.Y.Z), YQ, IMAGE_INSPECT (optional;
# default `docker manifest inspect`).
set -euo pipefail

: "${CHANNELS:?}" "${BUNDLE_REPO:?}"
YQ=${YQ:-yq}
PACKAGE=sops-operator

version=$("${YQ}" ea 'select(.schema == "olm.channel") | .entries[].name' "${CHANNELS}" | grep -v '^---$' \
  | sed "s/^${PACKAGE}\.v//" | sort -uV | tail -n1)
[ -n "${version}" ] || { echo "${CHANNELS} lists no versions" >&2; exit 1; }

# Only "manifest unknown" means unpublished; any other registry error stops, so an outage is never
# taken for an unpublished version.
ref="${BUNDLE_REPO}:v${version}"
if err=$(if [ -n "${IMAGE_INSPECT:-}" ]; then "${IMAGE_INSPECT}" "${ref}"; else docker manifest inspect "${ref}"; fi \
  2>&1 >/dev/null); then
  exit 0
fi
if ! grep -qiE 'manifest unknown|not found|name unknown' <<<"${err}"; then
  echo "cannot tell whether ${ref} is published: ${err}" >&2
  exit 1
fi
echo "${version}"
