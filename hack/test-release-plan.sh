#!/usr/bin/env bash
# Tests hack/release-plan.sh with a fake registry. Run with `make test-release-plan`.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
YQ=$(realpath "${YQ:-${root}/bin/yq}")
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

# Fake image inspector. Published: operator, bundle and catalog v0.0.1, v0.0.9, v0.0.10; the catalog
# tag v0.0.1-abc1234 (an earlier publish of commit abc1234); the operator image v0.0.5 alone (a release
# that failed partway). Refs containing "broken" fail like an authorization error; everything else is
# missing, as ghcr.io reports it.
cat > "${work}/inspect" <<'FAKE'
#!/usr/bin/env bash
case "$1" in
  *broken*) echo 'Get "https://ghcr.io/v2/x/manifests/y": unauthorized' >&2; exit 1 ;;
  *:v0.0.1|*:v0.0.9|*:v0.0.10|*-catalog:v0.0.1-abc1234|*/sops-operator:v0.0.5) echo '{"schemaVersion":2}' ;;
  *) echo "manifest unknown" >&2; exit 1 ;;
esac
FAKE
chmod +x "${work}/inspect"

fails=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }
channels() { # channels <entries...>: one alpha channel
  { printf 'schema: olm.channel\npackage: sops-operator\nname: alpha\nentries:\n'
    for e in "$@"; do printf '  - name: %s\n' "$e"; done; } > "${work}/channels.yaml"
}
plan() { # plan CHANGED_FILES [BEFORE_UNKNOWN] [BUNDLE_REPO] [SHA]
  CHANGED_FILES="$1" BEFORE_UNKNOWN="${2:-false}" BUNDLE_REPO="${3:-ghcr.io/stakater/sops-operator-bundle}" \
    SHA="${4:-fff0000aaaabbbb}" OPERATOR_REPO=ghcr.io/stakater/sops-operator \
    CATALOG_REPO=ghcr.io/stakater/sops-operator-catalog \
    CHANNELS="${work}/channels.yaml" IMAGE_INSPECT="${work}/inspect" YQ="${YQ}" "${root}/hack/release-plan.sh"
}
has() { grep -qx "$1" <<<"${out}"; }

channels sops-operator.v0.0.1 sops-operator.v0.0.2
out=$(plan $'internal/controller/x.go\nMakefile' 2>/dev/null || true)
check "shall publish nothing when catalog/ did not change" 'has publish=false'

out=$(plan 'catalog/channels.yaml' 2>/dev/null || true)
check "shall build the one listed version that is not published" \
  'has publish=true && has build=true && has version=0.0.2'
check "shall tag a new version's catalog with the version, the commit and latest" \
  'has "catalog_tags=v0.0.2 v0.0.2-fff0000 latest"'

channels sops-operator.v0.0.1
printf -- '---\nschema: olm.channel\npackage: sops-operator\nname: stable\nentries:\n  - name: sops-operator.v0.0.1\n' >> "${work}/channels.yaml"
out=$(plan 'catalog/channels.yaml' 2>/dev/null || true)
check "shall republish only the catalog when every listed version is published" \
  'has publish=true && has build=false && has version=0.0.1'
check "shall give a promoted catalog a new commit tag and latest, never an existing version tag" \
  'has "catalog_tags=v0.0.1-fff0000 latest"'
check "shall fail when this commit's catalog tag already exists" \
  '! plan catalog/channels.yaml false ghcr.io/stakater/sops-operator-bundle abc1234ffff > /dev/null 2>&1'

channels sops-operator.v0.0.9 sops-operator.v0.0.10
out=$(plan 'catalog/channels.yaml' 2>/dev/null || true)
check "shall tag the catalog with the highest listed version" 'has version=0.0.10'

channels sops-operator.v0.0.1 sops-operator.v0.0.5
check "shall fail when an image of an unpublished version already exists" '! plan catalog/channels.yaml > /dev/null 2>&1'

channels sops-operator.v0.0.1 sops-operator.v0.0.2 sops-operator.v0.0.3
check "shall fail when more than one listed version is unpublished" '! plan catalog/channels.yaml > /dev/null 2>&1'

channels sops-operator.v0.0.1 sops-operator.v0.0.2
out=$(plan 'internal/x.go' true 2>/dev/null || true)
check "shall treat an unknown previous commit as a change" 'has publish=true'

# One listed version, so only the registry error can fail the plan.
channels sops-operator.v0.0.1
check "shall fail when the registry cannot be read" \
  '! plan catalog/channels.yaml false ghcr.io/stakater/broken-bundle > /dev/null 2>&1'

exit "${fails}"
