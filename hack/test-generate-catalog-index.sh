#!/usr/bin/env bash
# Tests hack/generate-catalog-index.sh with a fake opm. Run with `make test-catalog`.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
YQ=$(realpath "${YQ:-${root}/bin/yq}")
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

# Fake opm: `render <ref>` prints a bundle named after the ref's tag and fails for tags containing
# "missing"; `validate` fails on documents without a schema.
cat > "${work}/opm" <<'OPM'
#!/usr/bin/env bash
case "$1" in
  render)
    # Like the real opm (containers/image), refuse to pull without a signature policy.
    [ -f "${HOME}/.config/containers/policy.json" ] || [ -f /etc/containers/policy.json ] \
      || { echo "no policy.json file found" >&2; exit 1; }
    tag=${2##*:}
    [[ "$tag" == *missing* ]] && { echo "unable to pull $2" >&2; exit 1; }
    # Like the real opm, the output starts with a document separator.
    printf -- '---\nschema: olm.bundle\npackage: sops-operator\nname: sops-operator.%s\nimage: %s\n' "$tag" "$2" ;;
  validate) # Like the real opm, reject documents without a schema (e.g. empty documents).
    f="$2/index.yaml"
    [ "$(( $(grep -c '^---$' "$f") + 1 ))" -eq "$(grep -c '^schema:' "$f")" ] \
      || { echo "object '' is missing root schema field" >&2; exit 1; } ;;
  *) exit 2 ;;
esac
OPM
chmod +x "${work}/opm"

fails=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fails=$((fails+1)); fi; }

catalog() { # catalog <dir> <channel entries...>: write package.yaml and channels.yaml
  local dir=$1; shift
  mkdir -p "${dir}"
  printf 'schema: olm.package\nname: sops-operator\ndefaultChannel: alpha\n' > "${dir}/package.yaml"
  { printf 'schema: olm.channel\npackage: sops-operator\nname: alpha\nentries:\n'
    for e in "$@"; do printf '  - name: %s\n' "$e"; done; } > "${dir}/channels.yaml"
}
generate() { # generate <dir> <version> [bundle img]
  CATALOG_DIR="$1" VERSION="$2" BUNDLE_IMG="${3:-}" BUNDLE_REPO=ghcr.io/stakater/sops-operator-bundle \
    OPM="${work}/opm" YQ="${YQ}" ICON="${root}/operator-icon.svg" "${root}/hack/generate-catalog-index.sh"
}

catalog "${work}/a" sops-operator.v0.0.1 sops-operator.v0.0.2
index="${work}/a/release/index.yaml"
check "shall build a valid catalog when the version is promoted" \
  'generate "${work}/a" 0.0.2 localhost:5001/sops-operator-bundle:e2e > /dev/null && [ -f "${index}" ]'
check "shall render the published bundle of older versions" \
  '[ "$("${YQ}" ea "select(.name == \"sops-operator.v0.0.1\") | .image" "${index}" 2>/dev/null)" = ghcr.io/stakater/sops-operator-bundle:v0.0.1 ]'
check "shall render BUNDLE_IMG for the version being built" \
  '"${YQ}" ea "select(.schema == \"olm.bundle\") | .image" "${index}" 2>/dev/null | grep -qx localhost:5001/sops-operator-bundle:e2e'
check "shall stamp the icon into the package" \
  '[ "$("${YQ}" ea "select(.schema == \"olm.package\") | .icon.mediatype" "${index}" 2>/dev/null)" = image/svg+xml ]'

catalog "${work}/b" sops-operator.v0.0.1
mkdir -p "${work}/b/release" && echo stale > "${work}/b/release/index.yaml"
generate "${work}/b" 0.0.2 > /dev/null || true
check "shall not build a catalog for an unpromoted version" '[ ! -e "${work}/b/release/index.yaml" ]'

catalog "${work}/c" sops-operator.v0.0.1 sops-operator.vmissing
check "shall fail when a listed bundle cannot be rendered" '! generate "${work}/c" 0.0.1 > /dev/null 2>&1'

exit "${fails}"
