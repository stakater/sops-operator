#!/usr/bin/env bash
# Tests scripts/encrypt.sh with a throwaway key in a throwaway GitOps directory.
#
# Usage: scripts/test.sh   (or make test-scripts)
#
# Needs: sops, yq, age-keygen (v1.3 or later)
set -euo pipefail

SCRIPTS="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
unset SOPS_AGE_KEY_FILE SOPS_AGE_KEY
FAILED=0

# check "<what should happen>" <command...>: prints ok when the command succeeds, FAIL otherwise.
check() {
  local what="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "ok   $what"
  else
    echo "FAIL $what"
    FAILED=1
  fi
}

# fails <command...>: succeeds when the command fails.
fails() {
  ! "$@"
}

# decrypts <file> <yq check>: the file decrypts with the test key and the check holds.
decrypts() {
  SOPS_AGE_KEY_FILE="$WORK/tenant.key" sops decrypt "$1" | yq -e "$2"
}

# A GitOps directory: .sops.yaml at the top, with a rule for one environment only.
age-keygen -pq -o "$WORK/tenant.key" 2>/dev/null
GITOPS="$WORK/gitops"
mkdir -p "$GITOPS/environments/stage/team-a" "$GITOPS/environments/prod"
cat >"$GITOPS/.sops.yaml" <<EOF
creation_rules:
  - path_regex: ^environments/stage/.*\.sops\.ya?ml$
    encrypted_regex: ^(data|stringData|scope)$
    mac_only_encrypted: true
    age: $(age-keygen -y "$WORK/tenant.key")
EOF
SECRET="$GITOPS/environments/stage/team-a/db.sops.yaml"
cat >"$SECRET" <<EOF
apiVersion: sops.stakater.com/v1alpha1
kind: SopsSecret
metadata:
  name: db
  namespace: team-a-stage
spec:
  tenantRef:
    name: team-a
    namespace: team-a-system
  stringData:
    username: "app"
    password: "throwaway"
EOF
EXPLICIT="$GITOPS/environments/stage/team-a/explicit.sops.yaml"
yq '.spec.scope = "other/db"' "$SECRET" >"$EXPLICIT"
OUTSIDE="$GITOPS/environments/prod/db.sops.yaml"
cp "$SECRET" "$OUTSIDE"
CONFIGMAP="$GITOPS/environments/stage/team-a/settings.yaml"
printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n' >"$CONFIGMAP"

# Run from somewhere else than the GitOps directory, as a developer might.
cd "$WORK"

echo "# encrypt.sh"
check "encrypts the file" "$SCRIPTS/encrypt.sh" "$SECRET"
check "encrypts for the key in the .sops.yaml above it" decrypts "$SECRET" '.spec.stringData.password == "throwaway"'
check "sets the scope from metadata" decrypts "$SECRET" '.spec.scope == "team-a-stage/db"'
check "sorts the keys" decrypts "$SECRET" '(.spec.stringData | keys | join(",")) == "password,username"'
check "leaves tenantRef readable" yq -e '.spec.tenantRef.name == "team-a"' "$SECRET"
check "keeps a scope written in the file" "$SCRIPTS/encrypt.sh" "$EXPLICIT"
check "keeps a scope written in the file (decrypted)" decrypts "$EXPLICIT" '.spec.scope == "other/db"'
cp "$SECRET" "$WORK/db.before"
check "refuses an encrypted file" fails "$SCRIPTS/encrypt.sh" "$SECRET"
check "leaves the encrypted file unchanged" cmp "$WORK/db.before" "$SECRET"
check "refuses a file that is not a SopsSecret" fails "$SCRIPTS/encrypt.sh" "$CONFIGMAP"
check "refuses a file that does not exist" fails "$SCRIPTS/encrypt.sh" "$GITOPS/missing.sops.yaml"
check "refuses a file no .sops.yaml rule covers" fails "$SCRIPTS/encrypt.sh" "$OUTSIDE"
check "leaves that file unencrypted" yq -e 'has("sops") | not' "$OUTSIDE"

if [ "$FAILED" = 1 ]; then
  echo "Some tests failed"
  exit 1
fi
echo "All tests passed"
