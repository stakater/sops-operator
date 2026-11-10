#!/usr/bin/env bash
# Tests scripts/encrypt.sh and scripts/rotate.sh with a throwaway key in a throwaway GitOps directory.
#
# Usage: scripts/test.sh   (or make test-scripts)
#
# Needs: sops, yq, age-keygen (v1.3 or later)
set -euo pipefail

SCRIPTS="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
unset SOPS_AGE_KEY_FILE SOPS_AGE_KEY
mkdir -p "$WORK/bin"
export PATH="$WORK/bin:$PATH"
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

# fails_with <text> <command...>: succeeds when the command fails with text in its output.
fails_with() {
  local text="$1" output
  shift
  if output="$("$@" 2>&1)"; then
    return 1
  fi
  grep -qF -- "$text" <<<"$output"
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

echo "# rotate.sh"

age-keygen -pq -o "$WORK/new.key" 2>/dev/null
NEW="$(age-keygen -y "$WORK/new.key")"
OLD="$(age-keygen -y "$WORK/tenant.key")"
age-keygen -pq -o "$WORK/breakglass.key" 2>/dev/null
BREAKGLASS="$(age-keygen -y "$WORK/breakglass.key")"

ROT="$WORK/rot"
mkdir -p "$ROT/team-a" "$WORK/cluster"
cat >"$ROT/.sops.yaml" <<EOF
creation_rules:
  - path_regex: \.sops\.ya?ml$
    encrypted_regex: ^(data|stringData|scope)$
    mac_only_encrypted: true
    age: $OLD,$BREAKGLASS
EOF
cat >"$ROT/team-a/db.sops.yaml" <<EOF
# kept comment
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
    password: "throwaway"
EOF
"$SCRIPTS/encrypt.sh" "$ROT/team-a/db.sops.yaml" >/dev/null
cp "$ROT/team-a/db.sops.yaml" "$ROT/team-a/with-new.sops.yaml"
yq -i ".creation_rules[0].age = \"$OLD,$BREAKGLASS,$NEW\"" "$ROT/.sops.yaml"
(cd "$ROT/team-a" && SOPS_AGE_KEY_FILE="$WORK/tenant.key" sops updatekeys -y with-new.sops.yaml >/dev/null 2>&1)
yq -i ".creation_rules[0].age = \"$OLD,$BREAKGLASS\"" "$ROT/.sops.yaml"
R="$NEW" yq -o json '.sops.age[] | select(.recipient == strenv(R))' "$ROT/team-a/with-new.sops.yaml" >"$WORK/entry.json"
rm "$ROT/team-a/with-new.sops.yaml"

yq -i '.creation_rules += [{"path_regex": "^kms-only/", "kms": "arn:aws:kms:x"}]' "$ROT/.sops.yaml"
yq '.creation_rules[1]' "$ROT/.sops.yaml" >"$WORK/kms-rule.before"
kms_rule_unchanged() {
  yq '.creation_rules[1]' "$ROT/.sops.yaml" | cmp - "$WORK/kms-rule.before"
}
mkdir -p "$ROT/lists"
printf 'creation_rules:\n  - path_regex: .*\n    age:\n      - %s\n      - %s\n' "$OLD" "$BREAKGLASS" >"$ROT/lists/.sops.yaml"
mkdir -p "$ROT/folded"
printf 'creation_rules:\n  - path_regex: .*\n    age: >-\n      %s,\n      %s\n' "$BREAKGLASS" "$OLD" >"$ROT/folded/.sops.yaml"
mkdir -p "$ROT/other-tenant"
printf 'creation_rules:\n  - path_regex: .*\n    age: %s\n' "$BREAKGLASS" >"$ROT/other-tenant/.sops.yaml"
cp "$ROT/other-tenant/.sops.yaml" "$WORK/other-tenant-sops.before"

cat >"$ROT/tenant.yaml" <<EOF
apiVersion: sops.stakater.com/v1alpha1
kind: SopsTenant
metadata:
  name: team-a
  namespace: team-a-system
EOF
TENANT_IN_CLUSTER="$WORK/cluster/sopstenant-team-a-system-team-a.json"
tenant_status() {
  yq -n -o json "$1" >"$TENANT_IN_CLUSTER"
}
ROTATION_IN_PROGRESS=".status.publicKey = \"$NEW\" | .status.rotation.phase = \"InProgress\" |
  .status.rotation.previousPublicKey = \"$OLD\""
ROTATION_COMPLETED=".status.publicKey = \"$NEW\" | .status.lastRotation.previousPublicKey = \"$OLD\""
tenant_status "$ROTATION_IN_PROGRESS"
ENTRY="$(cat "$WORK/entry.json")" yq -o json '.metadata.generation = 2 | .status.observedGeneration = 2 |
  .status.rotation.newRecipient = env(ENTRY) | .status.rotation.fromGeneration = 2' \
  "$ROT/team-a/db.sops.yaml" >"$WORK/cluster/sopssecret-team-a-stage-db.json"
DB="$(cat "$WORK/cluster/sopssecret-team-a-stage-db.json")" yq -n -o json '.items = [env(DB)]' \
  >"$WORK/cluster/sopssecrets-team-a-stage.json"

cat >"$WORK/bin/oc" <<'EOF'
#!/usr/bin/env bash
if [ "$3" = "-n" ]; then file="$FAKE_CLUSTER/$2-$4.json"; else file="$FAKE_CLUSTER/$2-$5-$3.json"; fi
if [ -f "$file" ]; then cat "$file"; else echo "Error from server (NotFound)" >&2; exit 1; fi
EOF
chmod +x "$WORK/bin/oc"
export FAKE_CLUSTER="$WORK/cluster"

sopssecret() {
  cat <<EOF
apiVersion: sops.stakater.com/v1alpha1
kind: SopsSecret
metadata:
  name: $2
  namespace: $1-stage
spec:
  tenantRef:
    name: $1
    namespace: $1-system
  stringData:
    password: "throwaway"
EOF
}
mkdir -p "$ROT/team-b" "$WORK/untouched"
sopssecret team-b db >"$ROT/team-b/db.sops.yaml"
"$SCRIPTS/encrypt.sh" "$ROT/team-b/db.sops.yaml" >/dev/null
sopssecret team-a plain >"$ROT/team-a/plain.yaml"
printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n' >"$ROT/team-a/settings.yaml"
cp "$ROT/team-b/db.sops.yaml" "$ROT/team-a/plain.yaml" "$ROT/team-a/settings.yaml" "$WORK/untouched/"
untouched() {
  cmp "$WORK/untouched/db.sops.yaml" "$ROT/team-b/db.sops.yaml" &&
    cmp "$WORK/untouched/plain.yaml" "$ROT/team-a/plain.yaml" &&
    cmp "$WORK/untouched/settings.yaml" "$ROT/team-a/settings.yaml" &&
    cmp "$WORK/other-tenant-sops.before" "$ROT/other-tenant/.sops.yaml"
}

cp -R "$ROT" "$WORK/rot.before"
tenant_status ".status.publicKey = \"$OLD\" | .status.rotation.phase = \"WaitingForKey\" |
  .status.rotation.previousPublicKey = \"$OLD\""
check "tells to wait while the tenant waits for its new key" \
  fails_with "waiting for its new key" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "changes no file while the tenant waits for its new key" diff -r "$WORK/rot.before" "$ROT"
tenant_status ".status.publicKey = \"$NEW\" | .status.rotation.phase = \"InProgress\""
check "stops when the tenant does not report its old key" \
  fails_with "does not report its new and old key" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "changes no file when the tenant does not report its old key" diff -r "$WORK/rot.before" "$ROT"
tenant_status ".status.publicKey = \"$OLD\""
check "stops when the tenant has no rotation" \
  fails_with "no key rotation in progress or completed" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "changes no file when the tenant has no rotation" diff -r "$WORK/rot.before" "$ROT"
tenant_status "$ROTATION_IN_PROGRESS"

mv "$WORK/cluster/sopssecret-team-a-stage-db.json" "$WORK/db.cluster.json"
check "stops when a file has no SopsSecret in the cluster" \
  fails_with "team-a-stage/db is not in the cluster" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "changes no file when a file has no SopsSecret in the cluster" diff -r "$WORK/rot.before" "$ROT"
mv "$WORK/db.cluster.json" "$WORK/cluster/sopssecret-team-a-stage-db.json"
mkdir -p "$WORK/empty"
check "stops when the directory has no files of the tenant" fails "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$WORK/empty"

cp "$WORK/cluster/sopssecret-team-a-stage-db.json" "$WORK/db.cluster.json"
stale() {
  yq -i -o json "$1" "$WORK/cluster/sopssecret-team-a-stage-db.json"
}
restore_cluster() {
  cp "$WORK/db.cluster.json" "$WORK/cluster/sopssecret-team-a-stage-db.json"
}
stale '.status.rotation.fromGeneration = 1'
check "stops when the entry was made for another generation" \
  fails_with "has not prepared the new key" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "changes no file when the entry was made for another generation" diff -r "$WORK/rot.before" "$ROT"
restore_cluster
stale '.status.observedGeneration = 1'
check "stops when the operator has not seen the SopsSecret's generation" \
  fails_with "has not prepared the new key" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "changes no file when the operator has not seen the generation" diff -r "$WORK/rot.before" "$ROT"
restore_cluster
stale '.sops.mac = "ENC[other]"'
check "stops when a file differs from its SopsSecret in the cluster" \
  fails_with "differs from SopsSecret team-a-stage/db" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "changes no file when a file differs from the cluster" diff -r "$WORK/rot.before" "$ROT"
restore_cluster
stale '.status.rotation.newRecipient.recipient = "age1pq1other"'
check "stops when the cluster's entry is for another key than the tenant's new key" \
  fails_with "has not prepared the new key" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "changes no file when the cluster's entry is for another key" diff -r "$WORK/rot.before" "$ROT"
restore_cluster
stale 'del(.status.rotation)'
check "stops when the SopsSecret offers no entry" \
  fails_with "has not prepared the new key" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "changes no file when the SopsSecret offers no entry" diff -r "$WORK/rot.before" "$ROT"
restore_cluster

mkdir -p "$ROT/team-a/zz/deep"
sopssecret team-a cache >"$ROT/team-a/zz/deep/cache.sops.yaml"
"$SCRIPTS/encrypt.sh" "$ROT/team-a/zz/deep/cache.sops.yaml" >/dev/null
cp -R "$ROT" "$WORK/rot.two"
check "stops when one of two files has no SopsSecret in the cluster" \
  fails_with "team-a-stage/cache is not in the cluster" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "changes no file when one of two files fails" diff -r "$WORK/rot.two" "$ROT"
rm -r "$ROT/team-a/zz"

cp -R "$WORK/rot.before" "$WORK/sub"
check "adds the new key to the files of a subdirectory" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$WORK/sub/team-a"
check "adds the new key to the .sops.yaml above the subdirectory" \
  yq -e ".creation_rules[0].age | contains(\"$NEW\")" "$WORK/sub/.sops.yaml"
check "leaves .sops.yaml files beside the subdirectory unchanged" \
  cmp "$WORK/rot.before/lists/.sops.yaml" "$WORK/sub/lists/.sops.yaml"

check "adds the new key to the tenant's files" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "the file decrypts with the new key" \
  env SOPS_AGE_KEY_FILE="$WORK/new.key" sops decrypt "$ROT/team-a/db.sops.yaml"
check "the file still decrypts with the old key" \
  env SOPS_AGE_KEY_FILE="$WORK/tenant.key" sops decrypt "$ROT/team-a/db.sops.yaml"
check "keeps the file's comments" grep -q '^# kept comment' "$ROT/team-a/db.sops.yaml"
check "adds the new key to .sops.yaml" yq -e ".creation_rules[0].age | contains(\"$NEW\")" "$ROT/.sops.yaml"
check "keeps other recipients" yq -e ".creation_rules[0].age | contains(\"$BREAKGLASS\")" "$ROT/.sops.yaml"
check "adds the new key to a YAML list of keys once" \
  yq -e ".creation_rules[0].age | join(\",\") == \"$OLD,$BREAKGLASS,$NEW\"" "$ROT/lists/.sops.yaml"
check "adds the new key to folded keys in their style" \
  yq -e ".creation_rules[0].age == \"$BREAKGLASS, $OLD, $NEW\"" "$ROT/folded/.sops.yaml"
check "leaves a rule without an age key unchanged" kms_rule_unchanged
check "leaves other tenants' files and rules, plaintext files and other kinds unchanged" untouched
cp -R "$ROT" "$WORK/rot.rotated"
check "runs again without errors" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "leaves rotated files and .sops.yaml unchanged" diff -r "$WORK/rot.rotated" "$ROT"

tenant_status ".status.publicKey = \"$NEW\" | .status.lastRotation.previousPublicKey = \"$NEW\""
check "never removes the tenant's current key" \
  fails_with "no key rotation in progress or completed" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "keeps the tenant's current key in files and .sops.yaml" diff -r "$WORK/rot.rotated" "$ROT"

tenant_status "$ROTATION_COMPLETED"
check "removes the old key after completion" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "removes the old key after completion from a subdirectory" \
  "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$WORK/sub/team-a"
check "removes the old key from the .sops.yaml above the subdirectory" \
  yq -e ".creation_rules[0].age == \"$BREAKGLASS,$NEW\"" "$WORK/sub/.sops.yaml"
check "the file no longer lists the old key" \
  yq -e "[.sops.age[].recipient] | contains([\"$OLD\"]) | not" "$ROT/team-a/db.sops.yaml"
check "the file decrypts with the new key after cleanup" \
  env SOPS_AGE_KEY_FILE="$WORK/new.key" sops decrypt "$ROT/team-a/db.sops.yaml"
check "the file no longer decrypts with the old key" \
  fails env SOPS_AGE_KEY_FILE="$WORK/tenant.key" sops decrypt "$ROT/team-a/db.sops.yaml"
check "removes the old key from .sops.yaml and keeps the others" \
  yq -e ".creation_rules[0].age == \"$BREAKGLASS,$NEW\"" "$ROT/.sops.yaml"
check "removes the old key from a YAML list and keeps the others" \
  yq -e ".creation_rules[0].age | join(\",\") == \"$BREAKGLASS,$NEW\"" "$ROT/lists/.sops.yaml"
check "removes the old key from folded keys and keeps the others in their style" \
  yq -e ".creation_rules[0].age == \"$BREAKGLASS, $NEW\"" "$ROT/folded/.sops.yaml"
check "leaves a rule without an age key unchanged after cleanup" kms_rule_unchanged
check "leaves other tenants' files and rules, plaintext files and other kinds unchanged after cleanup" untouched
cp -R "$ROT" "$WORK/rot.cleaned"
check "runs again after cleanup without errors" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "leaves cleaned files and .sops.yaml unchanged" diff -r "$WORK/rot.cleaned" "$ROT"

if [ "$FAILED" = 1 ]; then
  echo "Some tests failed"
  exit 1
fi
echo "All tests passed"
