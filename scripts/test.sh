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

# The tenant's next key and a break-glass key; the entry the operator would offer for db.sops.yaml
# is made here with sops, which wraps the data key the same way.
age-keygen -pq -o "$WORK/next.key" 2>/dev/null
NEXT="$(age-keygen -y "$WORK/next.key")"
CURRENT="$(age-keygen -y "$WORK/tenant.key")"
age-keygen -pq -o "$WORK/breakglass.key" 2>/dev/null
BREAKGLASS="$(age-keygen -y "$WORK/breakglass.key")"

ROT="$WORK/rot"
mkdir -p "$ROT/team-a" "$WORK/cluster"
cat >"$ROT/.sops.yaml" <<EOF
creation_rules:
  - path_regex: \.sops\.ya?ml$
    encrypted_regex: ^(data|stringData|scope)$
    mac_only_encrypted: true
    age: $CURRENT,$BREAKGLASS
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
cp "$ROT/team-a/db.sops.yaml" "$ROT/team-a/with-next.sops.yaml"
yq -i ".creation_rules[0].age = \"$CURRENT,$BREAKGLASS,$NEXT\"" "$ROT/.sops.yaml"
(cd "$ROT/team-a" && SOPS_AGE_KEY_FILE="$WORK/tenant.key" sops updatekeys -y with-next.sops.yaml >/dev/null 2>&1)
yq -i ".creation_rules[0].age = \"$CURRENT,$BREAKGLASS\"" "$ROT/.sops.yaml"
R="$NEXT" yq -o json '.sops.age[] | select(.recipient == strenv(R))' "$ROT/team-a/with-next.sops.yaml" >"$WORK/entry.json"
rm "$ROT/team-a/with-next.sops.yaml"

# A rule without an age key, and a .sops.yaml whose age is a YAML list; the script must leave the first alone.
yq -i '.creation_rules += [{"path_regex": "^kms-only/", "kms": "arn:aws:kms:x"}]' "$ROT/.sops.yaml"
yq '.creation_rules[1]' "$ROT/.sops.yaml" >"$WORK/kms-rule.before"
# kms_rule_unchanged: the rule without an age key is as it was before the script ran.
kms_rule_unchanged() {
  yq '.creation_rules[1]' "$ROT/.sops.yaml" | cmp - "$WORK/kms-rule.before"
}
mkdir -p "$ROT/lists"
printf 'creation_rules:\n  - path_regex: .*\n    age:\n      - %s\n      - %s\n' "$CURRENT" "$BREAKGLASS" >"$ROT/lists/.sops.yaml"

cat >"$ROT/tenant.yaml" <<EOF
apiVersion: sops.stakater.com/v1alpha1
kind: SopsTenant
metadata:
  name: team-a
  namespace: team-a-system
EOF
# Cluster state during the rotation.
yq -n -o json ".status.publicKey = \"$CURRENT\" | .status.rotation.nextPublicKey = \"$NEXT\"" \
  >"$WORK/cluster/sopstenant-team-a-system-team-a.json"
ENTRY="$(cat "$WORK/entry.json")" yq -o json '.status.rotation.nextRecipient = env(ENTRY)' \
  "$ROT/team-a/db.sops.yaml" >"$WORK/cluster/sopssecret-team-a-stage-db.json"
DB="$(cat "$WORK/cluster/sopssecret-team-a-stage-db.json")" yq -n -o json '.items = [env(DB)]' \
  >"$WORK/cluster/sopssecrets-team-a-stage.json"

cat >"$WORK/bin/oc" <<'EOF'
#!/usr/bin/env bash
# oc get <kind> [<name>] -n <namespace> -o json, answered from $FAKE_CLUSTER.
if [ "$3" = "-n" ]; then file="$FAKE_CLUSTER/$2-$4.json"; else file="$FAKE_CLUSTER/$2-$5-$3.json"; fi
if [ -f "$file" ]; then cat "$file"; else echo "Error from server (NotFound)" >&2; exit 1; fi
EOF
chmod +x "$WORK/bin/oc"
export FAKE_CLUSTER="$WORK/cluster"

cp "$ROT/team-a/db.sops.yaml" "$WORK/db.unrotated"
mv "$WORK/cluster/sopssecret-team-a-stage-db.json" "$WORK/db.cluster.json"
check "stops when a file has no SopsSecret in the cluster" fails "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "changes no file when it stops" cmp "$WORK/db.unrotated" "$ROT/team-a/db.sops.yaml"
mv "$WORK/db.cluster.json" "$WORK/cluster/sopssecret-team-a-stage-db.json"
mkdir -p "$WORK/empty"
check "stops when the directory has no files of the tenant" fails "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$WORK/empty"

check "adds the next key to the tenant's files" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "the file decrypts with the next key" \
  env SOPS_AGE_KEY_FILE="$WORK/next.key" sops decrypt "$ROT/team-a/db.sops.yaml"
check "the file still decrypts with the current key" \
  env SOPS_AGE_KEY_FILE="$WORK/tenant.key" sops decrypt "$ROT/team-a/db.sops.yaml"
check "keeps the file's comments" grep -q '^# kept comment' "$ROT/team-a/db.sops.yaml"
check "adds the next key to .sops.yaml" yq -e ".creation_rules[0].age | contains(\"$NEXT\")" "$ROT/.sops.yaml"
check "keeps other recipients" yq -e ".creation_rules[0].age | contains(\"$BREAKGLASS\")" "$ROT/.sops.yaml"
check "adds the next key to a YAML list of keys once" \
  yq -e ".creation_rules[0].age | join(\",\") == \"$CURRENT,$BREAKGLASS,$NEXT\"" "$ROT/lists/.sops.yaml"
check "leaves a rule without an age key unchanged" \
  kms_rule_unchanged
cp "$ROT/team-a/db.sops.yaml" "$WORK/db.rotated"
check "runs again without errors" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "leaves rotated files unchanged" cmp "$WORK/db.rotated" "$ROT/team-a/db.sops.yaml"

# Cluster state after completion: the old key is gone.
yq -n -o json ".status.publicKey = \"$NEXT\" | .status.lastRotation.previousPublicKey = \"$CURRENT\"" \
  >"$WORK/cluster/sopstenant-team-a-system-team-a.json"
check "removes the old key after completion" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "the file no longer lists the old key" \
  yq -e "[.sops.age[].recipient] | contains([\"$CURRENT\"]) | not" "$ROT/team-a/db.sops.yaml"
check "the file decrypts with the new key after cleanup" \
  env SOPS_AGE_KEY_FILE="$WORK/next.key" sops decrypt "$ROT/team-a/db.sops.yaml"
check "removes the old key from .sops.yaml and keeps the others" \
  yq -e ".creation_rules[0].age == \"$BREAKGLASS,$NEXT\"" "$ROT/.sops.yaml"
check "removes the old key from a YAML list and keeps the others" \
  yq -e ".creation_rules[0].age | join(\",\") == \"$BREAKGLASS,$NEXT\"" "$ROT/lists/.sops.yaml"
check "leaves a rule without an age key unchanged after cleanup" \
  kms_rule_unchanged

# A tenant status without a current key must not make the script touch every rule of .sops.yaml.
cp "$ROT/.sops.yaml" "$WORK/sops.before"
yq -n -o json ".status.rotation.nextPublicKey = \"$NEXT\"" >"$WORK/cluster/sopstenant-team-a-system-team-a.json"
check "does not update .sops.yaml without a current key" "$SCRIPTS/rotate.sh" "$ROT/tenant.yaml" "$ROT"
check "leaves .sops.yaml unchanged without a current key" cmp "$WORK/sops.before" "$ROT/.sops.yaml"

if [ "$FAILED" = 1 ]; then
  echo "Some tests failed"
  exit 1
fi
echo "All tests passed"
