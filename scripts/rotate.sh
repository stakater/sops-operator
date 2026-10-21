#!/usr/bin/env bash
# Moves every SopsSecret file of a tenant in a GitOps directory to the tenant's next key during a key
# rotation, and removes the old key after the rotation completed. It needs no private key: the operator
# prepared, for each SopsSecret, the entry its file needs to decrypt with the next key.
#
# Usage: scripts/rotate.sh <SopsTenant file> <GitOps directory>
#
# Needs: yq (https://github.com/mikefarah/yq), oc logged in to the tenant's cluster
set -euo pipefail

TENANT_FILE="${1:?usage: scripts/rotate.sh <SopsTenant file> <GitOps directory>}"
DIR="${2:?usage: scripts/rotate.sh <SopsTenant file> <GitOps directory>}"

# Step 1: read the tenant from its file, and its keys from the cluster.
TENANT_NAMESPACE="$(yq '.metadata.namespace' "$TENANT_FILE")"
TENANT_NAME="$(yq '.metadata.name' "$TENANT_FILE")"
TENANT="$(oc get sopstenant "$TENANT_NAME" -n "$TENANT_NAMESPACE" -o json)"
CURRENT="$(echo "$TENANT" | yq -p json '.status.publicKey // ""')"
NEXT="$(echo "$TENANT" | yq -p json '.status.rotation.nextPublicKey // ""')"
OLD="$(echo "$TENANT" | yq -p json '.status.lastRotation.previousPublicKey // ""')"
if [ -z "$NEXT" ] && [ -z "$OLD" ]; then
  echo "Tenant $TENANT_NAMESPACE/$TENANT_NAME has no key rotation in progress or completed" >&2
  exit 1
fi

# has_key <file> <public key>: the file has an entry for the key in sops.age.
has_key() {
  [ "$(K="$2" yq '[.sops.age[].recipient] | contains([strenv(K)])' "$1")" = "true" ]
}

# Step 2: find the tenant's encrypted SopsSecret files in the directory and its subdirectories.
FILES=()
while IFS= read -r file; do
  if [ "$(T_NS="$TENANT_NAMESPACE" T_NAME="$TENANT_NAME" yq '.kind == "SopsSecret" and has("sops") and
      .spec.tenantRef.namespace == strenv(T_NS) and .spec.tenantRef.name == strenv(T_NAME)' "$file")" = "true" ]; then
    FILES+=("$file")
  fi
done < <(find "$DIR" -type f \( -name '*.yaml' -o -name '*.yml' \) ! -name '.sops.yaml' | sort)

# Step 3: during a rotation, check every file against the cluster before changing any. A file must
# match its SopsSecret in the cluster (same MAC), so the operator's entry fits it.
if [ -n "$NEXT" ]; then
  PROBLEMS=0
  for file in ${FILES[@]+"${FILES[@]}"}; do
    if has_key "$file" "$NEXT"; then
      continue
    fi
    NAME="$(yq '.metadata.name' "$file")"
    NAMESPACE="$(yq '.metadata.namespace' "$file")"
    if ! CLUSTER="$(oc get sopssecret "$NAME" -n "$NAMESPACE" -o json 2>/dev/null)"; then
      echo "$file: SopsSecret $NAMESPACE/$NAME is not in the cluster; let your GitOps tool apply it first" >&2
      PROBLEMS=1
    elif [ "$(echo "$CLUSTER" | yq -p json '.sops.mac')" != "$(yq '.sops.mac' "$file")" ]; then
      echo "$file: differs from SopsSecret $NAMESPACE/$NAME in the cluster; sync it first" >&2
      PROBLEMS=1
    elif [ "$(echo "$CLUSTER" | yq -p json '.status.rotation.nextRecipient.recipient // ""')" != "$NEXT" ]; then
      echo "$file: the operator has not prepared the next key for $NAMESPACE/$NAME yet; try again shortly" >&2
      PROBLEMS=1
    fi
  done
  if [ "$PROBLEMS" = 1 ]; then
    echo "No file was changed" >&2
    exit 1
  fi
fi

for file in ${FILES[@]+"${FILES[@]}"}; do
  # Step 4: add the next key: append the entry the operator prepared to sops.age. Nothing else in
  # the file changes.
  if [ -n "$NEXT" ] && ! has_key "$file" "$NEXT"; then
    ENTRY="$(oc get sopssecret "$(yq '.metadata.name' "$file")" -n "$(yq '.metadata.namespace' "$file")" -o json |
      yq -p json -o json '.status.rotation.nextRecipient')"
    ENTRY="$ENTRY" yq -i '.sops.age += [env(ENTRY)]' "$file"
    echo "Added the next key to $file"
  fi
  # Step 5: remove the key an earlier rotation replaced; it decrypts nothing any more.
  if [ -n "$OLD" ] && has_key "$file" "$OLD"; then
    O="$OLD" yq -i 'del(.sops.age[] | select(.recipient == strenv(O)))' "$file"
    echo "Removed the old key from $file"
  fi
done

# Step 6: update every .sops.yaml in the directory: add the next key where the current key is listed,
# and remove the old key. Other recipients, such as break-glass keys, stay. The age list is a
# comma-separated string here; a YAML list works the same way.
while IFS= read -r config; do
  if [ -n "$NEXT" ]; then
    C="$CURRENT" N="$NEXT" yq -i '(.creation_rules[] | select((.age | tostring | contains(strenv(C))) and
      ((.age | tostring | contains(strenv(N))) | not)) | .age | select(tag == "!!str")) |= . + "," + strenv(N)' "$config"
    C="$CURRENT" N="$NEXT" yq -i '(.creation_rules[] | select((.age | tostring | contains(strenv(C))) and
      ((.age | tostring | contains(strenv(N))) | not)) | .age | select(tag == "!!seq")) |= . + [strenv(N)]' "$config"
  fi
  if [ -n "$OLD" ]; then
    O="$OLD" yq -i '(.creation_rules[].age | select(tag == "!!str")) |= (split(",") | map(select(. != strenv(O))) | join(","))' "$config"
    O="$OLD" yq -i '(.creation_rules[].age | select(tag == "!!seq")) |= map(select(. != strenv(O)))' "$config"
  fi
done < <(find "$DIR" -type f -name '.sops.yaml')

# Step 7: report SopsSecrets of the tenant in the cluster that have no file here: they belong to
# another directory, or their file is missing.
KNOWN="$(for file in ${FILES[@]+"${FILES[@]}"}; do yq '.metadata.namespace + "/" + .metadata.name' "$file"; done)"
for namespace in $(for file in ${FILES[@]+"${FILES[@]}"}; do yq '.metadata.namespace' "$file"; done | sort -u); do
  oc get sopssecrets -n "$namespace" -o json |
    T_NS="$TENANT_NAMESPACE" T_NAME="$TENANT_NAME" yq -p json '.items[] |
      select(.spec.tenantRef.namespace == strenv(T_NS) and .spec.tenantRef.name == strenv(T_NAME)) |
      .metadata.namespace + "/" + .metadata.name' |
    while IFS= read -r secret; do
      if ! echo "$KNOWN" | grep -qx "$secret"; then
        echo "Note: SopsSecret $secret has no file in $DIR" >&2
      fi
    done
done
echo "Done. Review the changes and commit them."
