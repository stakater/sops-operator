#!/usr/bin/env bash
# Encrypts a plaintext SopsSecret file in place, with the keys in the .sops.yaml of its GitOps directory.
#
# Usage: scripts/encrypt.sh <path to SopsSecret file>
#
# Needs: sops, yq (https://github.com/mikefarah/yq)
set -euo pipefail

FILE="${1:?usage: scripts/encrypt.sh <path to SopsSecret file>}"

# Step 1: check the file is a plaintext SopsSecret.
if [ ! -f "$FILE" ]; then
  echo "$FILE does not exist" >&2
  exit 1
fi
if [ "$(yq '.kind' "$FILE")" != "SopsSecret" ]; then
  echo "$FILE is not a SopsSecret" >&2
  exit 1
fi
if [ "$(yq 'has("sops")' "$FILE")" = "true" ]; then
  echo "$FILE is already encrypted" >&2
  exit 1
fi

# Step 2: set the scope "<namespace>/<name>". The operator only decrypts the file into that namespace and
# name, so a copy in another namespace is rejected. A scope already in the file is kept.
yq -i '.spec.scope = (.spec.scope // .metadata.namespace + "/" + .metadata.name)' "$FILE"

# Step 3: sort the keys. Kubernetes stores them sorted, and the encrypted file only checks out if its keys
# were in that same order when it was encrypted.
yq -i 'sort_keys(..)' "$FILE"

# Step 4: encrypt the file in place. sops looks for .sops.yaml in the file's directory and the directories
# above it, so run it from there.
cd "$(dirname "$FILE")"
sops encrypt -i "$(basename "$FILE")"
echo "Encrypted $FILE"
