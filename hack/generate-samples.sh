#!/usr/bin/env bash
# Regenerates config/samples/sops_v1alpha1_sopssecret.yaml, the SopsSecret OLM publishes as an
# alm-example (the OpenShift console pre-fills its "Create" form with it).
#
# The sample is a real SOPS document, produced the way a developer produces one (DESIGN.md §8.2),
# encrypted for a throwaway key whose private half is never stored. Created as is, it reports
# NotRecipient, which tells the user to encrypt the file for their tenant's key.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
SOPS=$(realpath "${SOPS:-${root}/bin/sops}")
YQ=$(realpath "${YQ:-${root}/bin/yq}")
out="${root}/config/samples/sops_v1alpha1_sopssecret.yaml"

recipient=$(cd "${root}" && go run ./hack/throwaway-recipient)
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

cat > "${work}/.sops.yaml" <<YAML
creation_rules:
  - path_regex: \.sops\.ya?ml$
    encrypted_regex: ^(data|stringData|scope)$
    mac_only_encrypted: true
    age: ${recipient}
YAML

cat > "${work}/sample.sops.yaml" <<'YAML'
apiVersion: sops.stakater.com/v1alpha1
kind: SopsSecret
metadata:
  name: db-credentials
  namespace: my-app
spec:
  tenantRef:
    name: my-team
    namespace: my-team-sops
  deletionPolicy: Delete
  type: Opaque
  template:
    metadata:
      labels:
        app.kubernetes.io/name: my-app
  stringData:
    username: my-app
    password: change-me
YAML

cd "${work}"
"${YQ}" -i '.spec.scope = .metadata.namespace + "/" + .metadata.name' sample.sops.yaml
"${YQ}" -i 'sort_keys(..)' sample.sops.yaml
"${SOPS}" encrypt -i sample.sops.yaml
cp sample.sops.yaml "${out}"
echo "wrote ${out#"${root}/"}"
