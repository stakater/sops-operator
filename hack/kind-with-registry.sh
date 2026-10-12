#!/usr/bin/env bash
# Creates Kind cluster CLUSTER (node image NODE_IMAGE) whose nodes pull localhost:REGISTRY_PORT/*
# from the registry container REGISTRY_NAME (image REGISTRY_IMAGE) over HTTP. Idempotent. The
# registry has a project-specific name and port so other projects' kind registries are left alone.
# Usage: kind-with-registry.sh KIND CLUSTER NODE_IMAGE REGISTRY_IMAGE REGISTRY_NAME REGISTRY_PORT
set -euo pipefail
KIND=$1 CLUSTER=$2 NODE_IMAGE=$3 REGISTRY_IMAGE=$4 reg_name=$5 reg_port=$6

if [ "$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)" != true ]; then
  docker run -d --restart=always -p "127.0.0.1:${reg_port}:5000" --network bridge --name "${reg_name}" "${REGISTRY_IMAGE}"
fi

if ! "${KIND}" get clusters | grep -qx "${CLUSTER}"; then
  "${KIND}" create cluster --name "${CLUSTER}" --image "${NODE_IMAGE}" --config=- <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry]
    config_path = "/etc/containerd/certs.d"
EOF
fi

dir="/etc/containerd/certs.d/localhost:${reg_port}"
for node in $("${KIND}" get nodes --name "${CLUSTER}"); do
  docker exec "${node}" mkdir -p "${dir}"
  printf '[host."http://%s:5000"]\n' "${reg_name}" | docker exec -i "${node}" cp /dev/stdin "${dir}/hosts.toml"
done

if [ "$(docker inspect -f '{{json .NetworkSettings.Networks.kind}}' "${reg_name}")" = null ]; then
  docker network connect kind "${reg_name}"
fi
