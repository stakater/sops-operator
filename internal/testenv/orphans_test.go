/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package testenv

import (
	"slices"
	"testing"
)

func TestOrphanedControlPlane(t *testing.T) {
	const assets = "/repo/bin/k8s/1.37.0-darwin-arm64"
	ps := `    1     0 /sbin/launchd
  101     1 /repo/bin/k8s/1.37.0-darwin-arm64/etcd --data-dir=/tmp/a
  102     1 /repo/bin/k8s/1.37.0-darwin-arm64/kube-apiserver --etcd-servers=http://127.0.0.1:1
  201   200 /repo/bin/k8s/1.37.0-darwin-arm64/etcd --data-dir=/tmp/b
  202   200 /repo/bin/k8s/1.37.0-darwin-arm64/kube-apiserver --etcd-servers=http://127.0.0.1:2
  301     1 /usr/local/bin/etcd --data-dir=/var/lib/etcd
  401     1 /repo/bin/k8s/1.37.0-darwin-arm64/kubectl proxy
  501     1 /usr/sbin/sshd -D
`
	t.Run("shall select only control plane processes of the envtest assets whose test is gone", func(t *testing.T) {
		if got := orphanedControlPlane(ps, assets); !slices.Equal(got, []int{101, 102}) {
			t.Fatalf("orphans = %v, want [101 102]", got)
		}
	})

	t.Run("shall select nothing without an assets directory", func(t *testing.T) {
		if got := orphanedControlPlane(ps, ""); len(got) != 0 {
			t.Fatalf("orphans = %v, want none", got)
		}
	})
}
