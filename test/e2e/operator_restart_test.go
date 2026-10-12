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

package e2e

import (
	"context"
	"testing"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// Use case: the operator restarts (upgrade, node drain, crash) while SopsSecrets exist.
// Not parallel: Go runs it before the parallel tests start, so the restart disturbs no other test.
func TestOperatorRestart(t *testing.T) {
	t.Run("shall resume after a restart without reporting Conflict", func(t *testing.T) {
		ctx := context.Background()
		prod := namespace(t, "e2e-restart-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-restart-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		before := outputSecret(t, prod)
		ready := *readyCondition(s)
		lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: leaderElectionID, Namespace: operatorNamespace}}
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(lease), lease); err != nil {
			t.Fatal(err)
		}
		oldLeader := ptr.Deref(lease.Spec.HolderIdentity, "")

		// Delete the pod rather than restarting the Deployment: under OLM the CSV owns the Deployment.
		if err := k8s.DeleteAllOf(ctx, &corev1.Pod{}, client.InNamespace(operatorNamespace),
			client.MatchingLabels{"control-plane": "controller-manager"}); err != nil {
			t.Fatal(err)
		}
		// Only the leader reconciles: wait until the new pod leads, then for a sync it made. The
		// leader identity includes a per-process ID, so any other holder is the new process.
		poll(t, "a new operator process to lead", func() (bool, error) {
			if err := k8s.Get(ctx, client.ObjectKeyFromObject(lease), lease); err != nil {
				return false, err
			}
			holder := ptr.Deref(lease.Spec.HolderIdentity, "")
			return holder != "" && holder != oldLeader, nil
		})
		waitForNewSync(t, s, &metav1.Time{Time: lease.Spec.AcquireTime.Time})

		if after := outputSecret(t, prod); after.UID != before.UID {
			t.Fatal("the Secret was recreated instead of updated")
		}
		if s.Status.SecretUID != before.UID {
			t.Fatal("status.secretUID changed across the restart")
		}
		if c := readyCondition(s); !c.LastTransitionTime.Equal(&ready.LastTransitionTime) {
			t.Fatalf("Ready changed across the restart: before %+v, after %+v", ready, *c)
		}
	})
}
