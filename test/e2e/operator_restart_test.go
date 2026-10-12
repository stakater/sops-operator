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

	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// Use case: the operator restarts (upgrade, node drain, crash) while SopsSecrets exist.
// Not parallel: Go runs it before the parallel tests start, so the restart disturbs no other test.
func TestOperatorRestart(t *testing.T) {
	t.Run("shall resume after a restart without reporting Conflict", func(t *testing.T) {
		prod := namespace(t, "e2e-restart-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-restart-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		before := outputSecret(t, prod)

		kubectl := []string{"--context", kubeContext, "-n", operatorNamespace}
		for _, args := range [][]string{
			{"rollout", "restart", "deployment/sops-operator-controller-manager"},
			{"rollout", "status", "deployment/sops-operator-controller-manager", "--timeout=180s"},
		} {
			if _, err := run("", "kubectl", append(kubectl, args...)...); err != nil {
				t.Fatal(err)
			}
		}
		// A sync after the rollout finished comes from the new pod, which must recognise the Secret
		// created before the restart.
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(s), s); err != nil {
			t.Fatal(err)
		}
		waitForNewSync(t, s, s.Status.LastSyncTime)
		if after := outputSecret(t, prod); after.UID != before.UID {
			t.Fatal("the Secret was recreated instead of updated")
		}
	})
}
