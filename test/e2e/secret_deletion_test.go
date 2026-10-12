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

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// Use case: a developer removes a SopsSecret from Git and the GitOps tool prunes it.
func TestSecretDeletion(t *testing.T) {
	t.Parallel()
	t.Run("shall delete the Secret with the SopsSecret", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-remove-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-remove-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		out := outputSecret(t, prod)
		if err := k8s.Delete(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		waitUntilDeleted(t, "the output Secret", out)
	})

	t.Run("shall keep the Secret when deletionPolicy is Retain", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-retain-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-retain-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			DeletionPolicy: string(sopsv1alpha1.DeletionPolicyRetain), StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		if err := k8s.Delete(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		waitUntilDeleted(t, "the SopsSecret", s)
		kept := outputSecret(t, prod)
		if len(kept.OwnerReferences) != 0 {
			t.Fatalf("a retained Secret must have no owner, got %v", kept.OwnerReferences)
		}
		assertGolden(t, kept, "retained")
	})
}
