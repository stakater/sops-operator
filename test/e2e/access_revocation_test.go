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
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// Use case: the cluster admin revokes a tenant's grants (DESIGN.md §6.5); the operator stops acting
// on the next resync.
func TestAccessRevocation(t *testing.T) {
	t.Parallel()
	t.Run("shall report AccessDenied after the namespace grant is removed", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-revoke-ns-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-revoke-ns-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		before := outputSecret(t, prod)
		grant := metav1.ObjectMeta{Name: tenantSA + "-" + tenantNS, Namespace: prod}
		deleteObject(t, &rbacv1.RoleBinding{ObjectMeta: grant})
		waitForReason(t, s, sopsv1alpha1.ReasonAccessDenied)
		assertGolden(t, s, "namespace grant removed")
		// The operator can no longer write there, so the existing Secret stays as it was (DESIGN.md §6.5).
		after := outputSecret(t, prod)
		if after.UID != before.UID || string(after.Data["password"]) != password {
			t.Fatal("the Secret changed after the grant was removed")
		}
	})

	t.Run("shall report TenantNotReady after the key grant is removed", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-revoke-key-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-revoke-key-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		keyGrant := metav1.ObjectMeta{Name: tenantSA + "-key-owner", Namespace: tenantNS}
		deleteObject(t, &rbacv1.RoleBinding{ObjectMeta: keyGrant})
		tenant := &sopsv1alpha1.SopsTenant{ObjectMeta: metav1.ObjectMeta{Name: tenantName, Namespace: tenantNS}}
		waitForReason(t, tenant, sopsv1alpha1.ReasonAccessDenied)
		waitForMessage(t, s, sopsv1alpha1.ReasonTenantNotReady, "is not ready")
		assertGolden(t, s, "key grant removed")
	})
}
