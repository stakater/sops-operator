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

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// Use case: a team moves an existing Secret to a SopsSecret (DESIGN.md §8.4).
func TestMigratingAnExistingSecret(t *testing.T) {
	t.Run("shall not overwrite a Secret it did not create", func(t *testing.T) {
		prod := namespace(t, "e2e-migrate-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-migrate-tenant", prod)
		apply(t, render(t, "secret.yaml", map[string]any{"Name": "db-creds", "Namespace": prod}))
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": "mine"},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonConflict)
		assertGolden(t, s, "conflict")
		if string(outputSecret(t, prod).Data["password"]) != "foreign" {
			t.Fatal("the existing Secret was overwritten")
		}
	})
}
