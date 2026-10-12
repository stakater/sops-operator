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

// Use case: a developer commits an encrypted SopsSecret and the application gets a Secret (DESIGN.md §8.2).
func TestSecretDecryption(t *testing.T) {
	t.Parallel()
	t.Run("shall decrypt into a Secret", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-deliver-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-deliver-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password, "username": "app"},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		assertGolden(t, s, "decrypted")

		out := outputSecret(t, prod)
		// Values are checked here; the snapshot only records which keys exist.
		if string(out.Data["password"]) != password || string(out.Data["username"]) != "app" {
			t.Fatal("output Secret does not hold the decrypted values")
		}
		assertGolden(t, out, "output")
	})

	t.Run("shall update the Secret when the SopsSecret changes", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-change-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-change-tenant", prod)
		secret := sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": "v1"},
		}
		s := createSopsSecret(t, recipient, secret)
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)

		// The developer re-encrypts the file with a new value and the GitOps tool applies it.
		secret.StringData = map[string]string{"password": "v2"}
		next := encryptSopsSecret(t, recipient, secret)
		next.ResourceVersion = s.ResourceVersion
		if err := k8s.Update(context.Background(), next); err != nil {
			t.Fatal(err)
		}
		poll(t, "the Secret to hold the new value", func() (bool, error) {
			return string(outputSecret(t, prod).Data["password"]) == "v2", nil
		})
		assertGolden(t, outputSecret(t, prod), "updated")
	})
}
