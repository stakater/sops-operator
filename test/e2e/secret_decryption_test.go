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

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

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
		out := outputSecret(t, prod)
		// Values are checked here; the golden files record keys, ownership and status.
		if string(out.Data["password"]) != password || string(out.Data["username"]) != "app" {
			t.Fatal("output Secret does not hold the decrypted values")
		}
		if s.Status.SecretUID != out.UID {
			t.Fatal("status.secretUID does not name the output Secret")
		}
		assertGolden(t, s, "decrypted", out)
		assertGolden(t, out, "output", s)
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
		before := outputSecret(t, prod)

		// The developer re-encrypts the file with a new value and the GitOps tool applies it.
		secret.StringData = map[string]string{"password": "v2"}
		next := encryptSopsSecret(t, recipient, secret)
		update(t, s, func() { s.Spec, s.Sops = next.Spec, next.Sops })
		poll(t, "the Secret to hold the new value", func() (bool, error) {
			return string(outputSecret(t, prod).Data["password"]) == "v2", nil
		})
		after := outputSecret(t, prod)
		if after.UID != before.UID {
			t.Fatal("the Secret was recreated instead of updated")
		}
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		if s.Generation != 2 || s.Status.ObservedGeneration != 2 {
			t.Fatalf("generation=%d observedGeneration=%d, want 2 and 2", s.Generation, s.Status.ObservedGeneration)
		}
		assertGolden(t, after, "updated", s)
	})
}

// outputSecretOrNil returns the Secret "db-creds" in namespace, or nil when it does not exist.
func outputSecretOrNil(t *testing.T, namespace string) *corev1.Secret {
	t.Helper()
	var s corev1.Secret
	err := k8s.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: "db-creds"}, &s)
	if client.IgnoreNotFound(err) != nil {
		t.Fatal(err)
	}
	if err != nil {
		return nil
	}
	return &s
}
