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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

// refused checks that err is the webhook's refusal naming want, and that the Secret is unchanged.
func refused(t *testing.T, err error, want string, before *corev1.Secret) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("got %v, want a refusal mentioning %q", err, want)
	}
	var after corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(before), &after); err != nil {
		t.Fatal(err)
	}
	if after.UID != before.UID || after.ResourceVersion != before.ResourceVersion {
		t.Fatal("the refused change was applied")
	}
}

func TestOwnedSecretProtection(t *testing.T) {
	t.Parallel()
	prod := namespace(t, "e2e-protect-prod")
	tenantNS, recipient := onboardedTenant(t, "e2e-protect-tenant", prod)
	s := createSopsSecret(t, recipient, sopsSecret{
		Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
		StringData: map[string]string{"password": password},
	})
	waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)

	t.Run("shall refuse deleting an output Secret", func(t *testing.T) {
		out := outputSecret(t, prod)
		refused(t, k8s.Delete(context.Background(), out), "SopsSecret db-creds", out)
	})

	t.Run("shall refuse editing an output Secret", func(t *testing.T) {
		out := outputSecret(t, prod)
		edited := out.DeepCopy()
		edited.Data["password"] = []byte("changed by hand")
		refused(t, k8s.Update(context.Background(), edited), "SopsSecret db-creds", out)
	})

	t.Run("shall refuse changing the key of a tenant with SopsSecrets", func(t *testing.T) {
		key := tenantKey(t, tenantNS)
		other, _, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		edited := key.DeepCopy()
		edited.Data[crypto.KeyFileField] = other
		refused(t, k8s.Update(context.Background(), edited), "startRotation", key)
	})

	t.Run("shall refuse deleting the key of a tenant with SopsSecrets", func(t *testing.T) {
		key := tenantKey(t, tenantNS)
		refused(t, k8s.Delete(context.Background(), key), "startRotation", key)
	})
}
