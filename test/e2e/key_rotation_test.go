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
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

// Use case: a tenant admin rotates the tenant key (DESIGN.md §8.3): add a new primary key, encrypt
// new files for it, then remove the old key.
func TestKeyRotation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	prod := namespace(t, "e2e-rotate-prod")
	tenantNS, oldRecipient := onboardedTenant(t, "e2e-rotate-tenant", prod)
	key := &corev1.Secret{}
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: tenantNS, Name: tenantKeySecret}, key); err != nil {
		t.Fatal(err)
	}
	oldKey := key.Data[crypto.KeyFileField]
	newKey, newRecipient, err := crypto.GenerateKeyFile(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// setKey stands in for the tenant admin editing the key Secret.
	setKey := func(t *testing.T, keyFile []byte, primary string) {
		t.Helper()
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(key), key); err != nil {
			t.Fatal(err)
		}
		key.Data[crypto.KeyFileField] = keyFile
		key.Data[crypto.PublicKeyField] = []byte(primary)
		if err := k8s.Update(ctx, key); err != nil {
			t.Fatal(err)
		}
	}

	existing := createSopsSecret(t, oldRecipient, sopsSecret{
		Name: "old-file", Namespace: prod, Scope: prod + "/old-file", TenantNamespace: tenantNS,
		StringData: map[string]string{"password": "old"},
	})
	waitForReason(t, existing, sopsv1alpha1.ReasonDecrypted)

	var rotated *sopsv1alpha1.SopsSecret
	t.Run("shall decrypt old and new files while both keys are present", func(t *testing.T) {
		setKey(t, append(append(newKey, '\n'), oldKey...), newRecipient)
		rotated = createSopsSecret(t, newRecipient, sopsSecret{
			Name: "new-file", Namespace: prod, Scope: prod + "/new-file", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": "new"},
		})
		waitForReason(t, rotated, sopsv1alpha1.ReasonDecrypted)
		// The new file decrypting proves the operator loaded both keys; a later sync of the old file
		// proves the old key still works with them.
		waitForNewSync(t, existing, rotated.Status.LastSyncTime)
	})

	t.Run("shall reject files for a removed key and keep their Secret", func(t *testing.T) {
		if rotated == nil {
			t.Skip("needs the new file from the previous subtest")
		}
		removed := metav1.Now()
		setKey(t, newKey, newRecipient)
		waitForReason(t, existing, sopsv1alpha1.ReasonNotRecipient)
		assertGolden(t, existing, "retired key")
		var kept corev1.Secret
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: prod, Name: "old-file"}, &kept); err != nil {
			t.Fatalf("the Secret written with the old key must stay: %v", err)
		}
		if string(kept.Data["password"]) != "old" {
			t.Fatal("the Secret written with the old key was changed")
		}
		waitForNewSync(t, rotated, &removed)
	})
}
