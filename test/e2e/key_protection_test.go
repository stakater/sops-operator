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

// keyBackups returns the tenant's key backups.
func keyBackups(t *testing.T, tenantNamespace string) []corev1.Secret {
	t.Helper()
	var list corev1.SecretList
	if err := k8s.List(context.Background(), &list, client.InNamespace(tenantNamespace),
		client.MatchingLabels{sopsv1alpha1.LabelKeyBackup: "true"}); err != nil {
		t.Fatal(err)
	}
	return list.Items
}

// waitForKey waits until the tenant's key Secret holds keyFile.
func waitForKey(t *testing.T, tenantNamespace string, keyFile []byte) {
	t.Helper()
	poll(t, "the key Secret to hold the key from its backup", func() (bool, error) {
		var key corev1.Secret
		err := k8s.Get(context.Background(), client.ObjectKey{Namespace: tenantNamespace, Name: tenantKeySecret}, &key)
		if err != nil {
			return false, client.IgnoreNotFound(err)
		}
		return string(key.Data[crypto.KeyFileField]) == string(keyFile) &&
			key.Labels[sopsv1alpha1.LabelEnabled] == sopsv1alpha1.EnabledValue, nil
	})
}

// Use case: the tenant key survives a deletion or a change of its Secret outside a rotation, because the
// operator keeps an immutable backup of it and restores the key Secret from that backup.
func TestKeyProtection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	prod := namespace(t, "e2e-keyprotect-prod")
	tenantNS, recipient := onboardedTenant(t, "e2e-keyprotect-tenant", prod)
	original := tenantKey(t, tenantNS).Data[crypto.KeyFileField]
	s := createSopsSecret(t, recipient, sopsSecret{
		Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
		StringData: map[string]string{"password": password},
	})
	waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)

	t.Run("shall keep an immutable backup of the tenant key", func(t *testing.T) {
		var backups []corev1.Secret
		poll(t, "a backup of the tenant key", func() (bool, error) {
			backups = keyBackups(t, tenantNS)
			return len(backups) == 1, nil
		})
		b := backups[0]
		if !strings.HasPrefix(b.Name, tenantKeySecret+"-") {
			t.Fatalf("backup name %s does not start with %s-", b.Name, tenantKeySecret)
		}
		if b.Immutable == nil || !*b.Immutable {
			t.Fatal("the backup is not immutable")
		}
		if b.Annotations[sopsv1alpha1.AnnotationPublicKey] != recipient {
			t.Fatal("the backup does not name the tenant's public key")
		}
		if string(b.Data[crypto.KeyFileField]) != string(original) {
			t.Fatal("the backup does not hold the tenant key")
		}
		edited := b.DeepCopy()
		edited.Data[crypto.KeyFileField] = []byte("changed by hand")
		if err := k8s.Update(ctx, edited); err == nil {
			t.Fatal("the API server accepted a change of an immutable backup")
		}
	})

	t.Run("shall restore a deleted key Secret from its backup", func(t *testing.T) {
		deleteObject(t, tenantKey(t, tenantNS))
		waitForKey(t, tenantNS, original)
	})

	t.Run("shall restore a changed key Secret from its backup", func(t *testing.T) {
		other, _, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		key := tenantKey(t, tenantNS)
		update(t, key, func() { key.Data[crypto.KeyFileField] = other })
		waitForKey(t, tenantNS, original)
	})

	t.Run("shall keep decrypting with the restored key", func(t *testing.T) {
		tenant := &sopsv1alpha1.SopsTenant{}
		tenant.Name, tenant.Namespace = tenantName, tenantNS
		waitForReason(t, tenant, sopsv1alpha1.ReasonKeyLoaded)
		if tenant.Status.PublicKey != recipient {
			t.Fatal("status.publicKey changed after the restore")
		}
		if n := len(keyBackups(t, tenantNS)); n != 1 {
			t.Fatalf("got %d key backups after the restores, want 1", n)
		}
		waitForNewSync(t, s, s.Status.LastSyncTime)
		if got := string(outputSecret(t, prod).Data["password"]); got != password {
			t.Fatal("the output Secret changed after the key was restored")
		}
	})
}
