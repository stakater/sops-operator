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
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

	t.Run("shall restore a deleted key Secret from its backup and record a KeyRestored event", func(t *testing.T) {
		deleteObject(t, tenantKey(t, tenantNS))
		waitForKey(t, tenantNS, original)
		poll(t, "a KeyRestored event on the tenant", func() (bool, error) {
			return hasEvent(t, tenantNS, tenantName, sopsv1alpha1.ReasonKeyRestored), nil
		})
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

// hasEvent reports whether an event with reason regards the object named name in namespace.
func hasEvent(t *testing.T, namespace, name, reason string) bool {
	t.Helper()
	var events eventsv1.EventList
	if err := k8s.List(context.Background(), &events, client.InNamespace(namespace)); err != nil {
		t.Fatal(err)
	}
	for _, e := range events.Items {
		if e.Regarding.Name == name && e.Reason == reason {
			return true
		}
	}
	return false
}

// wipeStatus clears the status of the tenant in tenantNamespace, as a restore from a backup without
// status does.
func wipeStatus(t *testing.T, tenantNamespace string) {
	t.Helper()
	tenant := &sopsv1alpha1.SopsTenant{}
	key := client.ObjectKey{Namespace: tenantNamespace, Name: tenantName}
	if err := k8s.Get(context.Background(), key, tenant); err != nil {
		t.Fatal(err)
	}
	tenant.Status = sopsv1alpha1.SopsTenantStatus{}
	if err := k8s.Status().Update(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
}

// Use case: the operator keeps the tenant key from objects alone; a tenant whose status is lost, for
// example restored from a backup without status, keeps its key.
func TestKeyWithoutStatus(t *testing.T) {
	t.Parallel()

	t.Run("shall restore the backed-up key, not generate one, after the tenant's status is lost", func(t *testing.T) {
		t.Parallel()
		tenantNS, recipient := onboardedTenant(t, "e2e-keystatus-restore-tenant")
		original := tenantKey(t, tenantNS).Data[crypto.KeyFileField]
		poll(t, "a backup of the tenant key", func() (bool, error) { return len(keyBackups(t, tenantNS)) == 1, nil })
		wipeStatus(t, tenantNS)
		deleteObject(t, tenantKey(t, tenantNS))
		waitForKey(t, tenantNS, original)
		tenant := &sopsv1alpha1.SopsTenant{}
		tenant.Name, tenant.Namespace = tenantName, tenantNS
		waitForReason(t, tenant, sopsv1alpha1.ReasonKeyLoaded)
		if tenant.Status.PublicKey != recipient {
			t.Fatal("status.publicKey is not the restored key")
		}
	})

	t.Run("shall not generate a key while SopsSecrets use the tenant", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		prod := namespace(t, "e2e-keystatus-used-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-keystatus-used-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		poll(t, "a backup of the tenant key", func() (bool, error) { return len(keyBackups(t, tenantNS)) == 1, nil })
		// The tenant admin deletes the key and its backup, and the tenant's status is lost.
		for _, b := range keyBackups(t, tenantNS) {
			deleteObject(t, &b)
		}
		wipeStatus(t, tenantNS)
		deleteObject(t, tenantKey(t, tenantNS))
		tenant := &sopsv1alpha1.SopsTenant{}
		tenant.Name, tenant.Namespace = tenantName, tenantNS
		waitForMessage(t, tenant, sopsv1alpha1.ReasonKeyMissing, "1 SopsSecrets")
		err := k8s.Get(ctx, client.ObjectKey{Namespace: tenantNS, Name: tenantKeySecret}, &corev1.Secret{})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("got %v, want no key Secret: a new key would decrypt none of the files", err)
		}
	})

	t.Run("shall report no public key while the key is missing", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-keystatus-nokey-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-keystatus-nokey-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		poll(t, "a backup of the tenant key", func() (bool, error) { return len(keyBackups(t, tenantNS)) == 1, nil })
		for _, b := range keyBackups(t, tenantNS) {
			deleteObject(t, &b)
		}
		deleteObject(t, tenantKey(t, tenantNS))
		tenant := &sopsv1alpha1.SopsTenant{}
		tenant.Name, tenant.Namespace = tenantName, tenantNS
		waitForReason(t, tenant, sopsv1alpha1.ReasonKeyMissing)
		if tenant.Status.PublicKey != "" {
			t.Fatalf("status.publicKey = %q, want none while the key is missing", tenant.Status.PublicKey)
		}
	})
}
