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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

const publicKeyField = "age.pub"

// secondKeySecret is the key Secret a tenant admin adds next to the first.
const secondKeySecret = tenantName + "-sops-keys-1"

func tenantOf(t *testing.T, tenantNamespace string) *sopsv1alpha1.SopsTenant {
	t.Helper()
	tenant := &sopsv1alpha1.SopsTenant{}
	key := client.ObjectKey{Namespace: tenantNamespace, Name: tenantName}
	if err := k8s.Get(context.Background(), key, tenant); err != nil {
		t.Fatal(err)
	}
	return tenant
}

func wipeStatus(t *testing.T, tenantNamespace string) {
	t.Helper()
	tenant := tenantOf(t, tenantNamespace)
	tenant.Status = sopsv1alpha1.SopsTenantStatus{}
	if err := k8s.Status().Update(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
}

func createKeySecret(t *testing.T, tenantNamespace, name string, keyFile []byte, labelled bool) {
	t.Helper()
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: tenantNamespace},
		Data:       map[string][]byte{crypto.KeyFileField: keyFile},
	}
	if labelled {
		s.Labels = map[string]string{sopsv1alpha1.LabelEnabled: sopsv1alpha1.EnabledValue}
	}
	if err := k8s.Create(context.Background(), s); err != nil {
		t.Fatal(err)
	}
}

func waitForImmutableKey(t *testing.T, tenantNamespace, name string, keyFile []byte, recipient string) {
	t.Helper()
	poll(t, "key Secret "+name+" to be immutable and to hold its public key", func() (bool, error) {
		var key corev1.Secret
		if err := k8s.Get(context.Background(), client.ObjectKey{Namespace: tenantNamespace, Name: name}, &key); err != nil {
			return false, client.IgnoreNotFound(err)
		}
		return key.Immutable != nil && *key.Immutable &&
			key.Labels[sopsv1alpha1.LabelEnabled] == sopsv1alpha1.EnabledValue &&
			string(key.Data[crypto.KeyFileField]) == string(keyFile) &&
			string(key.Data[publicKeyField]) == recipient, nil
	})
}

func waitForCurrentKey(t *testing.T, tenantNamespace, name, recipient string) {
	t.Helper()
	poll(t, "the tenant to report "+name+" as its current key", func() (bool, error) {
		tenant := tenantOf(t, tenantNamespace)
		return tenant.Status.KeySecretName == name && tenant.Status.PublicKey == recipient, nil
	})
}

// Use case: each tenant key is an immutable Secret <tenant>-sops-keys-<index> that holds the private and
// the public key; the highest index is the current key, and every key decrypts.
func TestTenantKeys(t *testing.T) {
	t.Parallel()

	t.Run("shall generate the first key in the immutable Secret <tenant>-sops-keys-0 with its public key",
		func(t *testing.T) {
			t.Parallel()
			tenantNS, recipient := onboardedTenant(t, "e2e-keys-generate-tenant")
			key := tenantKey(t, tenantNS, firstKeySecret)
			waitForImmutableKey(t, tenantNS, firstKeySecret, key.Data[crypto.KeyFileField], recipient)
			waitForCurrentKey(t, tenantNS, firstKeySecret, recipient)
		})

	t.Run("shall make the highest-indexed key current and keep decrypting with the others", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-keys-highest-prod")
		tenantNS, first := onboardedTenant(t, "e2e-keys-highest-tenant", prod)
		old := createSopsSecret(t, first, sopsSecret{
			Name: "old-creds", Namespace: prod, Scope: prod + "/old-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, old, sopsv1alpha1.ReasonDecrypted)
		keyFile, second, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		createKeySecret(t, tenantNS, secondKeySecret, keyFile, true)
		waitForImmutableKey(t, tenantNS, secondKeySecret, keyFile, second)
		waitForCurrentKey(t, tenantNS, secondKeySecret, second)
		next := createSopsSecret(t, second, sopsSecret{
			Name: "new-creds", Namespace: prod, Scope: prod + "/new-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, next, sopsv1alpha1.ReasonDecrypted)
		waitForNewSync(t, old, old.Status.LastSyncTime)
		waitForReason(t, old, sopsv1alpha1.ReasonDecrypted)
	})

	t.Run("shall report KeyInvalid for an invalid highest key instead of falling back", func(t *testing.T) {
		t.Parallel()
		tenantNS, _ := onboardedTenant(t, "e2e-keys-invalid-tenant")
		createKeySecret(t, tenantNS, secondKeySecret, []byte("not a key"), true)
		waitForMessage(t, tenantOf(t, tenantNS), sopsv1alpha1.ReasonKeyInvalid, secondKeySecret)
	})

	t.Run("shall use a brought key Secret only once it carries the enabled label", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		tenantNS := namespace(t, "e2e-keys-brought-tenant")
		onboard(t, tenantNS)
		keyFile, recipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		createKeySecret(t, tenantNS, firstKeySecret, keyFile, false)
		tenant := &sopsv1alpha1.SopsTenant{
			ObjectMeta: metav1.ObjectMeta{Name: tenantName, Namespace: tenantNS},
			Spec:       sopsv1alpha1.SopsTenantSpec{GenerateKey: new(bool)},
		}
		if err := k8s.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		waitForMessage(t, tenant, sopsv1alpha1.ReasonKeyMissing, sopsv1alpha1.LabelEnabled)
		key := tenantKey(t, tenantNS, firstKeySecret)
		update(t, key, func() { key.Labels = map[string]string{sopsv1alpha1.LabelEnabled: sopsv1alpha1.EnabledValue} })
		waitForImmutableKey(t, tenantNS, firstKeySecret, keyFile, recipient)
		waitForCurrentKey(t, tenantNS, firstKeySecret, recipient)
	})

	t.Run("shall keep the current key after the tenant's status is lost", func(t *testing.T) {
		t.Parallel()
		tenantNS, recipient := onboardedTenant(t, "e2e-keys-status-tenant")
		waitForCurrentKey(t, tenantNS, firstKeySecret, recipient)
		wipeStatus(t, tenantNS)
		waitForCurrentKey(t, tenantNS, firstKeySecret, recipient)
		second := client.ObjectKey{Namespace: tenantNS, Name: secondKeySecret}
		err := k8s.Get(context.Background(), second, &corev1.Secret{})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("got %v, want no second key", err)
		}
	})

	t.Run("shall keep its keys when the tenant is deleted and use them when it is created again", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		tenantNS, recipient := onboardedTenant(t, "e2e-keys-recreate-tenant")
		waitForCurrentKey(t, tenantNS, firstKeySecret, recipient)
		deleteObject(t, tenantOf(t, tenantNS))
		waitUntilDeleted(t, "the SopsTenant", &sopsv1alpha1.SopsTenant{
			ObjectMeta: metav1.ObjectMeta{Name: tenantName, Namespace: tenantNS}})
		if key := tenantKey(t, tenantNS, firstKeySecret); string(key.Data[publicKeyField]) != recipient {
			t.Fatal("the key Secret does not hold the public key while the tenant is gone")
		}
		apply(t, render(t, "sopstenant.yaml", map[string]any{"Name": tenantName, "Namespace": tenantNS}))
		waitForCurrentKey(t, tenantNS, firstKeySecret, recipient)
		second := client.ObjectKey{Namespace: tenantNS, Name: secondKeySecret}
		if err := k8s.Get(ctx, second, &corev1.Secret{}); !apierrors.IsNotFound(err) {
			t.Fatalf("got %v, want no second key", err)
		}
	})

	t.Run("shall not generate a key after the key Secret is deleted while SopsSecrets use the tenant", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		prod := namespace(t, "e2e-keys-used-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-keys-used-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		key := tenantKey(t, tenantNS, firstKeySecret)
		deleteObject(t, key)
		waitUntilDeleted(t, "the key Secret", key)
		tenant := tenantOf(t, tenantNS)
		waitForMessage(t, tenant, sopsv1alpha1.ReasonKeyMissing, "1 SopsSecrets")
		if tenant.Status.PublicKey != "" {
			t.Fatalf("status.publicKey = %q, want none while the key is missing", tenant.Status.PublicKey)
		}
		var keys corev1.SecretList
		if err := k8s.List(ctx, &keys, client.InNamespace(tenantNS)); err != nil {
			t.Fatal(err)
		}
		for _, k := range keys.Items {
			if strings.HasPrefix(k.Name, tenantName+"-sops-keys") {
				t.Fatalf("key Secret %s exists: a new key would decrypt none of the files", k.Name)
			}
		}
	})

	t.Run("shall move a key from v0.0.4 into <tenant>-sops-keys-0 only once it carries the enabled label",
		func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			tenantNS := namespace(t, "e2e-keys-upgrade-tenant")
			onboard(t, tenantNS)
			keyFile, recipient, err := crypto.GenerateKeyFile()
			if err != nil {
				t.Fatal(err)
			}
			legacy := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: legacyKeySecret, Namespace: tenantNS,
					Labels: map[string]string{sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue},
				},
				Data: map[string][]byte{crypto.KeyFileField: keyFile, publicKeyField: []byte(recipient)},
			}
			if err := k8s.Create(ctx, legacy); err != nil {
				t.Fatal(err)
			}
			apply(t, render(t, "sopstenant.yaml", map[string]any{"Name": tenantName, "Namespace": tenantNS}))
			waitForMessage(t, tenantOf(t, tenantNS), sopsv1alpha1.ReasonKeyMissing, sopsv1alpha1.LabelEnabled)
			first := client.ObjectKey{Namespace: tenantNS, Name: firstKeySecret}
			if err := k8s.Get(ctx, first, &corev1.Secret{}); !apierrors.IsNotFound(err) {
				t.Fatalf("got %v, want no key Secret before the label is added", err)
			}
			update(t, legacy, func() { legacy.Labels[sopsv1alpha1.LabelEnabled] = sopsv1alpha1.EnabledValue })
			waitForImmutableKey(t, tenantNS, firstKeySecret, keyFile, recipient)
			waitForCurrentKey(t, tenantNS, firstKeySecret, recipient)
		})
}
