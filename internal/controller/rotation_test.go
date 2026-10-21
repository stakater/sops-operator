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

package controller_test

import (
	"context"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

func TestRotationStart(t *testing.T) {
	t.Run("shall create the next key from a healthy tenant", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "hunter2"})
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)

		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, true)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationPending)

		rot := tenant.Status.Rotation
		if rot == nil || rot.Phase != sopsv1alpha1.RotationPhaseInProgress || rot.StartedAt.IsZero() {
			t.Fatalf("status.rotation = %+v", rot)
		}
		if rot.NextKeySecretName != tenantName+"-sops-keys-next" {
			t.Fatalf("nextKeySecretName = %q", rot.NextKeySecretName)
		}
		next := nextKeySet(t, tenantNS)
		if rot.NextPublicKey != next.Recipients[0] || !strings.HasPrefix(rot.NextPublicKey, "age1pq1") {
			t.Fatal("status.rotation.nextPublicKey does not match the next key Secret")
		}
		if tenant.Status.PublicKey != recipient {
			t.Fatal("status.publicKey does not hold the current key")
		}
	})

	t.Run("shall refuse to start while a SopsSecret is not healthy", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		_, otherRecipient, err := crypto.GenerateKeyFile(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		bad := encryptedSopsSecret(t, otherRecipient, tenantNS, prod, "bad", prod+"/bad", map[string]any{"a": "b"})
		create(t, bad)
		eventuallyReason(t, bad, sopsv1alpha1.ReasonNotRecipient)
		good := encryptedSopsSecret(t, recipient, tenantNS, prod, "good", prod+"/good", map[string]any{"a": "b"})
		create(t, good)
		eventuallyReason(t, good, sopsv1alpha1.ReasonDecrypted)

		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, true)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationRefused)
		if tenant.Status.Rotation != nil {
			t.Fatal("a refused rotation must not record a rotation")
		}
		assertNoSecret(t, tenantNS, sopsv1alpha1.TenantNextKeySecretName(tenantName))
		c := meta.FindStatusCondition(tenant.Status.Conditions, sopsv1alpha1.ConditionRotated)
		if !strings.Contains(c.Message, prod+"/bad") {
			t.Fatalf("message %q does not name the unhealthy SopsSecret", c.Message)
		}
	})

	t.Run("shall start on its own once the tenant is healthy", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		_, otherRecipient, err := crypto.GenerateKeyFile(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		bad := encryptedSopsSecret(t, otherRecipient, tenantNS, prod, "db", prod+"/db", map[string]any{"a": "b"})
		create(t, bad)
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, true)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationRefused)

		fixed := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"a": "b"})
		update(t, bad, func() { bad.Spec, bad.Sops = fixed.Spec, fixed.Sops })
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationPending)
	})

	t.Run("shall adopt a next key created before a crash", func(t *testing.T) {
		tenantNS, _ := onboardedTenant(t)
		keyFile, recipient, err := crypto.GenerateKeyFile(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		orphan := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: sopsv1alpha1.TenantNextKeySecretName(tenantName), Namespace: tenantNS,
				Labels: map[string]string{sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue},
			},
			Data: map[string][]byte{crypto.KeyFileField: keyFile, crypto.PublicKeyField: []byte(recipient)},
		}
		if err := env.Admin.Create(context.Background(), orphan); err != nil {
			t.Fatal(err)
		}
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, true)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationPending)
		if tenant.Status.Rotation.NextPublicKey != recipient {
			t.Fatal("the next key created before the crash was not adopted")
		}
	})

	t.Run("shall report KeyMismatch for a replaced key", func(t *testing.T) {
		tenantNS, _ := onboardedTenant(t)
		tenant := tenantOf(t, tenantNS)
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
			g.Expect(tenant.Status.PublicKey).NotTo(BeEmpty())
		}).WithTimeout(20 * time.Second).Should(Succeed())

		keyFile, recipient, err := crypto.GenerateKeyFile(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		key := &corev1.Secret{}
		if err := env.Admin.Get(context.Background(), client.ObjectKey{Namespace: tenantNS, Name: sopsv1alpha1.TenantKeySecretName(tenantName)}, key); err != nil {
			t.Fatal(err)
		}
		update(t, key, func() {
			key.Data = map[string][]byte{crypto.KeyFileField: keyFile, crypto.PublicKeyField: []byte(recipient)}
		})
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyMismatch)
	})
}
