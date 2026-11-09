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
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

const hunter2 = "hunter2"

// rotatingTenant returns a tenant namespace in rotation with one Decrypted SopsSecret "db", and the old
// key's public key.
func rotatingTenant(t *testing.T) (tenantNS string, s *sopsv1alpha1.SopsSecret, recipient string) {
	t.Helper()
	prod := env.Namespace(t, "prod")
	tenantNS, recipient = onboardedTenant(t, prod)
	s = encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": hunter2})
	create(t, s)
	eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
	tenant := tenantOf(t, tenantNS)
	setStartRotation(t, tenant, true)
	eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationPending)
	return tenantNS, s, recipient
}

// waitingTenant returns a tenant namespace with generateKey false and one Decrypted SopsSecret whose
// rotation waits for the tenant admin's key, and the old key file and its public key.
func waitingTenant(t *testing.T) (tenantNS string, oldKey []byte, recipient string) {
	t.Helper()
	prod := env.Namespace(t, "prod")
	tenantNS, recipient = onboardedTenant(t, prod)
	oldKey = tenantKey(t, tenantNS).Data[crypto.KeyFileField]
	s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": hunter2})
	create(t, s)
	eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
	tenant := tenantOf(t, tenantNS)
	update(t, tenant, func() {
		tenant.Spec.GenerateKey = ptr.To(false)
		tenant.Spec.StartRotation = true
	})
	eventuallyRotated(t, tenant, sopsv1alpha1.ReasonWaitingForKey)
	return tenantNS, oldKey, recipient
}

// replaceKey stands in for the tenant admin deleting the key Secret and creating it with keyFile.
func replaceKey(t *testing.T, tenantNS string, keyFile []byte) {
	t.Helper()
	deleteObject(t, tenantKey(t, tenantNS))
	if err := env.Admin.Create(context.Background(), keySecret(tenantNS, string(keyFile))); err != nil {
		t.Fatal(err)
	}
}

func TestRotationStart(t *testing.T) {
	t.Run("shall generate the new key, back it up and place it in the key Secret", func(t *testing.T) {
		tenantNS, _, oldRecipient := rotatingTenant(t)
		tenant := tenantOf(t, tenantNS)
		rot := tenant.Status.Rotation
		if rot == nil || rot.Phase != sopsv1alpha1.RotationPhaseInProgress || rot.StartedAt.IsZero() {
			t.Fatalf("status.rotation = %+v, want phase InProgress with startedAt", rot)
		}
		if rot.PreviousPublicKey != oldRecipient {
			t.Fatalf("status.rotation.previousPublicKey = %q, want the old key %q", rot.PreviousPublicKey, oldRecipient)
		}
		key := tenantKey(t, tenantNS)
		assertOnlyKeyFile(t, key)
		newRecipient := keyRecipient(t, key.Data[crypto.KeyFileField])
		if newRecipient == oldRecipient || !strings.HasPrefix(newRecipient, "age1pq1") {
			t.Fatalf("the key Secret holds %q, want a new post-quantum key", newRecipient)
		}
		if tenant.Status.PublicKey != newRecipient {
			t.Fatalf("status.publicKey = %q, want the new key %q", tenant.Status.PublicKey, newRecipient)
		}
		for _, b := range eventuallyBackups(t, tenantNS, oldRecipient, newRecipient) {
			if b.Annotations[sopsv1alpha1.AnnotationPublicKey] == newRecipient &&
				!bytes.Equal(b.Data[crypto.KeyFileField], key.Data[crypto.KeyFileField]) {
				t.Fatal("the new key's backup does not hold the key of the key Secret")
			}
		}
		eventuallyEvent(t, tenantNS, tenant.UID, sopsv1alpha1.ReasonRotationPending, corev1.EventTypeNormal,
			sopsv1alpha1.ActionStartRotation)
	})

	t.Run("shall stamp the generation each SopsSecret had at the start as accepted", func(t *testing.T) {
		tenantNS, s, _ := rotatingTenant(t)
		started := tenantOf(t, tenantNS).Status.Rotation.StartedAt
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(s), s)).To(Succeed())
			g.Expect(s.Status.Rotation).NotTo(BeNil(), "status.rotation of the SopsSecret")
			g.Expect(s.Status.Rotation.StartedAt.Equal(&started)).To(BeTrue(), "startedAt matches the tenant's")
			g.Expect(s.Status.Rotation.AcceptedGeneration).To(Equal(s.Generation), "accepted generation")
		}).WithTimeout(20 * time.Second).Should(Succeed())
	})

	t.Run("shall refuse to start while a SopsSecret is not healthy", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		_, otherRecipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		bad := encryptedSopsSecret(t, otherRecipient, tenantNS, prod, "bad", prod+"/bad", map[string]any{"a": "b"})
		create(t, bad)
		eventuallyReason(t, bad, sopsv1alpha1.ReasonNotRecipient)
		good := encryptedSopsSecret(t, recipient, tenantNS, prod, "good", prod+"/good", map[string]any{"a": "b"})
		create(t, good)
		eventuallyReason(t, good, sopsv1alpha1.ReasonDecrypted)
		key := tenantKey(t, tenantNS)

		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, true)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationRefused)
		if tenant.Status.Rotation != nil {
			t.Fatal("a refused rotation must not record a rotation")
		}
		if c := meta.FindStatusCondition(tenant.Status.Conditions, sopsv1alpha1.ConditionRotated); !strings.Contains(c.Message, prod+"/bad") {
			t.Fatalf("message %q does not name the unhealthy SopsSecret", c.Message)
		}
		assertUnchanged(t, key)
		eventuallyBackups(t, tenantNS, recipient)
	})

	t.Run("shall start on its own once the tenant is healthy", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		_, otherRecipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		bad := encryptedSopsSecret(t, otherRecipient, tenantNS, prod, "db", prod+"/db", map[string]any{"a": "b"})
		create(t, bad)
		eventuallyReason(t, bad, sopsv1alpha1.ReasonNotRecipient)
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, true)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationRefused)

		fixed := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"a": "b"})
		update(t, bad, func() { bad.Spec, bad.Sops = fixed.Spec, fixed.Sops })
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationPending)
	})

	t.Run("shall drop the refusal when the flag is cleared", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, _ := onboardedTenant(t, prod)
		_, otherRecipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		bad := encryptedSopsSecret(t, otherRecipient, tenantNS, prod, "db", prod+"/db", map[string]any{"a": "b"})
		create(t, bad)
		eventuallyReason(t, bad, sopsv1alpha1.ReasonNotRecipient)
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, true)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationRefused)

		setStartRotation(t, tenant, false)
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
			g.Expect(meta.FindStatusCondition(tenant.Status.Conditions, sopsv1alpha1.ConditionRotated)).To(BeNil(),
				"Rotated condition after the flag was cleared")
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(Succeed())
	})

	t.Run("shall restore the new key into a deleted key Secret during a rotation", func(t *testing.T) {
		tenantNS, _, _ := rotatingTenant(t)
		key := tenantKey(t, tenantNS)
		deleteObject(t, key)
		eventuallyKeyFile(t, tenantNS, key.Data[crypto.KeyFileField])
		if got := tenantOf(t, tenantNS).Status.PublicKey; got != keyRecipient(t, key.Data[crypto.KeyFileField]) {
			t.Fatalf("status.publicKey = %q, want the new key", got)
		}
	})

	t.Run("shall restore the new key into a changed key Secret during a rotation", func(t *testing.T) {
		tenantNS, _, _ := rotatingTenant(t)
		key := tenantKey(t, tenantNS)
		newKey := key.Data[crypto.KeyFileField]
		other, _, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		update(t, key, func() { key.Data[crypto.KeyFileField] = other })
		eventuallyKeyFile(t, tenantNS, newKey)
	})
}

func TestRotationWithTenantKey(t *testing.T) {
	t.Run("shall wait for the tenant admin's key with generateKey false and keep the old key", func(t *testing.T) {
		tenantNS, oldKey, oldRecipient := waitingTenant(t)
		tenant := tenantOf(t, tenantNS)
		rot := tenant.Status.Rotation
		if rot == nil || rot.Phase != sopsv1alpha1.RotationPhaseWaitingForKey || rot.PreviousPublicKey != oldRecipient {
			t.Fatalf("status.rotation = %+v, want phase WaitingForKey with the old key", rot)
		}
		if tenant.Status.PublicKey != oldRecipient {
			t.Fatalf("status.publicKey = %q, want the old key until the new key is in place", tenant.Status.PublicKey)
		}
		c := meta.FindStatusCondition(tenant.Status.Conditions, sopsv1alpha1.ConditionRotated)
		if c.Status != metav1.ConditionFalse || !strings.Contains(c.Message, sopsv1alpha1.TenantKeySecretName(tenantName)) {
			t.Fatalf("Rotated = %s %q, want False naming the key Secret to replace", c.Status, c.Message)
		}
		NewWithT(t).Consistently(func() []byte {
			return tenantKey(t, tenantNS).Data[crypto.KeyFileField]
		}).WithTimeout(2*resync).WithPolling(200*time.Millisecond).Should(Equal(oldKey), "the key Secret keeps the old key")
		eventuallyBackups(t, tenantNS, oldRecipient)
	})

	t.Run("shall take a recreated key Secret as the new key and back it up", func(t *testing.T) {
		tenantNS, _, oldRecipient := waitingTenant(t)
		newKey, newRecipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		replaceKey(t, tenantNS, newKey)
		tenant := tenantOf(t, tenantNS)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationPending)
		if tenant.Status.PublicKey != newRecipient || tenant.Status.Rotation.Phase != sopsv1alpha1.RotationPhaseInProgress {
			t.Fatalf("status.publicKey %q, rotation %+v, want the new key in progress", tenant.Status.PublicKey, tenant.Status.Rotation)
		}
		if tenant.Status.Rotation.PreviousPublicKey != oldRecipient {
			t.Fatalf("previousPublicKey = %q, want the old key", tenant.Status.Rotation.PreviousPublicKey)
		}
		eventuallyBackups(t, tenantNS, oldRecipient, newRecipient)
		NewWithT(t).Consistently(func() []byte {
			return tenantKey(t, tenantNS).Data[crypto.KeyFileField]
		}).WithTimeout(2*resync).WithPolling(200*time.Millisecond).Should(Equal(newKey), "the key Secret keeps the new key")
	})

	t.Run("shall take an updated key Secret as the new key", func(t *testing.T) {
		tenantNS, _, oldRecipient := waitingTenant(t)
		newKey, newRecipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		key := tenantKey(t, tenantNS)
		update(t, key, func() { key.Data[crypto.KeyFileField] = newKey })
		eventuallyRotated(t, tenantOf(t, tenantNS), sopsv1alpha1.ReasonRotationPending)
		eventuallyBackups(t, tenantNS, oldRecipient, newRecipient)
	})

	t.Run("shall keep waiting while the key Secret is deleted", func(t *testing.T) {
		tenantNS, _, oldRecipient := waitingTenant(t)
		deleteObject(t, tenantKey(t, tenantNS))
		tenant := tenantOf(t, tenantNS)
		NewWithT(t).Consistently(func(g Gomega) {
			g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
			g.Expect(tenant.Status.Rotation).NotTo(BeNil(), "status.rotation")
			g.Expect(tenant.Status.Rotation.Phase).To(Equal(sopsv1alpha1.RotationPhaseWaitingForKey))
			g.Expect(tenant.Status.PublicKey).To(Equal(oldRecipient))
		}).WithTimeout(2 * resync).WithPolling(200 * time.Millisecond).Should(Succeed())
		eventuallyBackups(t, tenantNS, oldRecipient)
	})
}
