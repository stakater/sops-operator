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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
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
		eventuallyReason(t, bad, sopsv1alpha1.ReasonNotRecipient)
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
		if err := env.Admin.Get(context.Background(), client.ObjectKeyFromObject(orphan), orphan); err != nil {
			t.Fatal(err)
		}
		if !tenant.Status.Rotation.StartedAt.Equal(&orphan.CreationTimestamp) {
			t.Fatalf("startedAt = %v, want the orphan's creationTimestamp %v",
				tenant.Status.Rotation.StartedAt, orphan.CreationTimestamp)
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

func TestRotationStartEdges(t *testing.T) {
	t.Run("shall drop the refusal when the flag is cleared", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, _ := onboardedTenant(t, prod)
		_, otherRecipient, err := crypto.GenerateKeyFile(time.Now())
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
			g.Expect(meta.FindStatusCondition(tenant.Status.Conditions, sopsv1alpha1.ConditionRotated)).To(BeNil())
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(Succeed())
	})

	t.Run("shall replace a corrupt unpublished next key", func(t *testing.T) {
		tenantNS, _ := onboardedTenant(t)
		orphan := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: sopsv1alpha1.TenantNextKeySecretName(tenantName), Namespace: tenantNS,
				Labels: map[string]string{sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue},
			},
			Data: map[string][]byte{crypto.KeyFileField: []byte("not a key")},
		}
		if err := env.Admin.Create(context.Background(), orphan); err != nil {
			t.Fatal(err)
		}
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, true)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationPending)
		if tenant.Status.Rotation.NextPublicKey != nextKeySet(t, tenantNS).Recipients[0] {
			t.Fatal("status.rotation.nextPublicKey does not match the fresh next key")
		}
	})

	t.Run("shall refuse a next key the operator did not create", func(t *testing.T) {
		tenantNS, _ := onboardedTenant(t)
		keyFile, recipient, err := crypto.GenerateKeyFile(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		foreign := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: sopsv1alpha1.TenantNextKeySecretName(tenantName), Namespace: tenantNS},
			Data:       map[string][]byte{crypto.KeyFileField: keyFile, crypto.PublicKeyField: []byte(recipient)},
		}
		if err := env.Admin.Create(context.Background(), foreign); err != nil {
			t.Fatal(err)
		}
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, true)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationRefused)
		if tenant.Status.Rotation != nil {
			t.Fatal("a refused rotation must not record a rotation")
		}
		_ = nextKeySet(t, tenantNS) // still there
	})

	t.Run("shall delete an unpublished next key when no rotation is asked for", func(t *testing.T) {
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
		NewWithT(t).Eventually(func(g Gomega) {
			err := env.Admin.Get(context.Background(), client.ObjectKeyFromObject(orphan), &corev1.Secret{})
			g.Expect(apierrors.IsNotFound(err)).To(BeTrue())
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(Succeed())
	})

	t.Run("shall not generate a key while the next key exists", func(t *testing.T) {
		tenantNS, _ := onboardedTenant(t)
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, true)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationPending)

		keyName := sopsv1alpha1.TenantKeySecretName(tenantName)
		key := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: keyName, Namespace: tenantNS}}
		if err := env.Admin.Delete(context.Background(), key); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyMissing)
		assertNoSecret(t, tenantNS, keyName)
	})

	t.Run("shall regenerate a deleted key and load it", func(t *testing.T) {
		tenantNS, recipient := onboardedTenant(t)
		tenant := tenantOf(t, tenantNS)
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
			g.Expect(tenant.Status.PublicKey).To(Equal(recipient))
		}).WithTimeout(20 * time.Second).Should(Succeed())

		keyName := sopsv1alpha1.TenantKeySecretName(tenantName)
		if err := env.Admin.Delete(context.Background(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: keyName, Namespace: tenantNS}}); err != nil {
			t.Fatal(err)
		}
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
			c := meta.FindStatusCondition(tenant.Status.Conditions, sopsv1alpha1.ConditionReady)
			g.Expect(c).NotTo(BeNil())
			g.Expect(c.Reason).To(Equal(sopsv1alpha1.ReasonKeyLoaded), c.Message)
			g.Expect(tenant.Status.PublicKey).NotTo(Equal(recipient))
			g.Expect(tenant.Status.PublicKey).NotTo(BeEmpty())
		}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(Succeed())
	})

	t.Run("shall load a bring-your-own key created after the old one was deleted", func(t *testing.T) {
		tenantNS, _ := onboardedTenant(t)
		tenant := tenantOf(t, tenantNS)
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
			g.Expect(tenant.Status.PublicKey).NotTo(BeEmpty())
		}).WithTimeout(20 * time.Second).Should(Succeed())
		update(t, tenant, func() { tenant.Spec.GenerateKey = ptr.To(false) })

		keyName := sopsv1alpha1.TenantKeySecretName(tenantName)
		if err := env.Admin.Delete(context.Background(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: keyName, Namespace: tenantNS}}); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyMissing)

		keyFile, recipient, err := crypto.GenerateKeyFile(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := env.Admin.Create(context.Background(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: keyName, Namespace: tenantNS},
			Data:       map[string][]byte{crypto.KeyFileField: keyFile, crypto.PublicKeyField: []byte(recipient)},
		}); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyLoaded)
		if tenant.Status.PublicKey != recipient {
			t.Fatal("status.publicKey does not hold the brought key")
		}
	})
}

// migrate appends the offered next-key entry to the SopsSecret, as a team does in Git.
func migrate(t *testing.T, s *sopsv1alpha1.SopsSecret) {
	t.Helper()
	eventuallyNextRecipient(t, s)
	entry := *s.Status.Rotation.NextRecipient
	update(t, s, func() { s.Sops.Age = append(s.Sops.Age, entry) })
}

func TestRotationCompletion(t *testing.T) {
	t.Run("shall report pending SopsSecrets and block completion until they are migrated", func(t *testing.T) {
		tenantNS, prod, s, recipient := rotatingTenant(t)
		// "other" is created after the start, so it is pending (NextKeyRequired) until migrated.
		other := encryptedSopsSecret(t, recipient, tenantNS, prod, "other", prod+"/other", map[string]any{"a": "b"})
		create(t, other)
		migrate(t, s)

		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, false)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationBlocked)
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
			g.Expect(tenant.Status.Rotation.Migrated).To(Equal(int32(1)))
			g.Expect(tenant.Status.Rotation.Pending).To(Equal(int32(1)))
			g.Expect(tenant.Status.Rotation.PendingSecrets).To(Equal([]string{prod + "/other"}))
		}).WithTimeout(20 * time.Second).Should(Succeed())
	})

	t.Run("shall replace the key once every SopsSecret uses the next key", func(t *testing.T) {
		tenantNS, prod, s, oldRecipient := rotatingTenant(t)
		next := nextKeySet(t, tenantNS)
		started := tenantOf(t, tenantNS).Status.Rotation.StartedAt
		migrate(t, s)
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, false)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationComplete)

		if tenant.Status.Rotation != nil || tenant.Status.PublicKey != next.Recipients[0] {
			t.Fatalf("status after completion: publicKey %q, rotation %+v", tenant.Status.PublicKey, tenant.Status.Rotation)
		}
		last := tenant.Status.LastRotation
		if last == nil || !last.StartedAt.Equal(&started) || last.CompletedAt.IsZero() || last.PreviousPublicKey != oldRecipient {
			t.Fatalf("status.lastRotation = %+v", last)
		}
		var key corev1.Secret
		if err := env.Admin.Get(context.Background(), client.ObjectKey{Namespace: tenantNS, Name: sopsv1alpha1.TenantKeySecretName(tenantName)}, &key); err != nil {
			t.Fatal(err)
		}
		ks, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
		if err != nil {
			t.Fatal(err)
		}
		if len(ks.Recipients) != 1 || ks.Recipients[0] != next.Recipients[0] ||
			strings.TrimSpace(string(key.Data[crypto.PublicKeyField])) != next.Recipients[0] {
			t.Fatal("the key Secret does not hold exactly the next key")
		}
		assertNoSecret(t, tenantNS, sopsv1alpha1.TenantNextKeySecretName(tenantName))
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(s), s)).To(Succeed())
			g.Expect(s.Status.Rotation).To(BeNil())
		}).WithTimeout(20 * time.Second).Should(Succeed())
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		if string(outputSecret(t, prod).Data["password"]) != hunter2 {
			t.Fatal("completion changed the output Secret")
		}
	})

	t.Run("shall finish a completion that stopped after replacing the key", func(t *testing.T) {
		tenantNS, _, s, _ := rotatingTenant(t)
		migrate(t, s)
		// Simulate a crash after step 3: the key Secret already holds the next key, the status does not know.
		var next, key corev1.Secret
		if err := env.Admin.Get(context.Background(), client.ObjectKey{Namespace: tenantNS, Name: sopsv1alpha1.TenantNextKeySecretName(tenantName)}, &next); err != nil {
			t.Fatal(err)
		}
		key.Namespace, key.Name = tenantNS, sopsv1alpha1.TenantKeySecretName(tenantName)
		update(t, &key, func() { key.Data = next.Data })
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, false)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationComplete)
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyLoaded)
		assertNoSecret(t, tenantNS, sopsv1alpha1.TenantNextKeySecretName(tenantName))
	})

	t.Run("shall stay in progress while startRotation is true", func(t *testing.T) {
		tenantNS, _, s, _ := rotatingTenant(t)
		migrate(t, s)
		tenant := tenantOf(t, tenantNS)
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
			g.Expect(tenant.Status.Rotation).NotTo(BeNil())
			g.Expect(tenant.Status.Rotation.Pending).To(BeZero())
		}).WithTimeout(20 * time.Second).Should(Succeed())
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationPending)
	})

	t.Run("shall abandon a rotation whose next key was lost", func(t *testing.T) {
		tenantNS, _, s, _ := rotatingTenant(t)
		deleteObject(t, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: tenantNS, Name: sopsv1alpha1.TenantNextKeySecretName(tenantName)}})
		tenant := tenantOf(t, tenantNS)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonNextKeyMissing)
		setStartRotation(t, tenant, false)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationAbandoned)
		if tenant.Status.Rotation != nil {
			t.Fatal("an abandoned rotation must be cleared")
		}
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(s), s)).To(Succeed())
			g.Expect(s.Status.Rotation).To(BeNil())
		}).WithTimeout(20 * time.Second).Should(Succeed())
	})

	t.Run("shall not abandon while a SopsSecret needs the next key", func(t *testing.T) {
		tenantNS, prod, _, _ := rotatingTenant(t)
		nextOnly := encryptedSopsSecret(t, tenantOf(t, tenantNS).Status.Rotation.NextPublicKey, tenantNS, prod,
			"next-only", prod+"/next-only", map[string]any{"a": "b"})
		create(t, nextOnly)
		eventuallyReason(t, nextOnly, sopsv1alpha1.ReasonDecrypted)
		deleteObject(t, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: tenantNS, Name: sopsv1alpha1.TenantNextKeySecretName(tenantName)}})
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, false)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonNextKeyMissing)
		c := meta.FindStatusCondition(tenant.Status.Conditions, sopsv1alpha1.ConditionRotated)
		if !strings.Contains(c.Message, prod+"/next-only") {
			t.Fatalf("message %q does not name the SopsSecret that needs the next key", c.Message)
		}
	})
}
