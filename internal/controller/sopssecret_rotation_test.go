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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

// eventuallyNewRecipient waits until the SopsSecret offers an entry for the new key for its generation.
func eventuallyNewRecipient(t *testing.T, s *sopsv1alpha1.SopsSecret) {
	t.Helper()
	NewWithT(t).Eventually(func(g Gomega) {
		g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(s), s)).To(Succeed())
		g.Expect(s.Status.Rotation).NotTo(BeNil(), "status.rotation")
		g.Expect(s.Status.Rotation.NewRecipient).NotTo(BeNil(), "status.rotation.newRecipient")
		g.Expect(s.Status.Rotation.FromGeneration).To(Equal(s.Generation), "the generation the entry was made for")
	}).WithTimeout(20 * time.Second).Should(Succeed())
}

// eventuallyMigrated waits until the SopsSecret's current generation was decrypted with the new key.
func eventuallyMigrated(t *testing.T, s *sopsv1alpha1.SopsSecret) {
	t.Helper()
	NewWithT(t).Eventually(func(g Gomega) {
		g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(s), s)).To(Succeed())
		g.Expect(s.Status.Rotation).NotTo(BeNil(), "status.rotation")
		g.Expect(s.Status.Rotation.Migrated).To(BeTrue(), "status.rotation.migrated")
		g.Expect(s.Status.Rotation.MigratedGeneration).To(Equal(s.Generation), "the migrated generation")
		g.Expect(s.Status.ObservedGeneration).To(Equal(s.Generation), "the observed generation")
	}).WithTimeout(20 * time.Second).Should(Succeed())
}

// migrate appends the offered new-key entry to the SopsSecret, as a team does in Git.
func migrate(t *testing.T, s *sopsv1alpha1.SopsSecret) {
	t.Helper()
	eventuallyNewRecipient(t, s)
	entry := *s.Status.Rotation.NewRecipient
	update(t, s, func() { s.Sops.Age = append(s.Sops.Age, entry) })
}

func TestSecretRotation(t *testing.T) {
	t.Run("shall offer the new-key entry and keep decrypting with the old key from its backup", func(t *testing.T) {
		tenantNS, _, s, _ := rotatingTenant(t)
		eventuallyNewRecipient(t, s)
		if got, want := s.Status.Rotation.NewRecipient.Recipient, tenantOf(t, tenantNS).Status.PublicKey; got != want {
			t.Fatal("the offered entry is not for the new key in status.publicKey")
		}
		if s.Status.Rotation.AcceptedGeneration != s.Generation {
			t.Fatalf("status.rotation = %+v, want generation %d accepted", s.Status.Rotation, s.Generation)
		}
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
	})

	t.Run("shall count a file with the entry as migrated and keep its Secret", func(t *testing.T) {
		_, prod, s, _ := rotatingTenant(t)
		migrate(t, s)
		eventuallyMigrated(t, s)
		if s.Status.Rotation.NewRecipient != nil {
			t.Fatal("a migrated file is still offered an entry")
		}
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		if string(outputSecret(t, prod).Data["password"]) != hunter2 {
			t.Fatal("the output Secret changed")
		}
	})

	t.Run("shall decrypt a new file encrypted for the new key alone", func(t *testing.T) {
		tenantNS, prod, _, _ := rotatingTenant(t)
		fresh := encryptedSopsSecret(t, tenantOf(t, tenantNS).Status.PublicKey, tenantNS, prod, "new", prod+"/new",
			map[string]any{"a": "b"})
		create(t, fresh)
		eventuallyReason(t, fresh, sopsv1alpha1.ReasonDecrypted)
		eventuallyMigrated(t, fresh)
	})

	t.Run("shall require the new key for a new SopsSecret", func(t *testing.T) {
		tenantNS, prod, _, recipient := rotatingTenant(t)
		fresh := encryptedSopsSecret(t, recipient, tenantNS, prod, "new", prod+"/new", map[string]any{"a": "b"})
		create(t, fresh)
		eventuallyReason(t, fresh, sopsv1alpha1.ReasonNextKeyRequired)
		if c := readyCondition(fresh); !strings.Contains(c.Message, tenantOf(t, tenantNS).Status.PublicKey) {
			t.Fatalf("message %q does not name the new public key", c.Message)
		}
		assertNoSecret(t, prod, "new")
		eventuallyNewRecipient(t, fresh)
	})

	t.Run("shall require the new key for a changed SopsSecret and keep its Secret", func(t *testing.T) {
		tenantNS, prod, s, recipient := rotatingTenant(t)
		eventuallyNewRecipient(t, s)
		changed := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "new"})
		update(t, s, func() { s.Spec, s.Sops = changed.Spec, changed.Sops })
		eventuallyReason(t, s, sopsv1alpha1.ReasonNextKeyRequired)
		if string(outputSecret(t, prod).Data["password"]) != hunter2 {
			t.Fatal("the output Secret must keep its last values")
		}
		eventuallyNewRecipient(t, s)
	})

	t.Run("shall keep accepting an unchanged file after a transient failure", func(t *testing.T) {
		_, _, s, _ := rotatingTenant(t)
		eventuallyNewRecipient(t, s)
		update(t, s, func() { s.Annotations = map[string]string{sopsv1alpha1.AnnotationSuspend: "true"} })
		eventuallyReason(t, s, sopsv1alpha1.ReasonSuspended)
		update(t, s, func() { delete(s.Annotations, sopsv1alpha1.AnnotationSuspend) })
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
	})

	t.Run("shall keep the offered entry unchanged across resyncs", func(t *testing.T) {
		_, _, s, _ := rotatingTenant(t)
		eventuallyNewRecipient(t, s)
		first := s.Status.Rotation.NewRecipient.Enc
		eventuallyResynced(t, s)
		if s.Status.Rotation == nil || s.Status.Rotation.NewRecipient == nil || s.Status.Rotation.NewRecipient.Enc != first {
			t.Fatal("the offered entry changed across a resync")
		}
	})

	t.Run("shall not clear status.rotation in its own reconcile while the tenant has no rotation", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": hunter2})
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		base := s.DeepCopy()
		s.Status.Rotation = &sopsv1alpha1.SecretRotationStatus{StartedAt: metav1.Now(), AcceptedGeneration: s.Generation}
		NewWithT(t).Expect(env.Admin.Status().Patch(context.Background(), s, client.MergeFrom(base))).To(Succeed())
		update(t, s, func() { s.Annotations = map[string]string{"test": "reconcile"} })
		eventuallyResynced(t, s)
		if s.Status.Rotation == nil || s.Status.Rotation.AcceptedGeneration != s.Generation {
			t.Fatalf("status.rotation = %+v was cleared", s.Status.Rotation)
		}
	})
}

func TestSecretRotationWaitingForKey(t *testing.T) {
	t.Run("shall accept a changed file encrypted for the old key while the rotation waits for the new key", func(t *testing.T) {
		tenantNS, s, _, recipient := waitingTenant(t)
		changed := encryptedSopsSecret(t, recipient, tenantNS, s.Namespace, "db", s.Namespace+"/db",
			map[string]any{"password": "new"})
		update(t, s, func() { s.Spec, s.Sops = changed.Spec, changed.Sops })
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(s), s)).To(Succeed())
			c := readyCondition(s)
			g.Expect(c).NotTo(BeNil(), "Ready condition")
			g.Expect(c.Reason).To(Equal(sopsv1alpha1.ReasonDecrypted), "message: %s", c.Message)
			g.Expect(c.ObservedGeneration).To(Equal(s.Generation), "the observed generation")
			g.Expect(s.Status.Rotation).NotTo(BeNil(), "status.rotation")
			g.Expect(s.Status.Rotation.AcceptedGeneration).To(Equal(s.Generation), "the accepted generation")
			g.Expect(s.Status.Rotation.NewRecipient).To(BeNil(), "an entry without a new key")
		}).WithTimeout(20 * time.Second).Should(Succeed())
		if string(outputSecret(t, s.Namespace).Data["password"]) != "new" {
			t.Fatal("the output Secret was not updated")
		}
	})

	t.Run("shall keep decrypting with the old key while the key Secret is deleted", func(t *testing.T) {
		tenantNS, s, _, _ := waitingTenant(t)
		deleteObject(t, tenantKey(t, tenantNS))
		eventuallyResynced(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
	})

	t.Run("shall offer the entry for the tenant admin's key once it is in place", func(t *testing.T) {
		tenantNS, s, _, _ := waitingTenant(t)
		newKey, newRecipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		replaceKey(t, tenantNS, newKey)
		eventuallyNewRecipient(t, s)
		if s.Status.Rotation.NewRecipient.Recipient != newRecipient {
			t.Fatal("the offered entry is not for the tenant admin's key")
		}
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
	})
}
