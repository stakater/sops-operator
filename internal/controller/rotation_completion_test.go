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
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/controller"
	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/identity"
)

// eventuallyPending waits until the tenant's rotation lists exactly the given SopsSecrets as pending.
func eventuallyPending(t *testing.T, tenant *sopsv1alpha1.SopsTenant, pending ...string) {
	t.Helper()
	NewWithT(t).Eventually(func(g Gomega) {
		g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
		g.Expect(tenant.Status.Rotation).NotTo(BeNil(), "status.rotation")
		g.Expect(tenant.Status.Rotation.PendingSecrets).To(Equal(pending), "status.rotation.pendingSecrets")
	}).WithTimeout(20 * time.Second).Should(Succeed())
}

// eventuallyRotationCleared waits until the SopsSecret has no rotation status.
func eventuallyRotationCleared(t *testing.T, s *sopsv1alpha1.SopsSecret) {
	t.Helper()
	NewWithT(t).Eventually(func(g Gomega) {
		g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(s), s)).To(Succeed())
		g.Expect(s.Status.Rotation).To(BeNil(), "status.rotation of the SopsSecret")
	}).WithTimeout(20 * time.Second).Should(Succeed())
}

func TestRotationCompletion(t *testing.T) {
	t.Run("shall report pending SopsSecrets, block completion and refuse to abandon after a migration", func(t *testing.T) {
		tenantNS, prod, s, recipient := rotatingTenant(t)
		other := encryptedSopsSecret(t, recipient, tenantNS, prod, "other", prod+"/other", map[string]any{"a": "b"})
		create(t, other)
		eventuallyReason(t, other, sopsv1alpha1.ReasonNextKeyRequired)
		migrate(t, s)
		eventuallyMigrated(t, s)

		tenant := tenantOf(t, tenantNS)
		newRecipient := tenant.Status.PublicKey
		setStartRotation(t, tenant, false)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationBlocked)
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
			g.Expect(tenant.Status.Rotation).NotTo(BeNil(), "status.rotation")
			g.Expect(tenant.Status.Rotation.Migrated).To(Equal(int32(1)), "migrated")
			g.Expect(tenant.Status.Rotation.Pending).To(Equal(int32(1)), "pending")
			g.Expect(tenant.Status.Rotation.PendingSecrets).To(Equal([]string{prod + "/other"}), "pendingSecrets")
		}).WithTimeout(20 * time.Second).Should(Succeed())
		c := meta.FindStatusCondition(tenant.Status.Conditions, sopsv1alpha1.ConditionRotated)
		if !strings.Contains(c.Message, "abandon") || !strings.Contains(c.Message, prod+"/other") {
			t.Fatalf("message %q does not name the pending SopsSecret and why the rotation cannot be abandoned", c.Message)
		}
		if tenant.Status.PublicKey != newRecipient {
			t.Fatal("status.publicKey no longer holds the new key")
		}
		eventuallyBackups(t, tenantNS, recipient, newRecipient)
	})

	t.Run("shall delete the old key's backup once every SopsSecret uses the new key", func(t *testing.T) {
		tenantNS, prod, s, oldRecipient := rotatingTenant(t)
		tenant := tenantOf(t, tenantNS)
		started, newRecipient := tenant.Status.Rotation.StartedAt, tenant.Status.PublicKey
		newKey := tenantKey(t, tenantNS).Data[crypto.KeyFileField]
		migrate(t, s)
		eventuallyMigrated(t, s)
		setStartRotation(t, tenant, false)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationComplete)

		if c := meta.FindStatusCondition(tenant.Status.Conditions, sopsv1alpha1.ConditionRotated); c.Status != metav1.ConditionTrue {
			t.Fatalf("Rotated = %s, want True", c.Status)
		}
		if tenant.Status.Rotation != nil || tenant.Status.PublicKey != newRecipient {
			t.Fatalf("status after completion: publicKey %q, rotation %+v", tenant.Status.PublicKey, tenant.Status.Rotation)
		}
		last := tenant.Status.LastRotation
		if last == nil || !last.StartedAt.Equal(&started) || last.CompletedAt.IsZero() || last.PreviousPublicKey != oldRecipient {
			t.Fatalf("status.lastRotation = %+v", last)
		}
		if !bytes.Equal(tenantKey(t, tenantNS).Data[crypto.KeyFileField], newKey) {
			t.Fatal("the key Secret does not hold the new key")
		}
		eventuallyBackups(t, tenantNS, newRecipient)
		eventuallyRotationCleared(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		if string(outputSecret(t, prod).Data["password"]) != hunter2 {
			t.Fatal("completion changed the output Secret")
		}
		eventuallyEvent(t, tenantNS, tenant.UID, sopsv1alpha1.ReasonRotationComplete, corev1.EventTypeNormal,
			sopsv1alpha1.ActionCompleteRotation)
	})

	t.Run("shall stay in progress while startRotation is true", func(t *testing.T) {
		tenantNS, _, s, oldRecipient := rotatingTenant(t)
		migrate(t, s)
		tenant := tenantOf(t, tenantNS)
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
			g.Expect(tenant.Status.Rotation).NotTo(BeNil(), "status.rotation")
			g.Expect(tenant.Status.Rotation.Pending).To(BeZero(), "pending")
		}).WithTimeout(20 * time.Second).Should(Succeed())
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationPending)
		eventuallyBackups(t, tenantNS, oldRecipient, tenant.Status.PublicKey)
	})

	t.Run("shall finish a completion that stopped after deleting the old key's backup", func(t *testing.T) {
		tenantNS, _, s, oldRecipient := rotatingTenant(t)
		migrate(t, s)
		eventuallyMigrated(t, s)
		for _, b := range keyBackups(t, tenantNS) {
			if b.Annotations[sopsv1alpha1.AnnotationPublicKey] == oldRecipient {
				deleteObject(t, &b)
			}
		}
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, false)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationComplete)
		if tenant.Status.LastRotation == nil || tenant.Status.LastRotation.PreviousPublicKey != oldRecipient {
			t.Fatalf("status.lastRotation = %+v", tenant.Status.LastRotation)
		}
		eventuallyBackups(t, tenantNS, tenant.Status.PublicKey)
	})
}

func TestRotationAbandon(t *testing.T) {
	t.Run("shall restore the old key and delete the new key's backup before any SopsSecret migrated", func(t *testing.T) {
		tenantNS, prod, s, oldRecipient := rotatingTenant(t)
		eventuallyNewRecipient(t, s)
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, false)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationAbandoned)
		if tenant.Status.Rotation != nil || tenant.Status.PublicKey != oldRecipient {
			t.Fatalf("status after abandon: publicKey %q, rotation %+v", tenant.Status.PublicKey, tenant.Status.Rotation)
		}
		if got := keyRecipient(t, tenantKey(t, tenantNS).Data[crypto.KeyFileField]); got != oldRecipient {
			t.Fatal("the key Secret does not hold the old key")
		}
		eventuallyBackups(t, tenantNS, oldRecipient)
		eventuallyRotationCleared(t, s)
		eventuallyResynced(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		if string(outputSecret(t, prod).Data["password"]) != hunter2 {
			t.Fatal("abandoning changed the output Secret")
		}
		eventuallyEvent(t, tenantNS, tenant.UID, sopsv1alpha1.ReasonRotationAbandoned, corev1.EventTypeNormal,
			sopsv1alpha1.ActionAbandonRotation)
	})

	t.Run("shall abandon a rotation that waits for the tenant admin's key", func(t *testing.T) {
		tenantNS, s, oldKey, oldRecipient := waitingTenant(t)
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, false)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationAbandoned)
		if tenant.Status.Rotation != nil || tenant.Status.PublicKey != oldRecipient {
			t.Fatalf("status after abandon: publicKey %q, rotation %+v", tenant.Status.PublicKey, tenant.Status.Rotation)
		}
		eventuallyKeyFile(t, tenantNS, oldKey)
		eventuallyBackups(t, tenantNS, oldRecipient)
		eventuallyRotationCleared(t, s)
	})

	t.Run("shall start a new rotation after an abandoned one", func(t *testing.T) {
		tenantNS, _, s, oldRecipient := rotatingTenant(t)
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, false)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationAbandoned)
		eventuallyRotationCleared(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		setStartRotation(t, tenant, true)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationPending)
		if tenant.Status.Rotation.PreviousPublicKey != oldRecipient || tenant.Status.PublicKey == oldRecipient {
			t.Fatalf("status after the new start: publicKey %q, rotation %+v", tenant.Status.PublicKey, tenant.Status.Rotation)
		}
		eventuallyBackups(t, tenantNS, oldRecipient, tenant.Status.PublicKey)
	})
}

func TestRotationGuards(t *testing.T) {
	t.Run("shall keep a SopsSecret pending whose new generation is suspended after it was migrated", func(t *testing.T) {
		tenantNS, prod, s, oldRecipient := rotatingTenant(t)
		migrate(t, s)
		eventuallyMigrated(t, s)
		update(t, s, func() {
			s.Annotations = map[string]string{sopsv1alpha1.AnnotationSuspend: "true"}
			s.Spec.Template.Metadata.Labels = map[string]string{"changed": "true"}
		})
		eventuallyReason(t, s, sopsv1alpha1.ReasonSuspended)
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, false)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationBlocked)
		eventuallyPending(t, tenant, prod+"/db")
		eventuallyBackups(t, tenantNS, oldRecipient, tenant.Status.PublicKey)
	})

	t.Run("shall keep a SopsSecret pending whose new generation fails after it was migrated", func(t *testing.T) {
		tenantNS, prod, s, _ := rotatingTenant(t)
		migrate(t, s)
		eventuallyMigrated(t, s)
		_, otherRecipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		foreign := encryptedSopsSecret(t, otherRecipient, tenantNS, prod, "db", prod+"/db", map[string]any{"a": "b"})
		update(t, s, func() { s.Spec, s.Sops = foreign.Spec, foreign.Sops })
		eventuallyReason(t, s, sopsv1alpha1.ReasonNotRecipient)
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, false)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationBlocked)
		eventuallyPending(t, tenant, prod+"/db")
	})
}

func TestRotationCompletionLiveList(t *testing.T) {
	t.Run("shall block completion on a SopsSecret that only the cache shows as migrated", func(t *testing.T) {
		ctx := context.Background()
		tenantNS, prod, s, oldRecipient := rotatingTenant(t)
		migrate(t, s)
		eventuallyMigrated(t, s)
		cached := []sopsv1alpha1.SopsSecret{*s.DeepCopy()}
		reapplied := encryptedSopsSecret(t, oldRecipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "changed"})
		update(t, s, func() { s.Spec, s.Sops = reapplied.Spec, reapplied.Sops })

		tenant := tenantOf(t, tenantNS)
		newRecipient := tenant.Status.PublicKey
		tenant.Spec.StartRotation = false
		r := &controller.SopsTenantReconciler{
			Client: env.Admin, APIReader: env.Admin, Identities: identity.NewFactory(env.OperatorConfig, env.Scheme),
			Recorder: events.NewFakeRecorder(10),
		}
		if err := r.ReconcileRotationForTest(ctx, tenant, cached); err != nil {
			t.Fatal(err)
		}
		c := meta.FindStatusCondition(tenant.Status.Conditions, sopsv1alpha1.ConditionRotated)
		if c == nil || c.Status != metav1.ConditionFalse || c.Reason != sopsv1alpha1.ReasonRotationBlocked {
			t.Fatalf("Rotated condition = %+v, want False/%s", c, sopsv1alpha1.ReasonRotationBlocked)
		}
		if got := tenant.Status.Rotation.PendingSecrets; len(got) != 1 || got[0] != prod+"/db" {
			t.Fatalf("pendingSecrets = %v, want [%s/db]", got, prod)
		}
		eventuallyBackups(t, tenantNS, oldRecipient, newRecipient)
	})
}
