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
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

const hunter2 = "hunter2"

// rotatingTenant returns a tenant namespace in rotation with one Decrypted SopsSecret "db" in prod.
func rotatingTenant(t *testing.T) (tenantNS, prod string, s *sopsv1alpha1.SopsSecret, recipient string) {
	t.Helper()
	prod = env.Namespace(t, "prod")
	tenantNS, recipient = onboardedTenant(t, prod)
	s = encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": hunter2})
	create(t, s)
	eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
	tenant := tenantOf(t, tenantNS)
	setStartRotation(t, tenant, true)
	eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationPending)
	return tenantNS, prod, s, recipient
}

// eventuallyNextRecipient waits until the SopsSecret offers an entry for the next key.
func eventuallyNextRecipient(t *testing.T, s *sopsv1alpha1.SopsSecret) {
	t.Helper()
	NewWithT(t).Eventually(func(g Gomega) {
		g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(s), s)).To(Succeed())
		g.Expect(s.Status.Rotation).NotTo(BeNil())
		g.Expect(s.Status.Rotation.NextRecipient).NotTo(BeNil())
		g.Expect(s.Status.Rotation.FromGeneration).To(Equal(s.Generation))
	}).WithTimeout(20 * time.Second).Should(Succeed())
}

func TestSecretRotation(t *testing.T) {
	t.Run("shall offer the next-key entry and keep decrypting with the current key", func(t *testing.T) {
		tenantNS, _, s, _ := rotatingTenant(t)
		eventuallyNextRecipient(t, s)
		next := nextKeySet(t, tenantNS)
		if s.Status.Rotation.NextRecipient.Recipient != next.Recipients[0] {
			t.Fatal("the entry is not for the next key")
		}
		if s.Status.Rotation.AcceptedGeneration != s.Generation {
			t.Fatalf("status.rotation = %+v, generation %d", s.Status.Rotation, s.Generation)
		}
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
	})

	t.Run("shall count a file with the entry as migrated", func(t *testing.T) {
		_, prod, s, _ := rotatingTenant(t)
		eventuallyNextRecipient(t, s)
		entry := *s.Status.Rotation.NextRecipient
		update(t, s, func() { s.Sops.Age = append(s.Sops.Age, entry) })
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(s), s)).To(Succeed())
			g.Expect(s.Status.Rotation).NotTo(BeNil())
			g.Expect(s.Status.Rotation.Migrated).To(BeTrue())
			g.Expect(s.Status.ObservedGeneration).To(Equal(s.Generation))
		}).WithTimeout(20 * time.Second).Should(Succeed())
		if string(outputSecret(t, prod).Data["password"]) != hunter2 {
			t.Fatal("the output Secret changed")
		}
	})

	t.Run("shall require the next key for a new SopsSecret", func(t *testing.T) {
		tenantNS, prod, _, recipient := rotatingTenant(t)
		fresh := encryptedSopsSecret(t, recipient, tenantNS, prod, "new", prod+"/new", map[string]any{"a": "b"})
		create(t, fresh)
		eventuallyReason(t, fresh, sopsv1alpha1.ReasonNextKeyRequired)
		c := readyCondition(fresh)
		if !strings.Contains(c.Message, tenantOf(t, tenantNS).Status.Rotation.NextPublicKey) {
			t.Fatalf("message %q does not name the next public key", c.Message)
		}
		assertNoSecret(t, prod, "new")
	})

	t.Run("shall require the next key for a changed SopsSecret and keep its Secret", func(t *testing.T) {
		tenantNS, prod, s, recipient := rotatingTenant(t)
		eventuallyNextRecipient(t, s)
		changed := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "new"})
		update(t, s, func() { s.Spec, s.Sops = changed.Spec, changed.Sops })
		eventuallyReason(t, s, sopsv1alpha1.ReasonNextKeyRequired)
		if string(outputSecret(t, prod).Data["password"]) != hunter2 {
			t.Fatal("the output Secret must keep its last values")
		}
		eventuallyNextRecipient(t, s)
	})

	t.Run("shall keep accepting an unchanged file after a transient failure", func(t *testing.T) {
		_, _, s, _ := rotatingTenant(t)
		eventuallyNextRecipient(t, s)
		update(t, s, func() { s.Annotations = map[string]string{sopsv1alpha1.AnnotationSuspend: "true"} })
		eventuallyReason(t, s, sopsv1alpha1.ReasonSuspended)
		update(t, s, func() { delete(s.Annotations, sopsv1alpha1.AnnotationSuspend) })
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
	})
}
