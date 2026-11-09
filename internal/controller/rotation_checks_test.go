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
	"testing"

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

// The completion decides on a live list: an informer that has not seen a file re-applied without
// the next-key entry must not let the old key go (DESIGN.md §4.4, completion).
func TestRotationCompletionLiveList(t *testing.T) {
	t.Run("shall block completion on a SopsSecret that only the cache shows as migrated", func(t *testing.T) {
		ctx := context.Background()
		tenantNS, prod, s, oldRecipient := rotatingTenant(t)
		migrate(t, s)
		eventuallyMigrated(t, s)
		if s.Status.Rotation.MigratedGeneration != s.Generation {
			t.Fatalf("precondition: migratedGeneration %d, generation %d", s.Status.Rotation.MigratedGeneration, s.Generation)
		}
		cached := []sopsv1alpha1.SopsSecret{*s.DeepCopy()}

		// The file is re-applied without the next-key entry: a new generation that is not migrated.
		reapplied := encryptedSopsSecret(t, oldRecipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "changed"})
		update(t, s, func() { s.Spec, s.Sops = reapplied.Spec, reapplied.Sops })

		// Only this copy asks for completion; the running controller keeps the rotation in progress.
		tenant := tenantOf(t, tenantNS)
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
		var key corev1.Secret
		if err := env.Admin.Get(ctx, client.ObjectKey{Namespace: tenantNS, Name: sopsv1alpha1.TenantKeySecretName(tenantName)}, &key); err != nil {
			t.Fatal(err)
		}
		ks, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
		if err != nil || ks.Recipients[0] != oldRecipient {
			t.Fatal("the key Secret no longer holds the current key")
		}
		var next corev1.Secret
		if err := env.Admin.Get(ctx, client.ObjectKey{Namespace: tenantNS, Name: sopsv1alpha1.TenantNextKeySecretName(tenantName)}, &next); err != nil {
			t.Fatalf("the next key Secret is gone: %v", err)
		}
	})
}

// A rotation starts only when every SopsSecret's current generation was decrypted (DESIGN.md §4.4,
// start): a Decrypted condition from an earlier generation says nothing about the current one.
func TestHealthy(t *testing.T) {
	decrypted := func(generation, conditionGeneration, observedGeneration int64) *sopsv1alpha1.SopsSecret {
		s := &sopsv1alpha1.SopsSecret{}
		s.Generation = generation
		s.Status.ObservedGeneration = observedGeneration
		s.Status.Conditions = []metav1.Condition{{
			Type: sopsv1alpha1.ConditionReady, Status: metav1.ConditionTrue, Reason: sopsv1alpha1.ReasonDecrypted,
			ObservedGeneration: conditionGeneration,
		}}
		return s
	}
	cases := []struct {
		name string
		s    *sopsv1alpha1.SopsSecret
		want bool
	}{
		{"current generation decrypted", decrypted(3, 3, 3), true},
		{"condition from an earlier generation", decrypted(3, 2, 3), false},
		{"status from an earlier generation", decrypted(3, 3, 2), false},
		{"nothing observed yet", decrypted(3, 2, 2), false},
	}
	for _, c := range cases {
		t.Run("shall report "+c.name+" as healthy="+map[bool]string{true: "true", false: "false"}[c.want], func(t *testing.T) {
			if got := controller.HealthyForTest(c.s); got != c.want {
				t.Fatalf("healthy = %v, want %v", got, c.want)
			}
		})
	}
}
