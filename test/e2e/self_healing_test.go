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
	"maps"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// watchDeadline is how soon the watch of output Secrets restores one. The resync comes about
// resyncInterval (10s) after a sync; each change below is made right after a sync, so a restore within
// this deadline comes from the watch, not from the resync.
const watchDeadline = 4 * time.Second

// Use case: Secrets written by the operator stay as declared even when someone deletes or edits them.
func TestSelfHealing(t *testing.T) {
	t.Parallel()
	t.Run("shall recreate a deleted Secret", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-heal-deleted-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-heal-deleted-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		waitForNewSync(t, s, s.Status.LastSyncTime)
		before := outputSecret(t, prod)
		since := s.Status.LastSyncTime
		deleteObject(t, before)
		var after *corev1.Secret
		pollFor(t, watchDeadline, "the Secret to be recreated before the next resync", func() (bool, error) {
			after = outputSecretOrNil(t, prod)
			return after != nil && after.UID != before.UID && string(after.Data["password"]) == password, nil
		})
		waitForNewSync(t, s, since)
		if s.Status.SecretUID != after.UID {
			t.Fatal("status.secretUID does not name the recreated Secret")
		}
	})

	t.Run("shall restore a modified Secret", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-heal-modified-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-heal-modified-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		waitForNewSync(t, s, s.Status.LastSyncTime)
		edited := outputSecret(t, prod)
		edited.Data["password"] = []byte("changed by hand")
		if err := k8s.Update(context.Background(), edited); err != nil {
			t.Fatal(err)
		}
		pollFor(t, watchDeadline, "the Secret to be restored before the next resync", func() (bool, error) {
			return string(outputSecret(t, prod).Data["password"]) == password, nil
		})
		if restored := outputSecret(t, prod); restored.UID != edited.UID {
			t.Fatal("the Secret was recreated instead of updated")
		}
	})
	t.Run("shall revert labels changed on the Secret", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-heal-labels-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-heal-labels-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		waitForNewSync(t, s, s.Status.LastSyncTime)
		edited := outputSecret(t, prod)
		want := maps.Clone(edited.Labels)
		edited.Labels["edited-by"] = "hand"
		edited.Labels[sopsv1alpha1.LabelManagedBy] = "someone-else"
		if err := k8s.Update(context.Background(), edited); err != nil {
			t.Fatal(err)
		}
		pollFor(t, watchDeadline, "the labels to be reverted before the next resync", func() (bool, error) {
			return maps.Equal(outputSecret(t, prod).Labels, want), nil
		})
		if restored := outputSecret(t, prod); restored.UID != edited.UID {
			t.Fatal("the Secret was recreated instead of updated")
		}
	})
}
