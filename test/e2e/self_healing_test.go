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
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

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
		before := outputSecret(t, prod)
		deleteObject(t, before)
		poll(t, "the Secret to be recreated", func() (bool, error) {
			var after corev1.Secret
			err := k8s.Get(context.Background(), client.ObjectKeyFromObject(before), &after)
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return err == nil && after.UID != before.UID && string(after.Data["password"]) == password, err
		})
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
		edited := outputSecret(t, prod)
		edited.Data["password"] = []byte("changed by hand")
		if err := k8s.Update(context.Background(), edited); err != nil {
			t.Fatal(err)
		}
		poll(t, "the Secret to be restored", func() (bool, error) {
			return string(outputSecret(t, prod).Data["password"]) == password, nil
		})
	})
}
