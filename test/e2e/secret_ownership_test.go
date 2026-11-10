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
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// Use case: a SopsSecret owns the Secret with its name and namespace that carries the enabled label,
// whatever happened to the SopsSecret's status: a SopsSecret restored or re-created by the GitOps
// tool keeps managing its Secret.
func TestSecretOwnership(t *testing.T) {
	t.Parallel()

	t.Run("shall keep updating its Secret after the SopsSecret's status is lost", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		prod := namespace(t, "e2e-own-status-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-own-status-tenant", prod)
		spec := sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		}
		s := createSopsSecret(t, recipient, spec)
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		before := outputSecret(t, prod)
		s.Status = sopsv1alpha1.SopsSecretStatus{}
		if err := k8s.Status().Update(ctx, s); err != nil {
			t.Fatal(err)
		}
		spec.StringData = map[string]string{"password": "changed in git"}
		next := encryptSopsSecret(t, recipient, spec)
		update(t, s, func() { s.Spec, s.Sops = next.Spec, next.Sops })
		poll(t, "the Secret to hold the changed value", func() (bool, error) {
			return string(outputSecret(t, prod).Data["password"]) == "changed in git", nil
		})
		if after := outputSecret(t, prod); after.UID != before.UID {
			t.Fatal("the Secret was recreated instead of updated")
		}
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
	})

	t.Run("shall take over a retained Secret with a SopsSecret of the same name", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-own-retain-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-own-retain-tenant", prod)
		spec := sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password}, DeletionPolicy: string(sopsv1alpha1.DeletionPolicyRetain),
		}
		first := createSopsSecret(t, recipient, spec)
		waitForReason(t, first, sopsv1alpha1.ReasonDecrypted)
		retained := outputSecret(t, prod)
		deleteObject(t, first)
		waitUntilDeleted(t, "the SopsSecret", first)
		second := createSopsSecret(t, recipient, spec)
		waitForReason(t, second, sopsv1alpha1.ReasonDecrypted)
		if got := outputSecret(t, prod); got.UID != retained.UID {
			t.Fatal("the retained Secret was replaced")
		}
	})

	t.Run("shall not write a Secret named like the tenant's key Secret", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		tenantNS, recipient := onboardedTenant(t, "e2e-own-keyname-tenant")
		key := tenantKey(t, tenantNS)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: tenantKeySecret, Namespace: tenantNS, Scope: tenantNS + "/" + tenantKeySecret, TenantNamespace: tenantNS,
			StringData: map[string]string{"age.agekey": "not a key"},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonConflict)
		var after corev1.Secret
		if err := k8s.Get(ctx, client.ObjectKeyFromObject(key), &after); err != nil {
			t.Fatal(err)
		}
		if after.ResourceVersion != key.ResourceVersion {
			t.Fatal("the key Secret was changed")
		}
	})
}
