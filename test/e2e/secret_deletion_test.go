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
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// Use case: a developer removes a SopsSecret from Git and the GitOps tool prunes it.
func TestSecretDeletion(t *testing.T) {
	t.Parallel()
	t.Run("shall delete the Secret with the SopsSecret", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-remove-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-remove-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		out := outputSecret(t, prod)
		if err := k8s.Delete(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		waitUntilDeleted(t, "the output Secret", out)
	})

	t.Run("shall keep the Secret when deletionPolicy is Retain", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-retain-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-retain-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			DeletionPolicy: string(sopsv1alpha1.DeletionPolicyRetain), StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		if err := k8s.Delete(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		waitUntilDeleted(t, "the SopsSecret", s)
		kept := outputSecret(t, prod)
		if len(kept.OwnerReferences) != 0 {
			t.Fatalf("a retained Secret must have no owner, got %v", kept.OwnerReferences)
		}
		assertGolden(t, kept, "retained")
	})

	t.Run("shall write the Secret without an owner reference", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-noowner-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-noowner-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		if refs := outputSecret(t, prod).OwnerReferences; len(refs) != 0 {
			t.Fatalf("the Secret has owner references %v, want none", refs)
		}
	})

	t.Run("shall take over a Secret written by v0.0.4 only once it carries the enabled label", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		prod := namespace(t, "e2e-oldowner-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-oldowner-tenant", prod)
		spec := sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		}
		s := encryptSopsSecret(t, recipient, spec)
		s.Annotations = map[string]string{sopsv1alpha1.AnnotationSuspend: "true"}
		if err := k8s.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		old := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "db-creds", Namespace: prod,
				Labels:      map[string]string{sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue},
				Annotations: map[string]string{sopsv1alpha1.AnnotationSopsSecret: "db-creds"},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: sopsv1alpha1.GroupVersion.String(), Kind: "SopsSecret", Name: s.Name, UID: s.UID,
					Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(false),
				}},
			},
			Data: map[string][]byte{"password": []byte("from v0.0.4")},
		}
		if err := k8s.Create(ctx, old); err != nil {
			t.Fatal(err)
		}
		update(t, s, func() { delete(s.Annotations, sopsv1alpha1.AnnotationSuspend) })
		waitForMessage(t, s, sopsv1alpha1.ReasonConflict, sopsv1alpha1.LabelEnabled)
		if got := string(outputSecret(t, prod).Data["password"]); got != "from v0.0.4" {
			t.Fatalf("password = %q, want the Secret unchanged until it is labelled", got)
		}
		labelled := outputSecret(t, prod)
		update(t, labelled, func() { labelled.Labels[sopsv1alpha1.LabelEnabled] = sopsv1alpha1.EnabledValue })
		waitForNewSync(t, s, s.Status.LastSyncTime)
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		out := outputSecret(t, prod)
		if out.UID != old.UID || len(out.OwnerReferences) != 0 || string(out.Data["password"]) != password {
			t.Fatalf("Secret %s owners %v, want %s updated in place without owner references",
				out.UID, out.OwnerReferences, old.UID)
		}
	})

	t.Run("shall not block the deletion of its namespace", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		prod := namespace(t, "e2e-nsdelete-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-nsdelete-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: prod}}
		if err := k8s.Delete(ctx, ns); err != nil {
			t.Fatal(err)
		}
		waitUntilDeleted(t, "the namespace", ns)
	})

	t.Run("shall not block the deletion of a SopsSecret whose tenant lost the namespace grant", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-revoked-delete-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-revoked-delete-tenant", prod)
		s := createSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": password},
		})
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		deleteObject(t, &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: tenantSA + "-" + tenantNS, Namespace: prod}})
		if err := k8s.Delete(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		waitUntilDeleted(t, "the SopsSecret", s)
	})
}
