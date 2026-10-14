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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

// Use case: a tenant admin creates a SopsTenant after the cluster admin onboarded the tenant (DESIGN.md §8.1).
func TestTenantOnboarding(t *testing.T) {
	t.Parallel()
	t.Run("shall generate a post-quantum key when onboarded", func(t *testing.T) {
		t.Parallel()
		tenantNS, recipient := onboardedTenant(t, "e2e-onboard-ready")
		if !strings.HasPrefix(recipient, "age1pq1") {
			t.Fatal("generated key is not post-quantum")
		}
		var key corev1.Secret
		keyName := client.ObjectKey{Namespace: tenantNS, Name: tenantKeySecret}
		if err := k8s.Get(context.Background(), keyName, &key); err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(key.Data[crypto.PublicKeyField])) != recipient {
			t.Fatal("the key Secret does not hold the matching public key")
		}
		if key.Labels[sopsv1alpha1.LabelManagedBy] != sopsv1alpha1.ManagedByValue || len(key.OwnerReferences) != 0 {
			t.Fatalf("key Secret metadata: labels=%v ownerReferences=%v", key.Labels, key.OwnerReferences)
		}
		// Values are redacted; the golden file records the Secret's shape and keys.
		assertGolden(t, &key, "key")
	})

	t.Run("shall report AccessDenied until onboarded and then generate a key", func(t *testing.T) {
		t.Parallel()
		ns := namespace(t, "e2e-onboard-missing")
		apply(t, render(t, "sopstenant.yaml", map[string]any{"Name": tenantName, "Namespace": ns}))
		tenant := &sopsv1alpha1.SopsTenant{ObjectMeta: metav1.ObjectMeta{Name: tenantName, Namespace: ns}}
		waitForReason(t, tenant, sopsv1alpha1.ReasonAccessDenied)
		assertGolden(t, tenant, "not onboarded")
		// Until the cluster admin lets the operator act in the namespace, it creates nothing there.
		var sa corev1.ServiceAccount
		if err := k8s.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: tenantSA}, &sa); err == nil {
			t.Fatal("the operator created a ServiceAccount in a namespace it was not granted")
		}

		onboard(t, ns)
		waitForReason(t, tenant, sopsv1alpha1.ReasonKeyGenerated, sopsv1alpha1.ReasonKeyLoaded)
		if err := k8s.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: tenantSA}, &sa); err != nil {
			t.Fatalf("tenant ServiceAccount: %v", err)
		}
	})
}
