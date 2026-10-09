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
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// Use case: a tenant admin creates a SopsTenant after the cluster admin onboarded the tenant (DESIGN.md §8.1).
func TestOnboardingATenant(t *testing.T) {
	t.Run("shall generate a post-quantum key when onboarded", func(t *testing.T) {
		tenantNS, recipient := onboardedTenant(t, "e2e-onboard-ready")
		if !strings.HasPrefix(recipient, "age1pq1") {
			t.Fatal("generated key is not post-quantum")
		}
		tenant := &sopsv1alpha1.SopsTenant{ObjectMeta: metav1.ObjectMeta{Name: tenantName, Namespace: tenantNS}}
		// The tenant reports KeyGenerated until the next resync.
		waitForReason(t, tenant, sopsv1alpha1.ReasonKeyGenerated)
		assertGolden(t, tenant, "ready")
	})

	t.Run("shall report AccessDenied until onboarded", func(t *testing.T) {
		ns := namespace(t, "e2e-onboard-missing")
		apply(t, render(t, "sopstenant.yaml", map[string]any{"Name": tenantName, "Namespace": ns}))
		tenant := &sopsv1alpha1.SopsTenant{ObjectMeta: metav1.ObjectMeta{Name: tenantName, Namespace: ns}}
		waitForReason(t, tenant, sopsv1alpha1.ReasonAccessDenied)
		assertGolden(t, tenant, "not onboarded")
	})
}
