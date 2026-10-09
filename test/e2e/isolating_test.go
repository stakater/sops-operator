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

// Use case: secrets stay inside the namespaces the cluster admin granted to their tenant (DESIGN.md §7.1).
func TestIsolatingSecrets(t *testing.T) {
	prod := namespace(t, "e2e-isolate-prod")
	dev := namespace(t, "e2e-isolate-dev")
	other := namespace(t, "e2e-isolate-other")
	tenantNS, recipient := onboardedTenant(t, "e2e-isolate-tenant", prod, dev)

	cases := []struct {
		name   string
		secret sopsSecret
		reason string
	}{
		{"shall reject a namespace not granted to the tenant",
			sopsSecret{Name: "db", Namespace: other, Scope: other + "/db"}, sopsv1alpha1.ReasonAccessDenied},
		{"shall reject ciphertext copied to another namespace",
			sopsSecret{Name: "db", Namespace: dev, Scope: prod + "/db"}, sopsv1alpha1.ReasonScopeMismatch},
		{"shall reject ciphertext copied under another name",
			sopsSecret{Name: "renamed", Namespace: prod, Scope: prod + "/db"}, sopsv1alpha1.ReasonScopeMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.secret.TenantNamespace, tc.secret.StringData = tenantNS, map[string]string{"password": "hunter2"}
			s := createSopsSecret(t, recipient, tc.secret)
			waitForReason(t, s, tc.reason)
			assertGolden(t, s, "rejected")
			err := k8s.Get(context.Background(), client.ObjectKeyFromObject(s), &corev1.Secret{})
			if !apierrors.IsNotFound(err) {
				t.Fatalf("no Secret may be written: %v", err)
			}
		})
	}
}
