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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// Use case: secrets stay inside the namespaces the cluster admin granted to their tenant (DESIGN.md §7.1).
func TestNamespaceIsolation(t *testing.T) {
	t.Parallel()
	prod := namespace(t, "e2e-isolate-prod")
	dev := namespace(t, "e2e-isolate-dev")
	other := namespace(t, "e2e-isolate-other")
	tenantNS, recipient := onboardedTenant(t, "e2e-isolate-tenant", prod, dev)

	// Each case encrypts a file for encryptedFor and applies it, unchanged but for its metadata, as
	// appliedAs: what a developer gets by copying a committed file.
	cases := []struct {
		name                    string
		encryptedFor, appliedAs string
		reason                  string
	}{
		{"shall reject a namespace not granted to the tenant",
			other + "/db", other + "/db", sopsv1alpha1.ReasonAccessDenied},
		{"shall reject ciphertext copied to another namespace",
			prod + "/db", dev + "/db", sopsv1alpha1.ReasonScopeMismatch},
		{"shall reject ciphertext copied under another name",
			prod + "/db", prod + "/renamed", sopsv1alpha1.ReasonScopeMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ns, name, _ := strings.Cut(tc.encryptedFor, "/")
			s := encryptSopsSecret(t, recipient, sopsSecret{
				Name: name, Namespace: ns, Scope: tc.encryptedFor, TenantNamespace: tenantNS,
				StringData: map[string]string{"password": password},
			})
			s.Namespace, s.Name, _ = strings.Cut(tc.appliedAs, "/")
			if err := k8s.Create(context.Background(), s); err != nil {
				t.Fatal(err)
			}
			waitForReason(t, s, tc.reason)
			assertGolden(t, s, "rejected")
			err := k8s.Get(context.Background(), client.ObjectKeyFromObject(s), &corev1.Secret{})
			if !apierrors.IsNotFound(err) {
				t.Fatalf("no Secret may be written: %v", err)
			}
		})
	}
}
