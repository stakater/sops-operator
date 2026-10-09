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

func outputSecret(t *testing.T, namespace, name string) *corev1.Secret {
	t.Helper()
	var s corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: name}, &s); err != nil {
		t.Fatalf("get Secret %s/%s: %v", namespace, name, err)
	}
	return &s
}

func TestSopsSecretDecryptsAndIsGarbageCollected(t *testing.T) {
	prod := namespace(t, "e2e-decrypt-prod")
	tenantNS, recipient := onboardedTenant(t, "e2e-decrypt-tenant", prod)
	s := createSopsSecret(t, recipient, sopsSecret{
		Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
		StringData: map[string]string{"password": "hunter2", "username": "app"},
	})
	waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
	matchSnapshot(t, s, "decrypted")

	out := outputSecret(t, prod, "db-creds")
	// Values are checked here; the snapshot only records which keys exist.
	if string(out.Data["password"]) != "hunter2" || string(out.Data["username"]) != "app" {
		t.Fatal("output Secret does not hold the decrypted values")
	}
	matchSnapshot(t, out, "output")

	if err := k8s.Delete(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	poll(t, "the output Secret to be garbage-collected", func() (bool, error) {
		err := k8s.Get(context.Background(), client.ObjectKeyFromObject(out), &corev1.Secret{})
		return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
	})
}

func TestSopsSecretRetainKeepsSecret(t *testing.T) {
	prod := namespace(t, "e2e-retain-prod")
	tenantNS, recipient := onboardedTenant(t, "e2e-retain-tenant", prod)
	s := createSopsSecret(t, recipient, sopsSecret{
		Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
		DeletionPolicy: string(sopsv1alpha1.DeletionPolicyRetain), StringData: map[string]string{"password": "hunter2"},
	})
	waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
	if err := k8s.Delete(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	poll(t, "the SopsSecret to be deleted", func() (bool, error) {
		err := k8s.Get(context.Background(), client.ObjectKeyFromObject(s), &sopsv1alpha1.SopsSecret{})
		return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
	})
	matchSnapshot(t, outputSecret(t, prod, "db-creds"), "retained")
}

func TestSopsSecretIsolation(t *testing.T) {
	prod := namespace(t, "e2e-isolation-prod")
	dev := namespace(t, "e2e-isolation-dev")
	other := namespace(t, "e2e-isolation-other")
	tenantNS, recipient := onboardedTenant(t, "e2e-isolation-tenant", prod, dev)
	value := map[string]string{"password": "hunter2"}

	cases := []struct {
		name   string
		secret sopsSecret
		reason string
	}{
		{"namespace not granted",
			sopsSecret{Name: "db", Namespace: other, Scope: other + "/db"}, sopsv1alpha1.ReasonAccessDenied},
		{"copied to another namespace",
			sopsSecret{Name: "db", Namespace: dev, Scope: prod + "/db"}, sopsv1alpha1.ReasonScopeMismatch},
		{"copied under another name",
			sopsSecret{Name: "renamed", Namespace: prod, Scope: prod + "/db"}, sopsv1alpha1.ReasonScopeMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.secret.TenantNamespace, tc.secret.StringData = tenantNS, value
			s := createSopsSecret(t, recipient, tc.secret)
			waitForReason(t, s, tc.reason)
			matchSnapshot(t, s, tc.reason)
			err := k8s.Get(context.Background(), client.ObjectKeyFromObject(s), &corev1.Secret{})
			if !apierrors.IsNotFound(err) {
				t.Fatalf("no Secret may be written: %v", err)
			}
		})
	}
}

func TestSopsSecretLeavesForeignSecretAlone(t *testing.T) {
	prod := namespace(t, "e2e-conflict-prod")
	tenantNS, recipient := onboardedTenant(t, "e2e-conflict-tenant", prod)
	apply(t, render(t, "secret.yaml", map[string]any{"Name": "db-creds", "Namespace": prod}))
	s := createSopsSecret(t, recipient, sopsSecret{
		Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
		StringData: map[string]string{"password": "mine"},
	})
	waitForReason(t, s, sopsv1alpha1.ReasonConflict)
	matchSnapshot(t, s, "conflict")
	if string(outputSecret(t, prod, "db-creds").Data["password"]) != "foreign" {
		t.Fatal("the foreign Secret was overwritten")
	}
}
