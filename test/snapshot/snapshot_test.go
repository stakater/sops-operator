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

package snapshot_test

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/test/snapshot"
)

func scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := sopsv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func meta(name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name: name, Namespace: "ns", UID: "1b4e28ba-2fa1", ResourceVersion: "4711", Generation: 2,
		CreationTimestamp: metav1.NewTime(time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)),
		ManagedFields:     []metav1.ManagedFieldsEntry{{Manager: "kubectl"}},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "sops.stakater.com/v1alpha1", Kind: "SopsSecret", Name: name, UID: "9f2c", Controller: ptr.To(true),
		}},
	}
}

func render(t *testing.T, obj runtime.Object) string {
	t.Helper()
	out, err := snapshot.YAML(obj, scheme(t))
	if err != nil {
		t.Fatalf("YAML: %v", err)
	}
	return string(out)
}

func mustContain(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Fatalf("output does not contain %q:\n%s", w, out)
		}
	}
}

func mustNotContain(t *testing.T, out string, unwanted ...string) {
	t.Helper()
	for _, u := range unwanted {
		if strings.Contains(out, u) {
			t.Fatalf("output contains %q:\n%s", u, out)
		}
	}
}

func TestSnapshotNormalization(t *testing.T) {
	t.Run("shall replace values that change on every run", func(t *testing.T) {
		out := render(t, &corev1.Secret{ObjectMeta: meta("db"), Type: corev1.SecretTypeOpaque})
		mustContain(t, out,
			"apiVersion: v1", "kind: Secret",
			"uid: <uid>", "resourceVersion: <resourceVersion>", "creationTimestamp: <timestamp>",
			"generation: 2", // deterministic, kept
		)
		mustNotContain(t, out, "1b4e28ba", "9f2c", "4711", "managedFields", "kubectl")
	})

	t.Run("shall redact Secret values and keep their keys", func(t *testing.T) {
		out := render(t, &corev1.Secret{ObjectMeta: meta("db"), Data: map[string][]byte{"password": []byte("hunter2")}})
		mustContain(t, out, "password: <redacted>")
		mustNotContain(t, out, "hunter2", "aHVudGVyMg==")
	})

	t.Run("shall hide ciphertext and SOPS metadata of a SopsSecret", func(t *testing.T) {
		enc := "ENC[AES256_GCM,data:eA==,iv:eA==,tag:eA==,type:str]"
		out := render(t, &sopsv1alpha1.SopsSecret{
			ObjectMeta: meta("db"),
			Spec: sopsv1alpha1.SopsSecretSpec{
				TenantRef: sopsv1alpha1.TenantReference{Name: "solar", Namespace: "solar-system"},
				Scope:     enc, StringData: map[string]string{"password": enc}, Data: map[string]string{"cert": enc},
			},
			Sops: sopsv1alpha1.SopsMetadata{
				Age: []sopsv1alpha1.SopsAgeRecipient{{Recipient: "age1pq1abc", Enc: "-----BEGIN AGE ENCRYPTED FILE-----"}},
				MAC: enc, LastModified: "2026-10-09T10:00:00Z", Version: "3.13.3",
			},
			Status: sopsv1alpha1.SopsSecretStatus{SecretUID: "77aa"},
		})
		mustContain(t, out, "scope: <encrypted>", "sops: <encrypted>", "password: <redacted>", "cert: <redacted>",
			"secretUID: <uid>", "name: solar")
		mustNotContain(t, out, "ENC[", "age1pq1abc", "BEGIN AGE", "77aa")
	})

	t.Run("shall replace valid condition timestamps", func(t *testing.T) {
		out := render(t, &sopsv1alpha1.SopsTenant{
			ObjectMeta: meta("solar"),
			Status: sopsv1alpha1.SopsTenantStatus{Conditions: []metav1.Condition{{
				Type: "Ready", Status: metav1.ConditionTrue, Reason: "KeyLoaded", Message: "key loaded",
				LastTransitionTime: metav1.NewTime(time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)),
			}}},
		})
		mustContain(t, out, "lastTransitionTime: <timestamp>", "reason: KeyLoaded")
	})

	t.Run("shall fail when a condition has no timestamp", func(t *testing.T) {
		_, err := snapshot.YAML(&sopsv1alpha1.SopsTenant{
			ObjectMeta: meta("solar"),
			Status: sopsv1alpha1.SopsTenantStatus{
				Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}},
			},
		}, scheme(t))
		if err == nil || !strings.Contains(err.Error(), "lastTransitionTime") {
			t.Fatalf("want an error about lastTransitionTime, got %v", err)
		}
	})

	t.Run("shall refuse an object containing an age private key", func(t *testing.T) {
		obj := &corev1.Secret{ObjectMeta: meta("db")}
		obj.Annotations = map[string]string{"note": "AGE-SECRET-KEY-PQ-1QQQQ"}
		if _, err := snapshot.YAML(obj, scheme(t)); err == nil {
			t.Fatal("want an error for an age private key")
		}
	})
}
