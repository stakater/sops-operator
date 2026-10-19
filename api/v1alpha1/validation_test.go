package v1alpha1_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/testenv"
)

var env *testenv.Env

func TestMain(m *testing.M) {
	var err error
	if env, err = testenv.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	_ = env.Stop()
	os.Exit(code)
}

func validSopsSecret(ns string) *sopsv1alpha1.SopsSecret {
	return &sopsv1alpha1.SopsSecret{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "s-", Namespace: ns},
		Spec: sopsv1alpha1.SopsSecretSpec{
			TenantRef: sopsv1alpha1.TenantReference{Name: "my-team", Namespace: "my-team-sops"},
			Encrypted: "eyJzY29wZSI6ICJFTkNbLi4uXSJ9", // the API server checks presence, not the ciphertext
		},
	}
}

func TestSopsSecretValidation(t *testing.T) {
	ns := env.Namespace(t, "validation")
	cases := []struct {
		name   string
		mutate func(s *sopsv1alpha1.SopsSecret)
		valid  bool
	}{
		{"shall accept a valid SopsSecret", func(*sopsv1alpha1.SopsSecret) {}, true},
		{"shall reject a missing encrypted value", func(s *sopsv1alpha1.SopsSecret) { s.Spec.Encrypted = "" }, false},
		{"shall reject the service-account-token type", func(s *sopsv1alpha1.SopsSecret) { s.Spec.Type = corev1.SecretTypeServiceAccountToken }, false},
		{"shall accept the TLS type", func(s *sopsv1alpha1.SopsSecret) { s.Spec.Type = corev1.SecretTypeTLS }, true},
		{"shall reject an unknown deletionPolicy", func(s *sopsv1alpha1.SopsSecret) { s.Spec.DeletionPolicy = "Orphan" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validSopsSecret(ns)
			tc.mutate(s)
			err := env.Admin.Create(context.Background(), s)
			if tc.valid && err != nil {
				t.Fatalf("want accepted, got %v", err)
			}
			if !tc.valid && !apierrors.IsInvalid(err) {
				t.Fatalf("want Invalid, got %v", err)
			}
		})
	}
}

func TestDefaults(t *testing.T) {
	t.Run("shall default deletionPolicy and type", func(t *testing.T) {
		s := validSopsSecret(env.Namespace(t, "defaults"))
		if err := env.Admin.Create(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		if s.Spec.DeletionPolicy != sopsv1alpha1.DeletionPolicyDelete || s.Spec.Type != corev1.SecretTypeOpaque {
			t.Fatalf("defaults not applied: deletionPolicy=%q type=%q", s.Spec.DeletionPolicy, s.Spec.Type)
		}
	})

	t.Run("shall default generateKey to true", func(t *testing.T) {
		tenant := &sopsv1alpha1.SopsTenant{ObjectMeta: metav1.ObjectMeta{Name: "my-team", Namespace: env.Namespace(t, "tenant")}}
		if err := env.Admin.Create(context.Background(), tenant); err != nil {
			t.Fatal(err)
		}
		var got sopsv1alpha1.SopsTenant
		if err := env.Admin.Get(context.Background(), client.ObjectKeyFromObject(tenant), &got); err != nil {
			t.Fatal(err)
		}
		if got.Spec.GenerateKey == nil || !*got.Spec.GenerateKey || !got.ShouldGenerateKey() {
			t.Fatal("generateKey does not default to true")
		}
	})
}

// The tenant name is used in the "app.kubernetes.io/instance" label of its ServiceAccount.
func TestSopsTenantValidation(t *testing.T) {
	ns := env.Namespace(t, "validation")
	for _, tc := range []struct {
		name  string
		len   int
		valid bool
	}{
		{"shall accept a 63-character name", 63, true},
		{"shall reject a 64-character name", 64, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenant := &sopsv1alpha1.SopsTenant{ObjectMeta: metav1.ObjectMeta{Name: strings.Repeat("a", tc.len), Namespace: ns}}
			err := env.Admin.Create(context.Background(), tenant)
			if tc.valid && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !tc.valid && !apierrors.IsInvalid(err) {
				t.Fatalf("got %v, want Invalid", err)
			}
		})
	}
}
