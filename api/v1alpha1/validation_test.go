package v1alpha1_test

import (
	"context"
	"fmt"
	"os"
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

const enc = "ENC[AES256_GCM,data:eA==,iv:eA==,tag:eA==,type:str]"

func validSopsSecret(ns string) *sopsv1alpha1.SopsSecret {
	return &sopsv1alpha1.SopsSecret{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "s-", Namespace: ns},
		Spec: sopsv1alpha1.SopsSecretSpec{
			TenantRef:  sopsv1alpha1.TenantReference{Name: "solar", Namespace: "solar-system"},
			Scope:      enc,
			StringData: map[string]string{"password": enc},
		},
		Sops: sopsv1alpha1.SopsMetadata{
			Age:              []sopsv1alpha1.SopsAgeRecipient{{Recipient: "age1pq1example", Enc: "-----BEGIN AGE ENCRYPTED FILE-----\nx\n-----END AGE ENCRYPTED FILE-----\n"}},
			MAC:              enc,
			LastModified:     "2026-10-09T10:00:00Z",
			Version:          "3.13.3",
			EncryptedRegex:   "^(data|stringData|scope)$",
			MACOnlyEncrypted: true,
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
		{"valid", func(*sopsv1alpha1.SopsSecret) {}, true},
		{"missing scope", func(s *sopsv1alpha1.SopsSecret) { s.Spec.Scope = "" }, false},
		{"no data", func(s *sopsv1alpha1.SopsSecret) { s.Spec.StringData = nil }, false},
		{"key in data and stringData", func(s *sopsv1alpha1.SopsSecret) { s.Spec.Data = map[string]string{"password": enc} }, false},
		{"service account token type", func(s *sopsv1alpha1.SopsSecret) { s.Spec.Type = corev1.SecretTypeServiceAccountToken }, false},
		{"tls type", func(s *sopsv1alpha1.SopsSecret) { s.Spec.Type = corev1.SecretTypeTLS }, true},
		{"other encrypted_regex", func(s *sopsv1alpha1.SopsSecret) { s.Sops.EncryptedRegex = "^data$" }, false},
		{"mac_only_encrypted false", func(s *sopsv1alpha1.SopsSecret) { s.Sops.MACOnlyEncrypted = false }, false},
		{"no age recipients", func(s *sopsv1alpha1.SopsSecret) { s.Sops.Age = nil }, false},
		{"unknown deletion policy", func(s *sopsv1alpha1.SopsSecret) { s.Spec.DeletionPolicy = "Orphan" }, false},
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

func TestSopsSecretDefaults(t *testing.T) {
	s := validSopsSecret(env.Namespace(t, "defaults"))
	if err := env.Admin.Create(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if s.Spec.DeletionPolicy != sopsv1alpha1.DeletionPolicyDelete || s.Spec.Type != corev1.SecretTypeOpaque {
		t.Fatalf("defaults not applied: deletionPolicy=%q type=%q", s.Spec.DeletionPolicy, s.Spec.Type)
	}
}

func TestSopsTenantGenerateKeyDefaultsToTrue(t *testing.T) {
	tenant := &sopsv1alpha1.SopsTenant{ObjectMeta: metav1.ObjectMeta{Name: "solar", Namespace: env.Namespace(t, "tenant")}}
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
}
