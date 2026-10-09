package document_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/crypto/cryptotest"
	"github.com/stakater/sops-operator/internal/document"
)

// encryptedSopsSecret builds a SopsSecret the way a developer would (sorted plaintext, then
// sops encrypt) and returns it as the API server would hand it to the operator.
func encryptedSopsSecret(t *testing.T, spec map[string]any) (*sopsv1alpha1.SopsSecret, *crypto.KeySet) {
	t.Helper()
	keyFile, recipient, err := crypto.GenerateKeyFile(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ks, err := crypto.ParseKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := yaml.Marshal(map[string]any{
		"apiVersion": "sops.stakater.com/v1alpha1",
		"kind":       "SopsSecret",
		"metadata":   map[string]any{"name": "db-creds", "namespace": "solar-prod"},
		"spec":       spec,
	})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cryptotest.Encrypt(plain, recipient)
	if err != nil {
		t.Fatal(err)
	}
	var s sopsv1alpha1.SopsSecret
	if err := yaml.Unmarshal(enc, &s); err != nil {
		t.Fatal(err)
	}
	// Round-trip through JSON like the API server.
	raw, err := json.Marshal(&s)
	if err != nil {
		t.Fatal(err)
	}
	var stored sopsv1alpha1.SopsSecret
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	return &stored, ks
}

func decrypt(t *testing.T, s *sopsv1alpha1.SopsSecret, ks *crypto.KeySet) (*document.Payload, error) {
	t.Helper()
	doc, err := document.Canonical(s)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	plain, err := crypto.Decrypt(doc, ks)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	return document.ParsePlain(plain)
}

func TestCanonicalDecryptsAfterAPIRoundTrip(t *testing.T) {
	s, ks := encryptedSopsSecret(t, map[string]any{
		"tenantRef":  map[string]any{"name": "solar", "namespace": "solar-system"},
		"scope":      "solar-prod/db-creds",
		"data":       map[string]any{"cert": "AAEC"}, // bytes 0x00 0x01 0x02
		"stringData": map[string]any{"password": "hunter2"},
	})
	p, err := decrypt(t, s, ks)
	if err != nil {
		t.Fatalf("ParsePlain: %v", err)
	}
	if p.Scope != document.ScopeFor("solar-prod", "db-creds") {
		t.Fatalf("scope = %q", p.Scope)
	}
	if string(p.Data["password"]) != "hunter2" || string(p.Data["cert"]) != "\x00\x01\x02" {
		t.Fatal("payload values do not match the plaintext")
	}
}

func TestParsePlainConvertsScalarsToStrings(t *testing.T) {
	s, ks := encryptedSopsSecret(t, map[string]any{
		"tenantRef":  map[string]any{"name": "solar", "namespace": "solar-system"},
		"scope":      "solar-prod/db-creds",
		"stringData": map[string]any{"enabled": true, "port": 5432, "ratio": 0.5},
	})
	p, err := decrypt(t, s, ks)
	if err != nil {
		t.Fatalf("ParsePlain: %v", err)
	}
	for k, want := range map[string]string{"enabled": "true", "port": "5432", "ratio": "0.5"} {
		if got := string(p.Data[k]); got != want {
			t.Fatalf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestParsePlainRejectsInvalidBase64WithoutValue(t *testing.T) {
	const secretValue = "not-base64-%%%"
	_, err := document.ParsePlain([]byte("spec:\n  scope: a/b\n  data:\n    token: " + secretValue + "\n"))
	if err == nil {
		t.Fatal("want error for invalid base64")
	}
	if !strings.Contains(err.Error(), "token") || strings.Contains(err.Error(), secretValue) {
		t.Fatalf("error %q must name the key and not contain the value", err)
	}
}

func TestParsePlainRejectsNestedValues(t *testing.T) {
	_, err := document.ParsePlain([]byte("spec:\n  scope: a/b\n  stringData:\n    nested:\n      x: y\n"))
	if err == nil || !strings.Contains(err.Error(), "nested") {
		t.Fatalf("want error naming the nested key, got %v", err)
	}
}
