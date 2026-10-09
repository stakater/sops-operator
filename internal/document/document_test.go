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
	// JSON output is valid YAML with keys sorted byte-wise, like `yq -i 'sort_keys(..)'`.
	plain, err := json.Marshal(map[string]any{
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
	plain, err := crypto.Decrypt(doc, ks, document.ScopeFor("solar-prod", "db-creds"))
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

func TestParsePlainRejectsUnquotedScalars(t *testing.T) {
	// SOPS parses unquoted scalars before encrypting, so 0123 would become 83: refuse them.
	for name, value := range map[string]any{"port": 5432, "pin": 0o123, "enabled": true} {
		t.Run(name, func(t *testing.T) {
			s, ks := encryptedSopsSecret(t, map[string]any{
				"tenantRef":  map[string]any{"name": "solar", "namespace": "solar-system"},
				"scope":      "solar-prod/db-creds",
				"stringData": map[string]any{name: value},
			})
			_, err := decrypt(t, s, ks)
			if err == nil || !strings.Contains(err.Error(), "stringData."+name) || !strings.Contains(err.Error(), "quoted") {
				t.Fatalf("want an error asking to quote stringData.%s, got %v", name, err)
			}
		})
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

func TestCanonicalKeepsByteOrderOfKeys(t *testing.T) {
	// Natural ordering (digit runs, punctuation first) differs from byte order for these keys.
	s, ks := encryptedSopsSecret(t, map[string]any{
		"tenantRef": map[string]any{"name": "solar", "namespace": "solar-system"},
		"scope":     "solar-prod/db-creds",
		"stringData": map[string]any{
			"key2": "a", "key10": "b", "APIKEY": "c", "API_KEY": "d", "Z": "e", "_a": "f",
			"PG_HOST": "g", "PGPASSWORD": "h",
		},
	})
	p, err := decrypt(t, s, ks)
	if err != nil {
		t.Fatalf("ParsePlain: %v", err)
	}
	if string(p.Data["key10"]) != "b" || string(p.Data["PGPASSWORD"]) != "h" {
		t.Fatal("payload values do not match the plaintext")
	}
}
