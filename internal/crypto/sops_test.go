package crypto_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/crypto/cryptotest"
)

// sortedPlain is a plaintext document whose keys are already sorted, as required (D29).
const sortedPlain = `spec:
  scope: solar-prod/db-creds
  stringData:
    a: one
    b: two
`

func newKeys(t *testing.T) *crypto.KeySet {
	t.Helper()
	keyFile, _, err := crypto.GenerateKeyFile(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ks, err := crypto.ParseKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func encrypt(t *testing.T, plain string, recipients ...string) []byte {
	t.Helper()
	enc, err := cryptotest.Encrypt([]byte(plain), recipients...)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return enc
}

// viaAPI simulates the Kubernetes API: the document is stored as JSON and returned with sorted keys.
func viaAPI(t *testing.T, doc []byte, mutate func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(m)
	}
	out, err := yaml.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDecryptRoundTrip(t *testing.T) {
	ks := newKeys(t)
	doc := viaAPI(t, encrypt(t, sortedPlain, ks.Recipients[0]), nil)

	recipients, err := crypto.Recipients(doc)
	if err != nil {
		t.Fatalf("Recipients: %v", err)
	}
	if len(recipients) != 1 || recipients[0] != ks.Recipients[0] {
		t.Fatal("Recipients does not return the encryption recipient")
	}

	plain, err := crypto.Decrypt(doc, ks)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	var got struct {
		Spec struct {
			Scope      string            `json:"scope"`
			StringData map[string]string `json:"stringData"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal(plain, &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.Scope != "solar-prod/db-creds" || got.Spec.StringData["a"] != "one" || got.Spec.StringData["b"] != "two" {
		t.Fatal("decrypted values do not match the plaintext")
	}
}

func TestDecryptNotRecipient(t *testing.T) {
	owner, other := newKeys(t), newKeys(t)
	doc := encrypt(t, sortedPlain, other.Recipients[0])
	if _, err := crypto.Decrypt(doc, owner); !errors.Is(err, crypto.ErrNotRecipient) {
		t.Fatalf("got %v, want ErrNotRecipient", err)
	}
}

func TestDecryptDetectsTampering(t *testing.T) {
	ks := newKeys(t)
	enc := encrypt(t, sortedPlain, ks.Recipients[0])
	cases := map[string]func(m map[string]any){
		"lastmodified changed": func(m map[string]any) {
			m["sops"].(map[string]any)["lastmodified"] = "2020-01-01T00:00:00Z"
		},
		"values swapped": func(m map[string]any) {
			sd := m["spec"].(map[string]any)["stringData"].(map[string]any)
			sd["a"], sd["b"] = sd["b"], sd["a"]
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := crypto.Decrypt(viaAPI(t, enc, mutate), ks)
			if !errors.Is(err, crypto.ErrDecrypt) {
				t.Fatalf("got %v, want ErrDecrypt", err)
			}
		})
	}
}

func TestDecryptUnsortedFileFailsWithHint(t *testing.T) {
	ks := newKeys(t)
	unsorted := "spec:\n  scope: solar-prod/db-creds\n  stringData:\n    b: two\n    a: one\n"
	doc := viaAPI(t, encrypt(t, unsorted, ks.Recipients[0]), nil)
	_, err := crypto.Decrypt(doc, ks)
	if !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("got %v, want ErrDecrypt", err)
	}
	if !strings.Contains(err.Error(), "sort_keys") {
		t.Fatalf("error %q does not tell the user to sort keys", err)
	}
}

func TestDecryptRejectsNonAgeKeys(t *testing.T) {
	ks := newKeys(t)
	doc := viaAPI(t, encrypt(t, sortedPlain, ks.Recipients[0]), func(m map[string]any) {
		m["sops"].(map[string]any)["pgp"] = []any{map[string]any{
			"fp": "0000000000000000000000000000000000000000", "enc": "x", "created_at": "2026-01-01T00:00:00Z",
		}}
	})
	if _, err := crypto.Decrypt(doc, ks); !errors.Is(err, crypto.ErrUnsupported) {
		t.Fatalf("got %v, want ErrUnsupported", err)
	}
}

func TestDecryptRejectsPlaintext(t *testing.T) {
	if _, err := crypto.Decrypt([]byte(sortedPlain), newKeys(t)); !errors.Is(err, crypto.ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}
