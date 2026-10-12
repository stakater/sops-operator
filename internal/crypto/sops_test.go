package crypto_test

import (
	"encoding/json"
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

// wantScope is the scope of sortedPlain.
const wantScope = "solar-prod/db-creds"

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

// viaAPI simulates the Kubernetes API: the document is stored as JSON and returned as JSON with
// keys sorted byte-wise.
func viaAPI(t *testing.T, doc []byte, mutate func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(m)
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// flipType changes the unauthenticated type tag of an encrypted value at spec.<field>[.<key>].
func flipType(field, key string) func(m map[string]any) {
	return func(m map[string]any) {
		spec := m["spec"].(map[string]any)
		if key == "" {
			spec[field] = strings.Replace(spec[field].(string), "type:str", "type:int", 1)
			return
		}
		values := spec[field].(map[string]any)
		values[key] = strings.Replace(values[key].(string), "type:str", "type:int", 1)
	}
}

const leakPlain = `spec:
  scope: solar-prod/db-creds
  stringData:
    password: hunter2-SECRET
`

func TestDecryption(t *testing.T) {
	t.Run("shall decrypt a document from the Kubernetes API", func(t *testing.T) {
		ks := newKeys(t)
		doc := viaAPI(t, encrypt(t, sortedPlain, ks.Recipients[0]), nil)

		recipients, err := crypto.Recipients(doc)
		if err != nil {
			t.Fatalf("Recipients: %v", err)
		}
		if len(recipients) != 1 || recipients[0] != ks.Recipients[0] {
			t.Fatal("Recipients does not return the encryption recipient")
		}

		plain, err := crypto.Decrypt(doc, ks, wantScope)
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
	})

	t.Run("shall decrypt with a key that is not the primary one", func(t *testing.T) {
		oldFile, oldRecipient, err := crypto.GenerateKeyFile(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		newFile, _, err := crypto.GenerateKeyFile(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		// During a rotation the new key is primary and the old one is still listed.
		rotated, err := crypto.ParseKeyFile(append(append(newFile, '\n'), oldFile...))
		if err != nil {
			t.Fatal(err)
		}
		doc := viaAPI(t, encrypt(t, sortedPlain, oldRecipient), nil)
		if _, err := crypto.Decrypt(doc, rotated, wantScope); err != nil {
			t.Fatalf("decrypting with the second identity: %v", err)
		}
	})

	t.Run("shall reject a document not encrypted for the key", func(t *testing.T) {
		owner, other := newKeys(t), newKeys(t)
		doc := viaAPI(t, encrypt(t, sortedPlain, other.Recipients[0]), nil)
		if _, err := crypto.Decrypt(doc, owner, wantScope); !errors.Is(err, crypto.ErrNotRecipient) {
			t.Fatalf("got %v, want ErrNotRecipient", err)
		}
	})

	t.Run("shall detect tampering", func(t *testing.T) {
		ks := newKeys(t)
		enc := encrypt(t, sortedPlain, ks.Recipients[0])
		cases := map[string]func(m map[string]any){
			"when lastmodified changed": func(m map[string]any) {
				m["sops"].(map[string]any)["lastmodified"] = "2020-01-01T00:00:00Z"
			},
			"when values were swapped": func(m map[string]any) {
				sd := m["spec"].(map[string]any)["stringData"].(map[string]any)
				sd["a"], sd["b"] = sd["b"], sd["a"]
			},
		}
		for name, mutate := range cases {
			t.Run(name, func(t *testing.T) {
				_, err := crypto.Decrypt(viaAPI(t, enc, mutate), ks, wantScope)
				if !errors.Is(err, crypto.ErrDecrypt) {
					t.Fatalf("got %v, want ErrDecrypt", err)
				}
			})
		}
	})

	t.Run("shall ask to sort keys when the MAC does not match", func(t *testing.T) {
		ks := newKeys(t)
		unsorted := "spec:\n  scope: solar-prod/db-creds\n  stringData:\n    b: two\n    a: one\n"
		doc := viaAPI(t, encrypt(t, unsorted, ks.Recipients[0]), nil)
		_, err := crypto.Decrypt(doc, ks, wantScope)
		if !errors.Is(err, crypto.ErrDecrypt) {
			t.Fatalf("got %v, want ErrDecrypt", err)
		}
		if !strings.Contains(err.Error(), "sort_keys") {
			t.Fatalf("error %q does not tell the user to sort keys", err)
		}
	})

	t.Run("shall reject non-age keys", func(t *testing.T) {
		ks := newKeys(t)
		doc := viaAPI(t, encrypt(t, sortedPlain, ks.Recipients[0]), func(m map[string]any) {
			m["sops"].(map[string]any)["pgp"] = []any{map[string]any{
				"fp": "0000000000000000000000000000000000000000", "enc": "x", "created_at": "2026-01-01T00:00:00Z",
			}}
		})
		if _, err := crypto.Decrypt(doc, ks, wantScope); !errors.Is(err, crypto.ErrUnsupported) {
			t.Fatalf("got %v, want ErrUnsupported", err)
		}
	})

	t.Run("shall reject plaintext", func(t *testing.T) {
		if _, err := crypto.Decrypt([]byte(sortedPlain), newKeys(t), wantScope); !errors.Is(err, crypto.ErrMalformed) {
			t.Fatalf("got %v, want ErrMalformed", err)
		}
	})

	t.Run("shall not leak plaintext through a tampered type tag", func(t *testing.T) {
		ks := newKeys(t)
		doc := viaAPI(t, encrypt(t, leakPlain, ks.Recipients[0]), flipType("stringData", "password"))
		_, err := crypto.Decrypt(doc, ks, wantScope)
		if !errors.Is(err, crypto.ErrDecrypt) {
			t.Fatalf("got %v, want ErrDecrypt", err)
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("error leaks plaintext: %q", err)
		}
	})

	t.Run("shall check the scope before other values", func(t *testing.T) {
		ks := newKeys(t)
		// A copied file with a tampered value must be rejected by scope, before the value is decrypted.
		doc := viaAPI(t, encrypt(t, leakPlain, ks.Recipients[0]), flipType("stringData", "password"))
		_, err := crypto.Decrypt(doc, ks, "solar-dev/db-creds")
		if !errors.Is(err, crypto.ErrScopeMismatch) {
			t.Fatalf("got %v, want ErrScopeMismatch", err)
		}
		if strings.Contains(err.Error(), "solar-prod") {
			t.Fatalf("error reveals the decrypted scope: %q", err)
		}
	})

	t.Run("shall reject a non-string scope without leaking it", func(t *testing.T) {
		ks := newKeys(t)
		doc := viaAPI(t, encrypt(t, leakPlain, ks.Recipients[0]), flipType("scope", ""))
		_, err := crypto.Decrypt(doc, ks, wantScope)
		if !errors.Is(err, crypto.ErrDecrypt) {
			t.Fatalf("got %v, want ErrDecrypt", err)
		}
		if strings.Contains(err.Error(), "solar-prod") {
			t.Fatalf("error leaks the scope plaintext: %q", err)
		}
	})
}
