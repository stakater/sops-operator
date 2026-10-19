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

package crypto_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/crypto/cryptotest"
)

const (
	plain     = "scope: my-app-prod/db-creds\nstringData:\n  b: two\n  a: one\n"
	wantScope = "my-app-prod/db-creds"
	leakPlain = "scope: my-app-prod/db-creds\nstringData:\n  password: hunter2-SECRET\n"
)

func newKeys(t *testing.T) *crypto.KeySet {
	t.Helper()
	keyFile, _, err := crypto.GenerateKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	ks, err := crypto.ParseKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// sopsFile encrypts plain like `sops encrypt` for the recipients.
func sopsFile(t *testing.T, plain string, opts cryptotest.Options, recipients ...string) string {
	t.Helper()
	file, err := cryptotest.EncryptFile([]byte(plain), opts, recipients...)
	if err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}
	return string(file)
}

// value encodes a sops file as a SopsSecret holds it: `... | base64`.
func value(file string) string { return base64.StdEncoding.EncodeToString([]byte(file)) }

// encValue returns the encrypted value at stringData.<key> of a JSON sops file.
func encValue(t *testing.T, file, key string) string {
	t.Helper()
	var doc struct {
		StringData map[string]string `json:"stringData"`
	}
	if err := json.Unmarshal([]byte(file), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.StringData[key]
}

func decrypted(t *testing.T, got []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("decrypted document is not JSON: %v", err)
	}
	return doc
}

func TestDecryption(t *testing.T) {
	t.Run("shall decrypt sops output in JSON and YAML with keys in any order", func(t *testing.T) {
		ks := newKeys(t)
		for name, opts := range map[string]cryptotest.Options{"JSON": {}, "YAML": {YAML: true}} {
			t.Run(name, func(t *testing.T) {
				got, err := crypto.DecryptValue(value(sopsFile(t, plain, opts, ks.Recipients[0])), ks, wantScope)
				if err != nil {
					t.Fatalf("DecryptValue: %v", err)
				}
				doc := decrypted(t, got)
				sd, _ := doc["stringData"].(map[string]any)
				if doc["scope"] != wantScope || sd["a"] != "one" || sd["b"] != "two" {
					t.Fatal("decrypted values do not match the plaintext")
				}
			})
		}
	})

	// The documented form: `sops encrypt --output-type json <file> | jq -c .`, one line without base64.
	t.Run("shall decrypt the sops JSON file as text, compact or as written", func(t *testing.T) {
		ks := newKeys(t)
		file := sopsFile(t, plain, cryptotest.Options{}, ks.Recipients[0])
		var compact bytes.Buffer
		if err := json.Compact(&compact, []byte(file)); err != nil {
			t.Fatal(err)
		}
		for name, v := range map[string]string{"compact": compact.String(), "as written": file} {
			t.Run(name, func(t *testing.T) {
				got, err := crypto.DecryptValue(v, ks, wantScope)
				if err != nil {
					t.Fatalf("DecryptValue: %v", err)
				}
				if decrypted(t, got)["scope"] != wantScope {
					t.Fatal("decrypted scope does not match the plaintext")
				}
			})
		}
	})

	// GNU base64 wraps lines at 76 characters; YAML block scalars add a final newline.
	t.Run("shall accept base64 with line breaks", func(t *testing.T) {
		ks := newKeys(t)
		v := value(sopsFile(t, plain, cryptotest.Options{}, ks.Recipients[0]))
		var wrapped strings.Builder
		for i := 0; i < len(v); i += 76 {
			wrapped.WriteString(v[i:min(i+76, len(v))] + "\n")
		}
		if _, err := crypto.DecryptValue(wrapped.String(), ks, wantScope); err != nil {
			t.Fatalf("DecryptValue: %v", err)
		}
	})

	t.Run("shall decrypt with a key that is not the primary one", func(t *testing.T) {
		oldFile, oldRecipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		newFile, _, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		// During a rotation the new key is primary and the old one is still listed.
		rotated, err := crypto.ParseKeyFile(append(append(newFile, '\n'), oldFile...))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := crypto.DecryptValue(value(sopsFile(t, plain, cryptotest.Options{}, oldRecipient)), rotated, wantScope); err != nil {
			t.Fatalf("decrypting with the second identity: %v", err)
		}
	})

	t.Run("shall reject a file not encrypted for the key", func(t *testing.T) {
		owner, other := newKeys(t), newKeys(t)
		_, err := crypto.DecryptValue(value(sopsFile(t, plain, cryptotest.Options{}, other.Recipients[0])), owner, wantScope)
		if !errors.Is(err, crypto.ErrNotRecipient) {
			t.Fatalf("got %v, want ErrNotRecipient", err)
		}
	})

	t.Run("shall detect tampering", func(t *testing.T) {
		ks := newKeys(t)
		file := sopsFile(t, plain, cryptotest.Options{}, ks.Recipients[0])
		a, b := encValue(t, file, "a"), encValue(t, file, "b")
		cases := map[string]string{
			"when values were swapped": strings.NewReplacer(a, b, b, a).Replace(file),
			"when lastmodified changed": regexp.MustCompile(`"lastmodified": "[^"]*"`).
				ReplaceAllString(file, `"lastmodified": "2020-01-01T00:00:00Z"`),
		}
		for name, tampered := range cases {
			t.Run(name, func(t *testing.T) {
				if _, err := crypto.DecryptValue(value(tampered), ks, wantScope); !errors.Is(err, crypto.ErrDecrypt) {
					t.Fatalf("got %v, want ErrDecrypt", err)
				}
			})
		}
	})

	t.Run("shall reject values left unencrypted by encrypted_regex", func(t *testing.T) {
		ks := newKeys(t)
		file := sopsFile(t, leakPlain, cryptotest.Options{EncryptedRegex: "^scope$"}, ks.Recipients[0])
		_, err := crypto.DecryptValue(value(file), ks, wantScope)
		if !errors.Is(err, crypto.ErrUnencrypted) || !strings.Contains(err.Error(), "stringData.password") {
			t.Fatalf("got %v, want ErrUnencrypted naming stringData.password", err)
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("error leaks the plaintext: %q", err)
		}
	})

	t.Run("shall reject non-age keys", func(t *testing.T) {
		ks := newKeys(t)
		file := strings.Replace(sopsFile(t, plain, cryptotest.Options{}, ks.Recipients[0]), `"sops": {`,
			`"sops": {"pgp": [{"fp": "0000000000000000000000000000000000000000", "enc": "x", "created_at": "2026-01-01T00:00:00Z"}],`, 1)
		if _, err := crypto.DecryptValue(value(file), ks, wantScope); !errors.Is(err, crypto.ErrUnsupported) {
			t.Fatalf("got %v, want ErrUnsupported", err)
		}
	})

	t.Run("shall reject values that are not sops files", func(t *testing.T) {
		for name, v := range map[string]string{
			"plaintext": plain, "base64 plaintext": value(plain), "JSON plaintext": `{"scope": "a/b"}`,
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := crypto.DecryptValue(v, newKeys(t), wantScope); !errors.Is(err, crypto.ErrMalformed) {
					t.Fatalf("got %v, want ErrMalformed", err)
				}
			})
		}
	})

	t.Run("shall not leak plaintext through a tampered type tag", func(t *testing.T) {
		ks := newKeys(t)
		file := sopsFile(t, leakPlain, cryptotest.Options{}, ks.Recipients[0])
		enc := encValue(t, file, "password")
		file = strings.Replace(file, enc, strings.Replace(enc, "type:str", "type:int", 1), 1)
		_, err := crypto.DecryptValue(value(file), ks, wantScope)
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
		file := sopsFile(t, leakPlain, cryptotest.Options{}, ks.Recipients[0])
		enc := encValue(t, file, "password")
		file = strings.Replace(file, enc, strings.Replace(enc, "type:str", "type:int", 1), 1)
		_, err := crypto.DecryptValue(value(file), ks, "my-app-dev/db-creds")
		if !errors.Is(err, crypto.ErrScopeMismatch) {
			t.Fatalf("got %v, want ErrScopeMismatch", err)
		}
		if strings.Contains(err.Error(), "my-app-prod") {
			t.Fatalf("error reveals the decrypted scope: %q", err)
		}
	})
}
