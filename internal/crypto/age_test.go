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
	"errors"
	"strings"
	"testing"

	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/crypto/cryptotest"
)

const plain = "scope: my-app-prod/db-creds\nstringData:\n  password: hunter2\n"

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

func encrypt(t *testing.T, recipients ...string) string {
	t.Helper()
	enc, err := cryptotest.Encrypt([]byte(plain), recipients...)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return enc
}

func TestDecryption(t *testing.T) {
	t.Run("shall decrypt an armored age file", func(t *testing.T) {
		ks := newKeys(t)
		got, err := crypto.Decrypt(encrypt(t, ks.Recipients[0]), ks)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if string(got) != plain {
			t.Fatal("decrypted payload does not match the plaintext")
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
		if _, err := crypto.Decrypt(encrypt(t, oldRecipient), rotated); err != nil {
			t.Fatalf("decrypting with the second identity: %v", err)
		}
	})

	t.Run("shall decrypt a file encrypted for several recipients with each key", func(t *testing.T) {
		a, b := newKeys(t), newKeys(t)
		enc := encrypt(t, a.Recipients[0], b.Recipients[0])
		for name, ks := range map[string]*crypto.KeySet{"first": a, "second": b} {
			if _, err := crypto.Decrypt(enc, ks); err != nil {
				t.Fatalf("decrypting with the %s recipient's key: %v", name, err)
			}
		}
	})

	// Helm and YAML block scalars add or keep newlines and indentation around the value.
	t.Run("shall accept surrounding whitespace", func(t *testing.T) {
		ks := newKeys(t)
		got, err := crypto.Decrypt("\n  "+encrypt(t, ks.Recipients[0])+"\n\n", ks)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if string(got) != plain {
			t.Fatal("decrypted payload does not match the plaintext")
		}
	})

	t.Run("shall reject a file not encrypted for the key", func(t *testing.T) {
		owner, other := newKeys(t), newKeys(t)
		if _, err := crypto.Decrypt(encrypt(t, other.Recipients[0]), owner); !errors.Is(err, crypto.ErrNotRecipient) {
			t.Fatalf("got %v, want ErrNotRecipient", err)
		}
	})

	t.Run("shall detect tampering", func(t *testing.T) {
		ks := newKeys(t)
		enc := encrypt(t, ks.Recipients[0])
		lines := strings.Split(enc, "\n")
		// The last line before the footer holds the end of the payload; change one character.
		i := len(lines) - 3
		r := []rune(lines[i])
		r[0] = map[bool]rune{true: 'B', false: 'A'}[r[0] == 'A']
		lines[i] = string(r)
		if _, err := crypto.Decrypt(strings.Join(lines, "\n"), ks); !errors.Is(err, crypto.ErrDecrypt) {
			t.Fatalf("got %v, want ErrDecrypt", err)
		}
	})

	t.Run("shall reject plaintext", func(t *testing.T) {
		if _, err := crypto.Decrypt(plain, newKeys(t)); !errors.Is(err, crypto.ErrMalformed) {
			t.Fatalf("got %v, want ErrMalformed", err)
		}
	})
}
