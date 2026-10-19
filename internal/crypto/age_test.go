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
	"encoding/base64"
	"errors"
	"testing"

	"filippo.io/age"

	"github.com/stakater/sops-operator/internal/crypto"
)

const plain = "my-app-prod/db-creds/password\nhunter2"

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

func x25519Keys(t *testing.T) *crypto.KeySet {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ks, err := crypto.ParseKeyFile([]byte(id.String()))
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func encrypt(t *testing.T, recipients ...string) string {
	t.Helper()
	enc, err := crypto.EncryptValue([]byte(plain), recipients)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return enc
}

func TestEncryption(t *testing.T) {
	t.Run("shall encrypt for several recipients of one kind", func(t *testing.T) {
		x1, x2 := x25519Keys(t), x25519Keys(t)
		for name, pair := range map[string][2]*crypto.KeySet{"post-quantum": {newKeys(t), newKeys(t)}, "X25519": {x1, x2}} {
			enc := encrypt(t, pair[0].Recipients[0], pair[1].Recipients[0])
			for _, ks := range pair {
				if got, err := crypto.DecryptValue(enc, ks); err != nil || string(got) != plain {
					t.Fatalf("%s: decrypting with each recipient's key: %v", name, err)
				}
			}
		}
	})

	// age refuses the mix: the file would be only as strong as its classic recipients.
	t.Run("shall refuse to mix post-quantum and X25519 recipients", func(t *testing.T) {
		_, err := crypto.EncryptValue([]byte(plain), []string{newKeys(t).Recipients[0], x25519Keys(t).Recipients[0]})
		if !errors.Is(err, crypto.ErrRecipient) {
			t.Fatalf("got %v, want ErrRecipient", err)
		}
	})

	t.Run("shall reject recipients that are not age public keys", func(t *testing.T) {
		for name, recipients := range map[string][]string{
			"none":    nil,
			"invalid": {"age1notakey"},
			"ssh":     {"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"},
			"private": {"AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"},
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := crypto.EncryptValue([]byte(plain), recipients); !errors.Is(err, crypto.ErrRecipient) {
					t.Fatalf("got %v, want ErrRecipient", err)
				}
			})
		}
	})
}

func TestDecryption(t *testing.T) {
	t.Run("shall decrypt a base64-encoded age file", func(t *testing.T) {
		ks := newKeys(t)
		got, err := crypto.DecryptValue(encrypt(t, ks.Recipients[0]), ks)
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
		if _, err := crypto.DecryptValue(encrypt(t, oldRecipient), rotated); err != nil {
			t.Fatalf("decrypting with the second identity: %v", err)
		}
	})

	t.Run("shall decrypt a file encrypted for several recipients with each key", func(t *testing.T) {
		a, b := newKeys(t), newKeys(t)
		enc := encrypt(t, a.Recipients[0], b.Recipients[0])
		for name, ks := range map[string]*crypto.KeySet{"first": a, "second": b} {
			if _, err := crypto.DecryptValue(enc, ks); err != nil {
				t.Fatalf("decrypting with the %s recipient's key: %v", name, err)
			}
		}
	})

	// GNU base64 wraps lines and YAML block scalars keep newlines.
	t.Run("shall accept whitespace and line breaks", func(t *testing.T) {
		ks := newKeys(t)
		enc := encrypt(t, ks.Recipients[0])
		got, err := crypto.DecryptValue("\n  "+enc[:76]+"\n"+enc[76:]+"\n", ks)
		if err != nil {
			t.Fatalf("DecryptValue: %v", err)
		}
		if string(got) != plain {
			t.Fatal("decrypted value does not match the plaintext")
		}
	})

	t.Run("shall reject a file not encrypted for the key", func(t *testing.T) {
		owner, other := newKeys(t), newKeys(t)
		if _, err := crypto.DecryptValue(encrypt(t, other.Recipients[0]), owner); !errors.Is(err, crypto.ErrNotRecipient) {
			t.Fatalf("got %v, want ErrNotRecipient", err)
		}
	})

	t.Run("shall detect tampering", func(t *testing.T) {
		ks := newKeys(t)
		raw, err := base64.StdEncoding.DecodeString(encrypt(t, ks.Recipients[0]))
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)-1] ^= 1 // the last byte belongs to the payload's authentication tag
		if _, err := crypto.DecryptValue(base64.StdEncoding.EncodeToString(raw), ks); !errors.Is(err, crypto.ErrDecrypt) {
			t.Fatalf("got %v, want ErrDecrypt", err)
		}
	})

	t.Run("shall reject values that are not base64-encoded age files", func(t *testing.T) {
		for name, value := range map[string]string{
			"plaintext":        plain,
			"base64 plaintext": base64.StdEncoding.EncodeToString([]byte(plain)),
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := crypto.DecryptValue(value, newKeys(t)); !errors.Is(err, crypto.ErrMalformed) {
					t.Fatalf("got %v, want ErrMalformed", err)
				}
			})
		}
	})
}
