package crypto_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/stakater/sops-operator/internal/crypto"
)

func TestKeyFile(t *testing.T) {
	t.Run("shall generate a post-quantum key", func(t *testing.T) {
		keyFile, recipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatalf("GenerateKeyFile: %v", err)
		}
		if !strings.HasPrefix(recipient, "age1pq1") {
			t.Fatalf("recipient %.12q… is not post-quantum", recipient)
		}
		if lines := strings.Split(strings.TrimSpace(string(keyFile)), "\n"); len(lines) != 1 ||
			!strings.HasPrefix(lines[0], "AGE-SECRET-KEY-PQ-1") {
			t.Fatal("the key file must be the private key alone")
		}
		ks, err := crypto.ParseKeyFile(keyFile)
		if err != nil {
			t.Fatalf("ParseKeyFile: %v", err)
		}
		if len(ks.Recipients) != 1 || ks.Recipients[0] != recipient {
			t.Fatal("parsed recipient does not match the generated one")
		}
	})

	t.Run("shall accept X25519 and post-quantum keys in file order", func(t *testing.T) {
		pq, err := age.GenerateHybridIdentity()
		if err != nil {
			t.Fatal(err)
		}
		x, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		// CRLF line endings, trailing spaces, blank lines and comments must be tolerated.
		file := "# created: 2026-10-09T10:00:00Z\r\n" + pq.String() + "  \r\n\r\n# old key\n" + x.String() + "\n"

		ks, err := crypto.ParseKeyFile([]byte(file))
		if err != nil {
			t.Fatalf("ParseKeyFile: %v", err)
		}
		want := []string{pq.Recipient().String(), x.Recipient().String()}
		if !reflect.DeepEqual(ks.Recipients, want) {
			t.Fatal("recipients are not in file order")
		}
		if len(ks.Identities) != 2 {
			t.Fatalf("got %d identities, want 2", len(ks.Identities))
		}
	})

	t.Run("shall reject unsupported keys without leaking key material", func(t *testing.T) {
		x, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		truncated := x.String()[:len(x.String())-4]
		cases := map[string]string{
			"shall reject an empty file":             "",
			"shall reject a file with only comments": "# public key: age1qqqq\n",
			"shall reject an SSH key":                "-----BEGIN OPENSSH PRIVATE KEY-----\n",
			"shall reject a plugin identity":         "AGE-PLUGIN-YUBIKEY-1QQQQQQQQQQ\n",
			"shall reject a corrupt X25519 key":      truncated + "\n",
		}
		for name, in := range cases {
			t.Run(name, func(t *testing.T) {
				_, err := crypto.ParseKeyFile([]byte(in))
				if !errors.Is(err, crypto.ErrKeyInvalid) {
					t.Fatalf("got %v, want ErrKeyInvalid", err)
				}
				if strings.Contains(err.Error(), "AGE-SECRET-KEY") || strings.Contains(err.Error(), "AGE-PLUGIN") {
					t.Fatal("error message contains key material")
				}
			})
		}
	})
}
