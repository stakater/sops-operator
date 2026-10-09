package crypto_test

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/stakater/sops-operator/internal/crypto"
)

func TestGenerateKeyFileIsPostQuantum(t *testing.T) {
	keyFile, recipient, err := crypto.GenerateKeyFile(time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	if !strings.HasPrefix(recipient, "age1pq1") {
		t.Fatalf("recipient %.12q… is not post-quantum", recipient)
	}
	if !bytes.Contains(keyFile, []byte("# public key: "+recipient)) {
		t.Fatal("key file does not contain the public key comment")
	}
	ks, err := crypto.ParseKeyFile(keyFile)
	if err != nil {
		t.Fatalf("ParseKeyFile: %v", err)
	}
	if len(ks.Recipients) != 1 || ks.Recipients[0] != recipient {
		t.Fatal("parsed recipient does not match the generated one")
	}
}

func TestParseKeyFileAcceptsMixedTypesInOrder(t *testing.T) {
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
}

func TestParseKeyFileRejectsWithoutLeakingKeyMaterial(t *testing.T) {
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	truncated := x.String()[:len(x.String())-4]
	cases := map[string]string{
		"empty":          "",
		"comments only":  "# public key: age1qqqq\n",
		"ssh key":        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
		"plugin":         "AGE-PLUGIN-YUBIKEY-1QQQQQQQQQQ\n",
		"corrupt x25519": truncated + "\n",
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
}
