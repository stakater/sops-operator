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

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/document"
)

// tenantKey is a generated key: the key file, its parsed identities and its public key.
type tenantKey struct {
	file      []byte
	keys      *crypto.KeySet
	recipient string
}

func newTenantKey(t *testing.T) tenantKey {
	t.Helper()
	file, recipient, err := crypto.GenerateKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := crypto.ParseKeyFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return tenantKey{file: file, keys: keys, recipient: recipient}
}

// repo creates a directory with a .sops.yaml listing recipient for every file.
func repo(t *testing.T, recipient string) string {
	t.Helper()
	t.Setenv("SOPS_CONFIG", "")
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".sops.yaml"), "creation_rules:\n  - path_regex: \\.yaml$\n    age:\n      - "+recipient+"\n")
	return dir
}

const plainSopsSecret = `# Database credentials for my-app.
apiVersion: sops.stakater.com/v1alpha1
kind: SopsSecret
metadata:
  name: db-creds
  namespace: my-app
spec:
  tenantRef:
    name: my-team
    namespace: my-team-sops
  stringData:
    username: app # not secret, but kept together
    password: "0123"
  data:
    cert: AAEC
  deletionPolicy: Retain
`

func run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	stdout, stderr, code := run(t, args...)
	if code != 0 {
		t.Fatalf("sopssecret %v exited %d: %s", args, code, stderr)
	}
	return stdout
}

func readSopsSecret(t *testing.T, raw []byte) *sopsv1alpha1.SopsSecret {
	t.Helper()
	var s sopsv1alpha1.SopsSecret
	if err := yaml.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// decrypted returns the values of s decrypted with keys, after checking each scope line.
func decrypted(t *testing.T, s *sopsv1alpha1.SopsSecret, keys *crypto.KeySet) map[string]string {
	t.Helper()
	out := map[string]string{}
	for key, value := range s.Spec.EncryptedData {
		plain, err := crypto.DecryptValue(string(value), keys)
		if err != nil {
			t.Fatalf("encryptedData.%s: %v", key, err)
		}
		v, err := document.Value(plain, document.ScopeFor(s.Namespace, s.Name, key))
		if err != nil {
			t.Fatalf("encryptedData.%s: %v", key, err)
		}
		out[key] = string(v)
	}
	return out
}

func TestEncrypt(t *testing.T) {
	t.Run("shall encrypt stringData and data in place with the scope of the file", func(t *testing.T) {
		key := newTenantKey(t)
		file := write(t, filepath.Join(repo(t, key.recipient), "my-app", "db-creds.yaml"), plainSopsSecret)
		mustRun(t, "encrypt", "-i", file)

		raw := readFile(t, file)
		s := readSopsSecret(t, raw)
		got := decrypted(t, s, key.keys)
		if len(got) != 3 || got["username"] != "app" || got["password"] != "0123" || got["cert"] != "\x00\x01\x02" {
			t.Fatal("encryptedData does not hold the plaintext values")
		}
		text := string(raw)
		for _, want := range []string{"# Database credentials for my-app.", "deletionPolicy: Retain", "encryptedData:"} {
			if !strings.Contains(text, want) {
				t.Errorf("the encrypted file lost %q:\n%s", want, text)
			}
		}
		if regexp.MustCompile(`(?m)^\s+(stringData|data):`).MatchString(text) {
			t.Errorf("the encrypted file still holds plaintext fields:\n%s", text)
		}
	})

	t.Run("shall keep encrypted keys and replace those given again in plaintext", func(t *testing.T) {
		key := newTenantKey(t)
		file := write(t, filepath.Join(repo(t, key.recipient), "db-creds.yaml"), plainSopsSecret)
		mustRun(t, "encrypt", "-i", file)
		before := readSopsSecret(t, readFile(t, file)).Spec.EncryptedData

		changed := strings.Replace(string(readFile(t, file)), "spec:\n", "spec:\n  stringData:\n    password: new\n", 1)
		write(t, file, changed)
		mustRun(t, "encrypt", "-i", file)

		s := readSopsSecret(t, readFile(t, file))
		if s.Spec.EncryptedData["username"] != before["username"] || s.Spec.EncryptedData["cert"] != before["cert"] {
			t.Error("keys not given in plaintext were re-encrypted")
		}
		if got := decrypted(t, s, key.keys); got["password"] != "new" {
			t.Errorf("password = %q, want the new value", got["password"])
		}
	})

	t.Run("shall print to stdout without -i", func(t *testing.T) {
		key := newTenantKey(t)
		file := write(t, filepath.Join(repo(t, key.recipient), "db-creds.yaml"), plainSopsSecret)
		out := mustRun(t, "encrypt", file)
		if got := decrypted(t, readSopsSecret(t, []byte(out)), key.keys); got["password"] != "0123" {
			t.Fatal("stdout does not hold the encrypted SopsSecret")
		}
		if string(readFile(t, file)) != plainSopsSecret {
			t.Fatal("the file was changed without -i")
		}
	})

	t.Run("shall require metadata.namespace for the scope", func(t *testing.T) {
		key := newTenantKey(t)
		plain := strings.Replace(plainSopsSecret, "  namespace: my-app\n", "", 1)
		file := write(t, filepath.Join(repo(t, key.recipient), "db-creds.yaml"), plain)
		_, stderr, code := run(t, "encrypt", "-i", file)
		if code != 1 || !strings.Contains(stderr, "metadata.namespace") {
			t.Fatalf("exit %d, stderr %q; want 1 and a message naming metadata.namespace", code, stderr)
		}
		if string(readFile(t, file)) != plain {
			t.Fatal("the file was changed")
		}
	})

	t.Run("shall change only SopsSecrets in a multi-document file", func(t *testing.T) {
		key := newTenantKey(t)
		configMap := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\ndata:\n  mode: plain\n"
		file := write(t, filepath.Join(repo(t, key.recipient), "app.yaml"), configMap+"---\n"+plainSopsSecret)
		mustRun(t, "encrypt", "-i", file)

		docs := strings.Split(string(readFile(t, file)), "---\n")
		if len(docs) != 2 || docs[0] != configMap {
			t.Fatalf("the ConfigMap changed:\n%s", readFile(t, file))
		}
		if got := decrypted(t, readSopsSecret(t, []byte(docs[1])), key.keys); got["password"] != "0123" {
			t.Fatal("the SopsSecret was not encrypted")
		}
	})

	t.Run("shall walk a directory and skip files that are not YAML", func(t *testing.T) {
		key := newTenantKey(t)
		dir := repo(t, key.recipient)
		secret := write(t, filepath.Join(dir, "a", "db-creds.yaml"), plainSopsSecret)
		const template = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: {{ .Values.name }}\n  {{- include \"x\" . }}\n"
		helm := write(t, filepath.Join(dir, "b", "template.yaml"), template)
		_, stderr, code := run(t, "encrypt", "-i", dir)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		if got := decrypted(t, readSopsSecret(t, readFile(t, secret)), key.keys); got["password"] != "0123" {
			t.Fatal("the SopsSecret in the directory was not encrypted")
		}
		if string(readFile(t, helm)) != template || !strings.Contains(stderr, "template.yaml") {
			t.Fatalf("want the template unchanged and named in a warning, stderr %q", stderr)
		}
	})
}

func TestRotate(t *testing.T) {
	t.Run("shall re-encrypt every value for the recipients .sops.yaml lists now", func(t *testing.T) {
		oldKey, newKey := newTenantKey(t), newTenantKey(t)
		dir := repo(t, oldKey.recipient)
		file := write(t, filepath.Join(dir, "my-app", "db-creds.yaml"), plainSopsSecret)
		mustRun(t, "encrypt", "-i", file)

		write(t, filepath.Join(dir, ".sops.yaml"), "creation_rules:\n  - age: "+newKey.recipient+"\n")
		identity := write(t, filepath.Join(t.TempDir(), "old.agekey"), string(oldKey.file))
		mustRun(t, "rotate", "--identity", identity, dir)

		s := readSopsSecret(t, readFile(t, file))
		if got := decrypted(t, s, newKey.keys); got["password"] != "0123" || got["username"] != "app" || got["cert"] != "\x00\x01\x02" {
			t.Fatal("the rotated values do not decrypt to the original plaintext with the new key")
		}
		if _, err := crypto.DecryptValue(string(s.Spec.EncryptedData["password"]), oldKey.keys); !errors.Is(err, crypto.ErrNotRecipient) {
			t.Fatalf("decrypting with the old key: got %v, want ErrNotRecipient", err)
		}
	})

	t.Run("shall refuse a value whose scope does not match its file", func(t *testing.T) {
		key := newTenantKey(t)
		dir := repo(t, key.recipient)
		file := write(t, filepath.Join(dir, "db-creds.yaml"), plainSopsSecret)
		mustRun(t, "encrypt", "-i", file)
		// The same file under another name: its values carry the scope my-app/db-creds/<key>.
		copied := write(t, filepath.Join(dir, "copy.yaml"), strings.Replace(string(readFile(t, file)), "name: db-creds", "name: copy", 1))
		before := readFile(t, copied)

		identity := write(t, filepath.Join(t.TempDir(), "key.agekey"), string(key.file))
		_, stderr, code := run(t, "rotate", "--identity", identity, copied)
		if code != 1 || !strings.Contains(stderr, "scope") {
			t.Fatalf("exit %d, stderr %q; want 1 and a scope error", code, stderr)
		}
		if !bytes.Equal(readFile(t, copied), before) {
			t.Fatal("the file was changed")
		}
	})
}

func TestUsage(t *testing.T) {
	for name, args := range map[string][]string{
		"no command":            nil,
		"unknown command":       {"edit", "x.yaml"},
		"no files":              {"encrypt", "-i"},
		"rotate, no identity":   {"rotate", "."},
		"stdout, several files": {"encrypt", "a.yaml", "b.yaml"},
	} {
		t.Run("shall exit 2 for "+name, func(t *testing.T) {
			if _, _, code := run(t, args...); code != 2 {
				t.Fatalf("exit %d, want 2", code)
			}
		})
	}
}
