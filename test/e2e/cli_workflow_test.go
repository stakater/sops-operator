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

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// Use case: a developer encrypts as documented (DESIGN.md §8.2) — the tenant's public key from the
// SopsTenant status in .sops.yaml, a SopsSecret written with plaintext stringData, then
// `sopssecret encrypt -i` — and the GitOps tool applies the file. Without the CLI, a value encrypted
// with the age CLI works too.
func TestCLIWorkflow(t *testing.T) {
	t.Parallel()
	prod := namespace(t, "e2e-cli-prod")
	tenantNS, _ := onboardedTenant(t, "e2e-cli-tenant", prod)
	out, err := kubectl("", "get", "sopstenant", tenantName, "-n", tenantNS, "-o", "jsonpath={.status.publicKey}")
	if err != nil {
		t.Fatal(err)
	}
	publicKey := strings.TrimSpace(out)
	repo := t.TempDir()
	rules := "creation_rules:\n  - path_regex: ^apps/\n    age:\n      - " + publicKey + "\n"
	writeFile(t, filepath.Join(repo, ".sops.yaml"), rules)

	t.Run("shall decrypt a file encrypted with sopssecret and .sops.yaml", func(t *testing.T) {
		const caCert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
		file := filepath.Join(repo, "apps", "db-creds.yaml")
		writeFile(t, file, `apiVersion: sops.stakater.com/v1alpha1
kind: SopsSecret
metadata:
  name: db-creds
  namespace: `+prod+`
spec:
  tenantRef:
    name: `+tenantName+`
    namespace: `+tenantNS+`
  stringData:
    password: `+password+`
    ca.crt: |
      -----BEGIN CERTIFICATE-----
      MIIB
      -----END CERTIFICATE-----
`)
		bin := filepath.Join(t.TempDir(), "sopssecret")
		if _, err := run("", "go", "build", "-o", bin, "./cmd/sopssecret"); err != nil {
			t.Fatal(err)
		}
		runIn(t, repo, "", bin, "encrypt", "-i", file)

		encrypted, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		apply(t, encrypted)
		s := &sopsv1alpha1.SopsSecret{}
		s.Name, s.Namespace = "db-creds", prod
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		secret := outputSecret(t, prod)
		if string(secret.Data["password"]) != password || string(secret.Data["ca.crt"]) != caCert {
			t.Fatal("output Secret does not hold the values encrypted with sopssecret")
		}
		assertGolden(t, s, "decrypted")
	})

	t.Run("shall decrypt a value encrypted with the age CLI", func(t *testing.T) {
		writeFile(t, filepath.Join(repo, "team.pub"), publicKey+"\n")
		// The documented one-liner: the scope line, the value, then age and base64.
		value := runIn(t, repo, "", "sh", "-c", `printf '%s\n%s' "$1" "$2" | "$AGE" -R team.pub | base64 | tr -d '\n'`,
			"sh", prod+"/age-creds/password", password)
		s := sopsSecretWith(t, sopsSecret{Name: "age-creds", Namespace: prod, TenantNamespace: tenantNS},
			map[string]string{"password": value})
		if err := k8s.Create(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		var secret corev1.Secret
		if err := k8s.Get(context.Background(), client.ObjectKey{Namespace: prod, Name: "age-creds"}, &secret); err != nil {
			t.Fatal(err)
		}
		if string(secret.Data["password"]) != password {
			t.Fatal("output Secret does not hold the value encrypted with the age CLI")
		}
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// runIn runs a developer tool in dir with stdin and returns its standard output.
func runIn(t *testing.T, dir, stdin, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(os.Environ(), "AGE="+envOr("AGE", "age"))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}
