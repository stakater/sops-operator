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

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// Use case: a developer encrypts each value as documented (DESIGN.md §8.2) — the public key from the
// SopsTenant status, then hack/encrypt-value.sh, which runs the age CLI — and the GitOps tool applies
// the SopsSecret holding the encrypted values.
func TestAgeCLIWorkflow(t *testing.T) {
	t.Parallel()
	t.Run("shall decrypt values encrypted with the age CLI", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-cli-prod")
		tenantNS, _ := onboardedTenant(t, "e2e-cli-tenant", prod)
		publicKey, err := kubectl("", "get", "sopstenant", tenantName, "-n", tenantNS, "-o", "jsonpath={.status.publicKey}")
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "team.pub"), publicKey+"\n")
		const caCert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
		writeFile(t, filepath.Join(dir, "ca.crt"), caCert)

		script := filepath.Join(repoRoot(), "hack", "encrypt-value.sh")
		target := prod + "/db-creds"
		s := sopsSecretWith(t, sopsSecret{Name: "db-creds", Namespace: prod, TenantNamespace: tenantNS}, map[string]string{
			"password": runIn(t, dir, password, script, "team.pub", target, "password"),
			"ca.crt":   runIn(t, dir, "", script, "team.pub", target, "ca.crt", "ca.crt"),
		})
		if err := k8s.Create(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		out := outputSecret(t, prod)
		if string(out.Data["password"]) != password || string(out.Data["ca.crt"]) != caCert {
			t.Fatal("output Secret does not hold the values encrypted with the age CLI")
		}
		assertGolden(t, s, "decrypted")
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
