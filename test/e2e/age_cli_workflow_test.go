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

// Use case: a developer encrypts with the age CLI exactly as documented (DESIGN.md §8.2) — the
// public key from the SopsTenant status, then `age -r <public key> -a` — and the GitOps tool applies
// the SopsSecret holding the armored file.
func TestAgeCLIWorkflow(t *testing.T) {
	t.Parallel()
	t.Run("shall decrypt a file encrypted with the age CLI", func(t *testing.T) {
		t.Parallel()
		prod := namespace(t, "e2e-cli-prod")
		tenantNS, _ := onboardedTenant(t, "e2e-cli-tenant", prod)
		publicKey, err := kubectl("", "get", "sopstenant", tenantName, "-n", tenantNS, "-o", "jsonpath={.status.publicKey}")
		if err != nil {
			t.Fatal(err)
		}

		dir := t.TempDir()
		// Written as a person would: unsorted, with a comment.
		writeFile(t, filepath.Join(dir, "db-creds.yaml"), `scope: `+prod+`/db-creds
stringData:
  username: "app"
  password: "hunter2" # rotated quarterly
`)
		runIn(t, dir, envOr("AGE", "age"), "-r", strings.TrimSpace(publicKey), "-a", "-o", "db-creds.age", "db-creds.yaml")
		encrypted, err := os.ReadFile(filepath.Join(dir, "db-creds.age"))
		if err != nil {
			t.Fatal(err)
		}

		s := sopsSecretWith(t, sopsSecret{Name: "db-creds", Namespace: prod, TenantNamespace: tenantNS}, string(encrypted))
		if err := k8s.Create(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		out := outputSecret(t, prod)
		if string(out.Data["password"]) != password || string(out.Data["username"]) != "app" {
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

// runIn runs a developer tool in dir.
func runIn(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}
