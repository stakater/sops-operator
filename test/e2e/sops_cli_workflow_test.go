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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/document"
)

// Use case: a developer encrypts with the sops CLI exactly as documented (DESIGN.md §8.2) — the repo's
// .sops.yaml picks the key by path, and `sops encrypt --output-type json <file> | base64` gives the
// value for the SopsSecret or a Helm values file — and the GitOps tool applies it. Later a tenant
// admin re-encrypts the value for new recipients with the documented sops decrypt | sops encrypt pipe.
func TestSopsCLIWorkflow(t *testing.T) {
	t.Parallel()
	prod := namespace(t, "e2e-cli-prod")
	tenantNS, recipient := onboardedTenant(t, "e2e-cli-tenant", prod)
	repo := t.TempDir()
	rules := "creation_rules:\n  - path_regex: ^environments/e2e/\n    age: "
	writeFile(t, filepath.Join(repo, ".sops.yaml"), rules+recipient+"\n")
	// Written as a person would: unsorted, with a comment.
	writeFile(t, filepath.Join(repo, "environments", "e2e", "db-creds.plain.yaml"), "scope: "+prod+"/db-creds\n"+
		"stringData:\n  username: \"app\"\n  password: \""+password+"\" # rotated quarterly\n")

	var s *sopsv1alpha1.SopsSecret
	t.Run("shall decrypt a value encrypted with the sops CLI", func(t *testing.T) {
		value := shell(t, repo, nil,
			`"$SOPS" encrypt --output-type json environments/e2e/db-creds.plain.yaml | base64 | tr -d '\n'`)
		s = sopsSecretWith(t, sopsSecret{Name: "db-creds", Namespace: prod, TenantNamespace: tenantNS}, value)
		if err := k8s.Create(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		out := outputSecret(t, prod)
		if string(out.Data["password"]) != password || string(out.Data["username"]) != "app" {
			t.Fatal("output Secret does not hold the values encrypted with the sops CLI")
		}
		assertGolden(t, s, "decrypted")
	})

	t.Run("shall decrypt a value re-encrypted for new recipients", func(t *testing.T) {
		if s == nil {
			t.Skip("needs the SopsSecret from the previous subtest")
		}
		breakGlassFile, breakGlass, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(repo, ".sops.yaml"), rules+recipient+","+breakGlass+"\n")
		keyFile := filepath.Join(t.TempDir(), "tenant.agekey")
		writeFile(t, keyFile, string(tenantKey(t, tenantNS).Data[crypto.KeyFileField]))

		value := shell(t, repo, []string{"VALUE=" + s.Spec.Encrypted, "SOPS_AGE_KEY_FILE=" + keyFile},
			`printf %s "$VALUE" | base64 -d | "$SOPS" decrypt --input-type json --output-type json /dev/stdin `+
				`| "$SOPS" encrypt --filename-override environments/e2e/db-creds.yaml `+
				`--input-type json --output-type json /dev/stdin `+
				`| base64 | tr -d '\n'`)
		breakGlassKeys, err := crypto.ParseKeyFile(breakGlassFile)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := crypto.DecryptValue(value, breakGlassKeys, document.ScopeFor(prod, "db-creds")); err != nil {
			t.Fatalf("the re-encrypted value is not readable with the added recipient: %v", err)
		}

		since := metav1.Now()
		update(t, s, func() { s.Spec.Encrypted = value })
		waitForNewSync(t, s, &since)
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		if string(outputSecret(t, prod).Data["password"]) != password {
			t.Fatal("output Secret changed after re-encryption")
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

// shell runs a documented command line in dir with the pinned sops CLI as $SOPS and returns its
// standard output.
func shell(t *testing.T, dir string, env []string, script string) string {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "SOPS="+envOr("SOPS", "sops")), env...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s: %v\n%s", script, err, stderr.String())
	}
	return string(out)
}
