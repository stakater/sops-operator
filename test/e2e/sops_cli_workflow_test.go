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
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// Use case: a developer encrypts with the sops CLI exactly as documented (DESIGN.md §8.2) — the repo's
// .sops.yaml, yq for the scope and key order, then `sops encrypt` — and the GitOps tool applies the file.
func TestSopsCLIWorkflow(t *testing.T) {
	t.Run("shall decrypt a file encrypted with the sops CLI", func(t *testing.T) {
		prod := namespace(t, "e2e-cli-prod")
		tenantNS, recipient := onboardedTenant(t, "e2e-cli-tenant", prod)

		repo := t.TempDir()
		writeFile(t, filepath.Join(repo, ".sops.yaml"), `creation_rules:
  - path_regex: \.sops\.ya?ml$
    encrypted_regex: ^(data|stringData|scope)$
    mac_only_encrypted: true
    age: `+recipient+"\n")
		// Written in the order a person would, not sorted.
		file := filepath.Join(repo, "prod", "db-creds.sops.yaml")
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
    username: app
    password: "hunter2"
`)

		yq, sops := envOr("YQ", "yq"), envOr("SOPS", "sops")
		runIn(t, repo, yq, "-i", `.spec.scope = .metadata.namespace + "/" + .metadata.name`, "prod/db-creds.sops.yaml")
		runIn(t, repo, yq, "-i", "sort_keys(..)", "prod/db-creds.sops.yaml")
		runIn(t, repo, sops, "encrypt", "-i", "prod/db-creds.sops.yaml")

		encrypted, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		apply(t, encrypted)
		s := &sopsv1alpha1.SopsSecret{}
		s.Name, s.Namespace = "db-creds", prod
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
		out := outputSecret(t, prod)
		if string(out.Data["password"]) != password || string(out.Data["username"]) != "app" {
			t.Fatal("output Secret does not hold the values encrypted with the sops CLI")
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

// runIn runs a developer tool in dir, where sops discovers .sops.yaml.
func runIn(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}
