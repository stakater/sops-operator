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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

// Use case: a tenant admin rotates the tenant key through GitOps (DESIGN.md §8.3): the operator
// prepares the next key, scripts/rotate.sh adds it to the files in the GitOps directory, the GitOps
// tool applies them, and the operator completes the rotation.
func TestGitOpsKeyRotation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	prodA := namespace(t, "e2e-gitops-rotate-a")
	prodB := namespace(t, "e2e-gitops-rotate-b")
	tenantNS, recipient := onboardedTenant(t, "e2e-gitops-rotate", prodA, prodB)

	// The GitOps directory: the repo's .sops.yaml, the tenant and one SopsSecret per namespace.
	repo := t.TempDir()
	sopsConfig := filepath.Join(repo, ".sops.yaml")
	writeFile(t, sopsConfig, "creation_rules:\n  - path_regex: \\.sops\\.ya?ml$\n    age: "+recipient+"\n")
	tenantFile := filepath.Join(repo, "tenant.yaml")
	tenantYAML := render(t, "sopstenant.yaml", map[string]any{"Name": tenantName, "Namespace": tenantNS})
	writeFile(t, tenantFile, string(tenantYAML))
	values := map[string]string{prodA: "password-a", prodB: "password-b"}
	files := make([]string, 0, 2)
	secrets := make([]*sopsv1alpha1.SopsSecret, 0, 2)
	for _, ns := range []string{prodA, prodB} {
		obj := encryptSopsSecret(t, recipient, sopsSecret{
			Name: "db-creds", Namespace: ns, Scope: ns + "/db-creds", TenantNamespace: tenantNS,
			StringData: map[string]string{"password": values[ns]},
		})
		out, err := yaml.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(repo, ns, "db-creds.sops.yaml")
		writeFile(t, file, string(out))
		files = append(files, file)
		secrets = append(secrets, &sopsv1alpha1.SopsSecret{})
		secrets[len(secrets)-1].Name, secrets[len(secrets)-1].Namespace = "db-creds", ns
	}
	applyFiles := func(t *testing.T) {
		t.Helper()
		for _, f := range files {
			if out, err := kubectl("", "apply", "-f", f); err != nil {
				t.Fatalf("apply %s: %v\n%s", f, err, out)
			}
		}
	}
	applyFiles(t)
	for _, s := range secrets {
		waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
	}

	tenant := &sopsv1alpha1.SopsTenant{}
	tenant.Name, tenant.Namespace = tenantName, tenantNS
	waitForRotated := func(t *testing.T, reason string, ready func() bool) {
		t.Helper()
		poll(t, "Rotated reason "+reason, func() (bool, error) {
			if err := k8s.Get(ctx, client.ObjectKeyFromObject(tenant), tenant); err != nil {
				return false, err
			}
			c := meta.FindStatusCondition(tenant.Status.Conditions, sopsv1alpha1.ConditionRotated)
			return c != nil && c.Reason == reason && ready(), nil
		}, func() string {
			if c := meta.FindStatusCondition(tenant.Status.Conditions, sopsv1alpha1.ConditionRotated); c != nil {
				return "last Rotated: " + c.Reason + ": " + c.Message
			}
			return "no Rotated condition"
		})
	}

	t.Run("shall prepare the next key when a rotation is started", func(t *testing.T) {
		update(t, tenant, func() { tenant.Spec.StartRotation = true })
		waitForRotated(t, sopsv1alpha1.ReasonRotationPending, func() bool {
			return tenant.Status.Rotation != nil && tenant.Status.Rotation.NextPublicKey != ""
		})
		for _, s := range secrets {
			poll(t, "next recipient of "+s.Namespace+"/"+s.Name, func() (bool, error) {
				if err := k8s.Get(ctx, client.ObjectKeyFromObject(s), s); err != nil {
					return false, err
				}
				return s.Status.Rotation != nil && s.Status.Rotation.NextRecipient != nil, nil
			})
		}
	})

	var next string
	t.Run("shall add the next key to the files with scripts/rotate.sh", func(t *testing.T) {
		if tenant.Status.Rotation == nil {
			t.Skip("needs the rotation from the previous subtest")
		}
		next = tenant.Status.Rotation.NextPublicKey
		// The script wants oc; the e2e environment has kubectl.
		bin := t.TempDir()
		writeFile(t, filepath.Join(bin, "oc"), "#!/usr/bin/env bash\nexec kubectl --context "+kubeContext+" \"$@\"\n")
		if err := os.Chmod(filepath.Join(bin, "oc"), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(filepath.Join(repoRoot(), "scripts", "rotate.sh"), tenantFile, repo)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+filepath.Dir(envOr("YQ", "yq"))+":"+os.Getenv("PATH"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("rotate.sh: %v\n%s", err, out)
		}
		config, err := os.ReadFile(sopsConfig)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(config), next) {
			t.Fatal(".sops.yaml does not list the next key")
		}
	})

	t.Run("shall complete the rotation once the files are applied", func(t *testing.T) {
		if next == "" {
			t.Skip("needs the next key from the previous subtests")
		}
		applyFiles(t)
		update(t, tenant, func() { tenant.Spec.StartRotation = false })
		waitForRotated(t, sopsv1alpha1.ReasonRotationComplete, func() bool { return tenant.Status.Rotation == nil })

		err := k8s.Get(ctx, client.ObjectKey{Namespace: tenantNS, Name: tenantKeySecret + "-next"}, &corev1.Secret{})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("the next key Secret must be deleted, got: %v", err)
		}
		var key corev1.Secret
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: tenantNS, Name: tenantKeySecret}, &key); err != nil {
			t.Fatal(err)
		}
		ks, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
		if err != nil {
			t.Fatal(err)
		}
		if len(ks.Recipients) != 1 || ks.Recipients[0] != next {
			t.Fatalf("the key Secret must hold exactly the next key, got %d keys", len(ks.Recipients))
		}
		for _, s := range secrets {
			waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
			if got := string(outputSecret(t, s.Namespace).Data["password"]); got != values[s.Namespace] {
				t.Fatalf("output Secret in %s changed its value", s.Namespace)
			}
		}
		assertGolden(t, tenant, "rotated")
	})
}
