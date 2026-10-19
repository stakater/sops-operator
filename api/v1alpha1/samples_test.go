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
package v1alpha1_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/document"
)

// samplesDir holds the samples OLM publishes as alm-examples: the OpenShift console pre-fills its
// "Create" form with them.
const samplesDir = "../../config/samples"

// Use case: a user creates a resource from the operator's page in the OpenShift console.
func TestConfigSamples(t *testing.T) {
	var kustomization struct {
		Resources []string `json:"resources"`
	}
	readYAML(t, filepath.Join(samplesDir, "kustomization.yaml"), &kustomization)
	// samples lists the sample files of each kind in kustomization order; the console pre-fills
	// its form with the first and offers the others under "Samples".
	samples := map[string][]string{}
	for _, file := range kustomization.Resources {
		var typeMeta struct {
			Kind string `json:"kind"`
		}
		readYAML(t, filepath.Join(samplesDir, file), &typeMeta)
		samples[typeMeta.Kind] = append(samples[typeMeta.Kind], filepath.Join(samplesDir, file))
	}

	t.Run("shall provide a sample for every kind", func(t *testing.T) {
		for _, kind := range []string{"SopsTenant", "SopsSecret"} {
			if len(samples[kind]) == 0 {
				t.Errorf("config/samples has no %s", kind)
			}
		}
	})

	t.Run("shall default to a SopsTenant that generates its key", func(t *testing.T) {
		var tenant sopsv1alpha1.SopsTenant
		readYAML(t, requireSample(t, samples, "SopsTenant"), &tenant)
		createInNewNamespace(t, &tenant)
		if tenant.Spec.GenerateKey == nil || !*tenant.Spec.GenerateKey {
			t.Error("the default sample must show generateKey: true")
		}
	})

	t.Run("shall offer a SopsTenant for an existing key Secret", func(t *testing.T) {
		found := false
		for _, file := range samples["SopsTenant"] {
			var tenant sopsv1alpha1.SopsTenant
			readYAML(t, file, &tenant)
			if tenant.Spec.GenerateKey == nil || *tenant.Spec.GenerateKey {
				continue
			}
			found = true
			createInNewNamespace(t, &tenant)
		}
		if !found {
			t.Error("config/samples has no SopsTenant with generateKey: false")
		}
	})

	t.Run("shall accept the SopsSecret sample", func(t *testing.T) {
		var s sopsv1alpha1.SopsSecret
		readYAML(t, requireSample(t, samples, "SopsSecret"), &s)
		createInNewNamespace(t, &s)
		if s.Spec.DeletionPolicy == "" || s.Spec.Type == "" {
			t.Error("the sample must show deletionPolicy and type")
		}
	})

	// A sample with placeholder ciphertext would report DecryptFailed. A real SOPS file for a key
	// nobody holds reports NotRecipient, which tells the user to encrypt for their tenant key.
	t.Run("shall ship a SopsSecret sample encrypted with sops", func(t *testing.T) {
		var s sopsv1alpha1.SopsSecret
		readYAML(t, requireSample(t, samples, "SopsSecret"), &s)
		keyFile, _, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		keys, err := crypto.ParseKeyFile(keyFile)
		if err != nil {
			t.Fatal(err)
		}
		_, err = crypto.DecryptValue(s.Spec.Encrypted, keys, document.ScopeFor(s.Namespace, s.Name))
		if !errors.Is(err, crypto.ErrNotRecipient) {
			t.Fatalf("want ErrNotRecipient from a valid SOPS file, got %v", err)
		}
	})
}

func readYAML(t *testing.T, path string, into any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, into); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// requireSample returns the default (first) sample of kind.
func requireSample(t *testing.T, samples map[string][]string, kind string) string {
	t.Helper()
	if len(samples[kind]) == 0 {
		t.Fatalf("config/samples has no %s", kind)
	}
	return samples[kind][0]
}

// createInNewNamespace creates obj the way the console does: in the user's current project.
func createInNewNamespace(t *testing.T, obj client.Object) {
	t.Helper()
	obj.SetNamespace(env.Namespace(t, "sample"))
	if err := env.Admin.Create(context.Background(), obj); err != nil {
		t.Fatalf("the API server rejects the sample: %v", err)
	}
}
