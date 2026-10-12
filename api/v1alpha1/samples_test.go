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
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

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
	samples := map[string]string{}
	for _, file := range kustomization.Resources {
		var typeMeta struct {
			Kind string `json:"kind"`
		}
		readYAML(t, filepath.Join(samplesDir, file), &typeMeta)
		samples[typeMeta.Kind] = filepath.Join(samplesDir, file)
	}

	t.Run("shall provide a sample for every kind", func(t *testing.T) {
		for _, kind := range []string{"SopsTenant", "SopsSecret"} {
			if samples[kind] == "" {
				t.Errorf("config/samples has no %s", kind)
			}
		}
	})

	t.Run("shall accept the SopsTenant sample", func(t *testing.T) {
		var tenant sopsv1alpha1.SopsTenant
		readYAML(t, requireSample(t, samples, "SopsTenant"), &tenant)
		createInNewNamespace(t, &tenant)
		if tenant.Spec.GenerateKey == nil || !*tenant.Spec.GenerateKey {
			t.Error("the sample must show generateKey: true")
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

	// A sample with placeholder ciphertext would report DecryptFailed. A real SOPS document for a
	// key nobody holds reports NotRecipient, which tells the user to encrypt for their tenant key.
	t.Run("shall ship a SopsSecret sample encrypted with sops", func(t *testing.T) {
		var s sopsv1alpha1.SopsSecret
		readYAML(t, requireSample(t, samples, "SopsSecret"), &s)
		doc, err := document.Canonical(&s)
		if err != nil {
			t.Fatal(err)
		}
		keyFile, _, err := crypto.GenerateKeyFile(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		keys, err := crypto.ParseKeyFile(keyFile)
		if err != nil {
			t.Fatal(err)
		}
		_, err = crypto.Decrypt(doc, keys, document.ScopeFor(s.Namespace, s.Name))
		if !errors.Is(err, crypto.ErrNotRecipient) {
			t.Fatalf("want ErrNotRecipient from a valid SOPS document, got %v", err)
		}
		// Without the key, decryption stops at the recipients; check every value is real ciphertext.
		values := map[string]string{"spec.scope": s.Spec.Scope, "sops.mac": s.Sops.MAC}
		for k, v := range s.Spec.StringData {
			values["spec.stringData."+k] = v
		}
		for k, v := range s.Spec.Data {
			values["spec.data."+k] = v
		}
		for path, v := range values {
			if !isSopsCiphertext(v) {
				t.Errorf("%s is not SOPS ciphertext: %s", path, v)
			}
		}
	})
}

// sopsCiphertext matches a value written by `sops encrypt`: AES-256-GCM with a 32-byte IV and a
// 16-byte tag, base64-encoded.
var sopsCiphertext = regexp.MustCompile(`^ENC\[AES256_GCM,data:([A-Za-z0-9+/=]+),iv:([A-Za-z0-9+/=]+),tag:([A-Za-z0-9+/=]+),type:str\]$`)

func isSopsCiphertext(v string) bool {
	m := sopsCiphertext.FindStringSubmatch(v)
	if m == nil {
		return false
	}
	iv, errIV := base64.StdEncoding.DecodeString(m[2])
	tag, errTag := base64.StdEncoding.DecodeString(m[3])
	return errIV == nil && errTag == nil && len(iv) == 32 && len(tag) == 16
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

func requireSample(t *testing.T, samples map[string]string, kind string) string {
	t.Helper()
	if samples[kind] == "" {
		t.Fatalf("config/samples has no %s", kind)
	}
	return samples[kind]
}

// createInNewNamespace creates obj the way the console does: in the user's current project.
func createInNewNamespace(t *testing.T, obj client.Object) {
	t.Helper()
	obj.SetNamespace(env.Namespace(t, "sample"))
	if err := env.Admin.Create(context.Background(), obj); err != nil {
		t.Fatalf("the API server rejects the sample: %v", err)
	}
}
