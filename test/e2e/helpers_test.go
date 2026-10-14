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
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"gotest.tools/v3/golden"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/yaml"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/crypto/cryptotest"
	"github.com/stakater/sops-operator/test/snapshot"
)

const (
	waitTimeout = 2 * time.Minute
	tenantName  = "my-team"
	// tenantSA is the tenant's ServiceAccount, which the operator creates.
	tenantSA = tenantName + "-sops"
	// password is the plaintext value the use cases encrypt.
	password = "hunter2"
)

// namespace creates a namespace with a fixed name, so snapshots are stable, and deletes it
// after the test. A namespace left over from an earlier run is removed first.
func namespace(t *testing.T, name string) string {
	t.Helper()
	ctx := context.Background()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := k8s.Delete(ctx, ns); err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("delete leftover namespace %s: %v", name, err)
	}
	poll(t, "leftover namespace "+name+" to be gone", func() (bool, error) {
		err := k8s.Get(ctx, client.ObjectKeyFromObject(ns), &corev1.Namespace{})
		return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
	})
	if err := k8s.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
		t.Fatalf("create namespace %s: %v", name, err)
	}
	t.Cleanup(func() { _ = k8s.Delete(context.Background(), ns) })
	return name
}

// render fills a fixture template from test/e2e/fixtures.
func render(t *testing.T, fixture string, data any) []byte {
	t.Helper()
	out, err := renderFile(fixture, data)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// renderFile renders test/e2e/fixtures/<fixture> with data; setup uses it outside a test.
func renderFile(fixture string, data any) ([]byte, error) {
	tmpl, err := template.ParseFiles(filepath.Join(repoRoot(), "test", "e2e", "fixtures", fixture))
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, data); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// apply creates every object of a YAML stream.
func apply(t *testing.T, manifests []byte) {
	t.Helper()
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(manifests), 4096)
	for {
		var obj map[string]any
		if err := dec.Decode(&obj); err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			t.Fatal(err)
		}
		if len(obj) == 0 {
			continue
		}
		u := &unstructured.Unstructured{Object: obj}
		if err := k8s.Create(context.Background(), u); err != nil {
			t.Fatalf("create %s %s/%s: %v", u.GetKind(), u.GetNamespace(), u.GetName(), err)
		}
	}
}

// onboard applies the cluster admin's onboarding for the tenant in tenantNamespace with Secret
// write in writeNamespaces; legacy applies the onboarding of releases before per-tenant
// ServiceAccounts.
func onboard(t *testing.T, legacy bool, tenantNamespace string, writeNamespaces ...string) {
	t.Helper()
	apply(t, render(t, "onboarding.yaml", map[string]any{
		"TenantNamespace": tenantNamespace, "TenantName": tenantName, "WriteNamespaces": writeNamespaces,
		"OperatorNamespace": operatorNamespace, "Legacy": legacy,
	}))
}

// onboardedTenant creates a tenant namespace, onboards it with Secret write in writeNamespaces,
// waits for its key and returns the namespace and the key's recipient.
func onboardedTenant(t *testing.T, tenantNamespace string, writeNamespaces ...string) (string, string) {
	t.Helper()
	return tenantOnboardedAs(t, false, tenantNamespace, writeNamespaces...)
}

// tenantOnboardedAs is onboardedTenant with the legacy onboarding of onboard.
func tenantOnboardedAs(t *testing.T, legacy bool, tenantNamespace string, writeNamespaces ...string) (string, string) {
	t.Helper()
	namespace(t, tenantNamespace)
	onboard(t, legacy, tenantNamespace, writeNamespaces...)
	apply(t, render(t, "sopstenant.yaml", map[string]any{"Name": tenantName, "Namespace": tenantNamespace}))
	tenant := &sopsv1alpha1.SopsTenant{ObjectMeta: metav1.ObjectMeta{Name: tenantName, Namespace: tenantNamespace}}
	waitForReason(t, tenant, sopsv1alpha1.ReasonKeyGenerated, sopsv1alpha1.ReasonKeyLoaded)

	var key corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(tenant), &key); err != nil {
		t.Fatal(err)
	}
	ks, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
	if err != nil {
		t.Fatal(err)
	}
	return tenantNamespace, ks.Recipients[0]
}

// sopsSecret encrypts the sopssecret.yaml fixture for recipient and creates it.
type sopsSecret struct {
	Name, Namespace, Scope, DeletionPolicy string
	TenantNamespace                        string
	StringData                             map[string]string
}

// encryptSopsSecret renders and encrypts the sopssecret.yaml fixture for recipient, as a developer would.
func encryptSopsSecret(t *testing.T, recipient string, s sopsSecret) *sopsv1alpha1.SopsSecret {
	t.Helper()
	if s.DeletionPolicy == "" {
		s.DeletionPolicy = string(sopsv1alpha1.DeletionPolicyDelete)
	}
	data := map[string]any{
		"Name": s.Name, "Namespace": s.Namespace, "Scope": s.Scope, "DeletionPolicy": s.DeletionPolicy,
		"TenantName": tenantName, "TenantNamespace": s.TenantNamespace, "StringData": s.StringData,
	}
	encrypted, err := cryptotest.Encrypt(render(t, "sopssecret.yaml", data), recipient)
	if err != nil {
		t.Fatal(err)
	}
	var out sopsv1alpha1.SopsSecret
	if err := yaml.Unmarshal(encrypted, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

// createSopsSecret encrypts the fixture and applies it, as the GitOps tool would.
func createSopsSecret(t *testing.T, recipient string, s sopsSecret) *sopsv1alpha1.SopsSecret {
	t.Helper()
	obj := encryptSopsSecret(t, recipient, s)
	if err := k8s.Create(context.Background(), obj); err != nil {
		t.Fatalf("create SopsSecret %s/%s: %v", obj.Namespace, obj.Name, err)
	}
	return obj
}

// outputSecret returns the Secret "db-creds" in namespace, the name the use cases deliver.
func outputSecret(t *testing.T, namespace string) *corev1.Secret {
	t.Helper()
	var s corev1.Secret
	if err := k8s.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: "db-creds"}, &s); err != nil {
		t.Fatalf("get Secret %s/db-creds: %v", namespace, err)
	}
	return &s
}

func waitUntilDeleted(t *testing.T, what string, obj client.Object) {
	t.Helper()
	poll(t, what+" to be deleted", func() (bool, error) {
		err := k8s.Get(context.Background(), client.ObjectKeyFromObject(obj), obj)
		return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
	})
}

// waitForNewSync waits until the SopsSecret reports Decrypted with a lastSyncTime after since, i.e.
// it was reconciled again. Timestamps come from the operator, so host clock skew does not matter.
func waitForNewSync(t *testing.T, s *sopsv1alpha1.SopsSecret, since *metav1.Time) {
	t.Helper()
	poll(t, "a new successful sync of "+s.Namespace+"/"+s.Name, func() (bool, error) {
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(s), s); err != nil {
			return false, err
		}
		c := meta.FindStatusCondition(s.Status.Conditions, sopsv1alpha1.ConditionReady)
		synced := s.Status.LastSyncTime != nil && (since == nil || s.Status.LastSyncTime.After(since.Time))
		return synced && c != nil && c.Reason == sopsv1alpha1.ReasonDecrypted, nil
	})
}

// deleteObject deletes obj and fails the test on any error other than NotFound.
func deleteObject(t *testing.T, obj client.Object) {
	t.Helper()
	if err := k8s.Delete(context.Background(), obj); client.IgnoreNotFound(err) != nil {
		t.Fatalf("delete %T %s/%s: %v", obj, obj.GetNamespace(), obj.GetName(), err)
	}
}

// waitForMessage waits until the Ready condition of obj has reason and a message containing text.
func waitForMessage(t *testing.T, obj client.Object, reason, text string) {
	t.Helper()
	poll(t, "Ready "+reason+" with message containing "+text, func() (bool, error) {
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(obj), obj); err != nil {
			return false, client.IgnoreNotFound(err)
		}
		c := readyCondition(obj)
		return c != nil && c.Reason == reason && strings.Contains(c.Message, text), nil
	})
}

// readyCondition returns the Ready condition of a SopsTenant or SopsSecret.
func readyCondition(obj client.Object) *metav1.Condition {
	switch o := obj.(type) {
	case *sopsv1alpha1.SopsTenant:
		return meta.FindStatusCondition(o.Status.Conditions, sopsv1alpha1.ConditionReady)
	case *sopsv1alpha1.SopsSecret:
		return meta.FindStatusCondition(o.Status.Conditions, sopsv1alpha1.ConditionReady)
	}
	return nil
}

// update re-reads obj and applies mutate until the write is not rejected by a concurrent change
// (the operator writes status, which changes the resourceVersion).
func update(t *testing.T, obj client.Object, mutate func()) {
	t.Helper()
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(obj), obj); err != nil {
			return err
		}
		mutate()
		return k8s.Update(context.Background(), obj)
	})
	if err != nil {
		t.Fatalf("update %s/%s: %v", obj.GetNamespace(), obj.GetName(), err)
	}
}

// waitForReason waits until the Ready condition of obj has one of reasons; obj is refreshed in place.
func waitForReason(t *testing.T, obj client.Object, reasons ...string) {
	t.Helper()
	last := ""
	what := "Ready reason " + strings.Join(reasons, " or ") + " on " + obj.GetNamespace() + "/" + obj.GetName()
	poll(t, what, func() (bool, error) {
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(obj), obj); err != nil {
			return false, client.IgnoreNotFound(err)
		}
		var conditions []metav1.Condition
		switch o := obj.(type) {
		case *sopsv1alpha1.SopsTenant:
			conditions = o.Status.Conditions
		case *sopsv1alpha1.SopsSecret:
			conditions = o.Status.Conditions
		}
		c := meta.FindStatusCondition(conditions, sopsv1alpha1.ConditionReady)
		if c == nil {
			return false, nil
		}
		last = c.Reason + ": " + c.Message
		for _, r := range reasons {
			if c.Reason == r {
				return true, nil
			}
		}
		return false, nil
	}, func() string { return "last Ready: " + last })
}

// poll calls cond until it returns true or waitTimeout passes.
func poll(t *testing.T, what string, cond func() (bool, error), detail ...func() string) {
	t.Helper()
	pollFor(t, waitTimeout, what, cond, detail...)
}

// pollFor calls cond until it returns true or timeout passes.
func pollFor(t *testing.T, timeout time.Duration, what string, cond func() (bool, error), detail ...func() string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ok, err := cond()
		if err != nil {
			t.Fatalf("waiting for %s: %v", what, err)
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			msg := "timed out waiting for " + what
			for _, d := range detail {
				msg += "; " + d()
			}
			t.Fatal(msg)
		}
		time.Sleep(time.Second)
	}
}

// usedGolden records the golden files compared in this run, to find obsolete ones.
var (
	usedGoldenMu sync.Mutex
	usedGolden   = map[string]bool{}
)

// assertGolden compares obj, normalized by test/snapshot, with
// testdata/<test>/<kind>-<label>.yaml. UIDs of obj and of related objects are written as
// <uid:kind/name>, so the file shows what a reference points to. Record or update the files with
// `make test-e2e UPDATE_GOLDEN=true`.
func assertGolden(t *testing.T, obj client.Object, label string, related ...client.Object) {
	t.Helper()
	gvk, err := apiutil.GVKForObject(obj, scheme)
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]string{}
	for _, o := range append([]client.Object{obj}, related...) {
		k, err := apiutil.GVKForObject(o, scheme)
		if err != nil {
			t.Fatal(err)
		}
		if o.GetUID() != "" {
			known[string(o.GetUID())] = strings.ToLower(k.Kind) + "/" + o.GetName()
		}
	}
	out, err := snapshot.YAML(obj, scheme, known)
	if err != nil {
		t.Fatalf("snapshot %s: %v", gvk.Kind, err)
	}
	file := strings.ToLower(gvk.Kind) + "-" + strings.ReplaceAll(strings.ToLower(label), " ", "-") + ".yaml"
	name := filepath.Join(t.Name(), file)
	usedGoldenMu.Lock()
	usedGolden[name] = true
	usedGoldenMu.Unlock()
	golden.Assert(t, string(out), name)
}
