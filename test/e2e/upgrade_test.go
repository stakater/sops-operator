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
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

// upgradePaths are the upgrade tests derived from catalog/channels.yaml: for every version a
// customer can run, the path OLM takes to the channel head, reduced to the smallest set that
// traverses every edge. Edit them in the change that edits the channel graph. The fresh install of
// each channel head is `make test-e2e`.
// legacyOnboarding marks a from version that predates per-tenant ServiceAccounts: the tenant is
// onboarded with bindings to "sops", and the new onboarding is applied after the upgrade.
var upgradePaths = []struct {
	channel, from, to string
	legacyOnboarding  bool
}{
	// alpha: v0.0.1 --replaces--> v0.0.2 (head); the only edge and the previous head.
	{channel: "alpha", from: "0.0.1", to: "0.0.2", legacyOnboarding: true},
}

const (
	// installTimeout bounds one InstallPlan: catalog pod, bundle unpack, CSV and Deployment rollout.
	installTimeout     = 5 * time.Minute
	operatorDeployment = "deployment/sops-operator-controller-manager"
)

var (
	olmV1alpha1    = schema.GroupVersion{Group: "operators.coreos.com", Version: "v1alpha1"}
	installPlanGVK = olmV1alpha1.WithKind("InstallPlan")
	csvGVK         = olmV1alpha1.WithKind("ClusterServiceVersion")
)

// Use case: a customer running an earlier release gets the new one through OLM, and everything the
// operator already manages keeps working (DESIGN.md §9). Run with `make test-upgrade`.
func TestUpgrade(t *testing.T) {
	if os.Getenv("E2E_UPGRADE") != "true" {
		t.Skip("upgrade paths run with make test-upgrade")
	}
	for _, p := range upgradePaths {
		t.Run(fmt.Sprintf("shall upgrade %s from v%s to v%s and keep serving existing Secrets", p.channel, p.from, p.to),
			func(t *testing.T) {
				installAt(t, p.channel, p.from)

				prod := namespace(t, "e2e-upgrade-prod")
				tenantNS, recipient := tenantOnboardedAs(t, p.legacyOnboarding, "e2e-upgrade-tenant", prod)
				secret := sopsSecret{
					Name: "db-creds", Namespace: prod, Scope: prod + "/db-creds", TenantNamespace: tenantNS,
					StringData: map[string]string{"password": "v1"},
				}
				s := createSopsSecret(t, recipient, secret)
				waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
				before := outputSecret(t, prod)
				keyBefore := tenantKey(t, tenantNS)

				upgradeTo(t, p.to)
				if p.legacyOnboarding {
					// The release notes ask the cluster admin to apply the new onboarding (DESIGN.md D46).
					onboard(t, false, tenantNS, prod)
				}

				// The new operator reconciles the SopsSecret created before the upgrade: it decrypts a
				// change with the tenant key the earlier version generated, into the same Secret.
				secret.StringData = map[string]string{"password": "v2"}
				next := encryptSopsSecret(t, recipient, secret)
				update(t, s, func() { s.Spec, s.Sops = next.Spec, next.Sops })
				poll(t, "the upgraded operator to deliver the new value", func() (bool, error) {
					return string(outputSecret(t, prod).Data["password"]) == "v2", nil
				})
				waitForReason(t, s, sopsv1alpha1.ReasonDecrypted)
				if after := outputSecret(t, prod); after.UID != before.UID {
					t.Fatal("the upgrade recreated the output Secret instead of keeping it")
				}
				keyAfter := tenantKey(t, tenantNS)
				keyFile := func(s *corev1.Secret) string { return string(s.Data[crypto.KeyFileField]) }
				if keyAfter.UID != keyBefore.UID || keyFile(keyAfter) != keyFile(keyBefore) {
					t.Fatal("the upgrade replaced the tenant key")
				}
			})
	}
}

// installAt subscribes to channel starting at version with manual approval and approves only the
// InstallPlan for that version, so the test controls when the upgrade happens.
func installAt(t *testing.T, channel, version string) {
	t.Helper()
	csv := csvName(version)
	if err := subscribe(channel, "Manual", csv); err != nil {
		t.Fatal(err)
	}
	approveUntilSucceeded(t, csv, func(csvs []string) bool { return slices.Equal(csvs, []string{csv}) })
}

// upgradeTo approves each InstallPlan OLM offers until version's CSV has succeeded, then checks it
// replaced the earlier one.
func upgradeTo(t *testing.T, version string) {
	t.Helper()
	csv := csvName(version)
	approveUntilSucceeded(t, csv, func([]string) bool { return true })
	var csvs unstructured.UnstructuredList
	csvs.SetGroupVersionKind(csvGVK)
	if err := k8s.List(context.Background(), &csvs, client.InNamespace(operatorNamespace)); err != nil {
		t.Fatal(err)
	}
	if len(csvs.Items) != 1 || csvs.Items[0].GetName() != csv {
		t.Fatalf("after the upgrade the operator namespace holds CSVs %v, want only %s", names(csvs.Items), csv)
	}
}

// approveUntilSucceeded approves pending InstallPlans whose CSVs match until the CSV named csv has
// succeeded and the operator Deployment has rolled out.
func approveUntilSucceeded(t *testing.T, csv string, approve func(csvs []string) bool) {
	t.Helper()
	ctx := context.Background()
	plans := func() []unstructured.Unstructured {
		var list unstructured.UnstructuredList
		list.SetGroupVersionKind(installPlanGVK)
		if err := k8s.List(ctx, &list, client.InNamespace(operatorNamespace)); err != nil {
			t.Fatal(err)
		}
		return list.Items
	}
	pollFor(t, installTimeout, csv+" to succeed", func() (bool, error) {
		pending := plans()
		for i := range pending {
			p := &pending[i]
			csvs, _, _ := unstructured.NestedStringSlice(p.Object, "spec", "clusterServiceVersionNames")
			approved, _, _ := unstructured.NestedBool(p.Object, "spec", "approved")
			if approved || !approve(csvs) {
				continue
			}
			if err := unstructured.SetNestedField(p.Object, true, "spec", "approved"); err != nil {
				return false, err
			}
			if err := k8s.Update(ctx, p); err != nil {
				return false, client.IgnoreNotFound(err)
			}
		}
		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(csvGVK)
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: csv}, obj); err != nil {
			return false, client.IgnoreNotFound(err)
		}
		phase, _, _ := unstructured.NestedString(obj.Object, "status", "phase")
		return phase == "Succeeded", nil
	}, func() string {
		var seen []string
		for _, p := range plans() {
			csvs, _, _ := unstructured.NestedStringSlice(p.Object, "spec", "clusterServiceVersionNames")
			phase, _, _ := unstructured.NestedString(p.Object, "status", "phase")
			seen = append(seen, fmt.Sprintf("%s %v %s", p.GetName(), csvs, phase))
		}
		return "InstallPlans: [" + strings.Join(seen, "; ") + "]"
	})
	rollout := []string{"-n", operatorNamespace, "rollout", "status", operatorDeployment, "--timeout=180s"}
	if _, err := kubectl("", rollout...); err != nil {
		t.Fatal(err)
	}
}

func csvName(version string) string { return "sops-operator.v" + version }

// tenantKey returns the tenant's key Secret, named after the SopsTenant.
func tenantKey(t *testing.T, tenantNamespace string) *corev1.Secret {
	t.Helper()
	var key corev1.Secret
	key.Namespace, key.Name = tenantNamespace, tenantName
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(&key), &key); err != nil {
		t.Fatal(err)
	}
	return &key
}

func names(objs []unstructured.Unstructured) []string {
	out := make([]string, 0, len(objs))
	for _, o := range objs {
		out = append(out, o.GetName())
	}
	return out
}
