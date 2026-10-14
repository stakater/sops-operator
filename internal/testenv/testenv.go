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

// Package testenv starts a Kubernetes API server for integration tests with the RBAC
// authorizer, the operator's CRDs and roles installed, and a non-admin operator user bound
// to the generated operator ClusterRole, so tests exercise real permissions.
package testenv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
)

// OperatorUser is the user the operator runs as in tests.
const OperatorUser = "sops-operator"

// Env is a running test API server.
type Env struct {
	env            *envtest.Environment
	Scheme         *runtime.Scheme
	Admin          client.Client
	OperatorConfig *rest.Config
	Operator       client.Client
}

// Start starts the API server and installs CRDs, roles and the operator user.
func Start() (*Env, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := sopsv1alpha1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	te := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join(root, "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	te.ControlPlane.GetAPIServer().Configure().Set("authorization-mode", "RBAC")
	cfg, err := te.Start()
	if err != nil {
		return nil, fmt.Errorf("start envtest: %w", err)
	}
	e := &Env{env: te, Scheme: scheme}
	if err := e.setup(root, cfg); err != nil {
		_ = te.Stop()
		return nil, err
	}
	return e, nil
}

func (e *Env) setup(root string, cfg *rest.Config) error {
	ctx := context.Background()
	admin, err := client.New(cfg, client.Options{Scheme: e.Scheme})
	if err != nil {
		return err
	}
	e.Admin = admin
	for _, f := range []string{
		filepath.Join(root, "config", "rbac", "role.yaml"),
		filepath.Join(root, "config", "tenant-rbac", "roles.yaml"),
	} {
		if err := applyFile(ctx, admin, f); err != nil {
			return err
		}
	}
	user, err := e.env.AddUser(envtest.User{Name: OperatorUser}, cfg)
	if err != nil {
		return fmt.Errorf("add operator user: %w", err)
	}
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: OperatorUser},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "manager-role"},
		Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: OperatorUser}},
	}
	if err := admin.Create(ctx, binding); err != nil {
		return err
	}
	e.OperatorConfig = user.Config()
	e.Operator, err = client.New(e.OperatorConfig, client.Options{Scheme: e.Scheme})
	return err
}

// Stop stops the API server.
func (e *Env) Stop() error { return e.env.Stop() }

// Namespace creates a namespace with a generated name and returns the name.
func (e *Env) Namespace(t testing.TB, prefix string) string {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: prefix + "-"}}
	if err := e.Admin.Create(context.Background(), ns); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	return ns.Name
}

// AllowOperator lets the operator create and act as ServiceAccounts in tenantNamespace, as the
// first RoleBinding of the cluster admin's onboarding template does (DESIGN.md §5.2).
func (e *Env) AllowOperator(t testing.TB, tenantNamespace string) {
	t.Helper()
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "sops-operator", Namespace: tenantNamespace},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "sops-operator-tenant"},
		Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: OperatorUser}},
	}
	if err := e.Admin.Create(context.Background(), binding); err != nil {
		t.Fatalf("allow operator: %v", err)
	}
}

// Onboard does what the cluster admin's onboarding template does (DESIGN.md §5.2): it lets the
// operator act in tenantNamespace and lets the ServiceAccount of the tenant named tenant, which
// the operator creates, own keys in the tenant namespace and write Secrets in each of
// writeNamespaces.
func (e *Env) Onboard(t testing.TB, tenantNamespace, tenant string, writeNamespaces ...string) {
	t.Helper()
	e.AllowOperator(t, tenantNamespace)
	subjects := []rbacv1.Subject{{
		Kind: rbacv1.ServiceAccountKind, Name: sopsv1alpha1.TenantServiceAccountName(tenant), Namespace: tenantNamespace,
	}}
	objs := []client.Object{
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "sops-key-owner", Namespace: tenantNamespace},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "sops-key-owner"},
			Subjects:   subjects,
		},
	}
	for _, ns := range writeNamespaces {
		objs = append(objs, &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "sops-" + tenantNamespace, Namespace: ns},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "sops-secret-writer"},
			Subjects:   subjects,
		})
	}
	for _, o := range objs {
		if err := e.Admin.Create(context.Background(), o); err != nil {
			t.Fatalf("onboard: create %T: %v", o, err)
		}
	}
}

func applyFile(ctx context.Context, c client.Client, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	for {
		var obj map[string]any
		if err := dec.Decode(&obj); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("decode %s: %w", path, err)
		}
		if len(obj) == 0 {
			continue
		}
		u := &unstructured.Unstructured{Object: obj}
		if err := c.Create(ctx, u); err != nil {
			return fmt.Errorf("create %s %s from %s: %w", u.GetKind(), u.GetName(), path, err)
		}
	}
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found above the working directory")
		}
		dir = parent
	}
}
