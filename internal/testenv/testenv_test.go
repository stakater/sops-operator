package testenv_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/testenv"
)

var env *testenv.Env

func TestMain(m *testing.M) {
	var err error
	if env, err = testenv.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	_ = env.Stop()
	os.Exit(code)
}

func TestOperatorHasNoStandingSecretAccess(t *testing.T) {
	err := env.Operator.List(context.Background(), &corev1.SecretList{})
	if !apierrors.IsForbidden(err) {
		t.Fatalf("operator listing Secrets: got %v, want Forbidden", err)
	}
}

func TestOperatorCanReadItsResources(t *testing.T) {
	ctx := context.Background()
	if err := env.Operator.List(ctx, &sopsv1alpha1.SopsTenantList{}); err != nil {
		t.Fatalf("list SopsTenants: %v", err)
	}
	if err := env.Operator.List(ctx, &sopsv1alpha1.SopsSecretList{}); err != nil {
		t.Fatalf("list SopsSecrets: %v", err)
	}
}

func TestOperatorImpersonatesOnlySopsServiceAccounts(t *testing.T) {
	ctx := context.Background()
	ns := env.Namespace(t, "imp")
	// Both ServiceAccounts may read Secrets, so only the impersonation check can deny.
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "read-secrets", Namespace: ns},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}},
	}
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "read-secrets", Namespace: ns},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "read-secrets"},
		Subjects: []rbacv1.Subject{
			{Kind: rbacv1.ServiceAccountKind, Name: "sops", Namespace: ns},
			{Kind: rbacv1.ServiceAccountKind, Name: "default", Namespace: ns},
		},
	}
	probe := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "probe", Namespace: ns}}
	for _, o := range []client.Object{role, binding, probe} {
		if err := env.Admin.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	for sa, allowed := range map[string]bool{"sops": true, "default": false} {
		cfg := rest.CopyConfig(env.OperatorConfig)
		cfg.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:" + ns + ":" + sa}
		c, err := client.New(cfg, client.Options{Scheme: env.Scheme})
		if err != nil {
			t.Fatal(err)
		}
		err = c.Get(ctx, client.ObjectKeyFromObject(probe), &corev1.Secret{})
		if allowed && err != nil {
			t.Fatalf("impersonating %s: %v", sa, err)
		}
		if !allowed && !apierrors.IsForbidden(err) {
			t.Fatalf("impersonating %s: got %v, want Forbidden", sa, err)
		}
	}
}
