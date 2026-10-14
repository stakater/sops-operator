package testenv_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func TestOperatorPermissions(t *testing.T) {
	t.Run("shall have no standing access to Secrets", func(t *testing.T) {
		err := env.Operator.List(context.Background(), &corev1.SecretList{})
		if !apierrors.IsForbidden(err) {
			t.Fatalf("operator listing Secrets: got %v, want Forbidden", err)
		}
	})

	t.Run("shall read its own resources", func(t *testing.T) {
		ctx := context.Background()
		if err := env.Operator.List(ctx, &sopsv1alpha1.SopsTenantList{}); err != nil {
			t.Fatalf("list SopsTenants: %v", err)
		}
		if err := env.Operator.List(ctx, &sopsv1alpha1.SopsSecretList{}); err != nil {
			t.Fatalf("list SopsSecrets: %v", err)
		}
	})

	t.Run("shall act as and create ServiceAccounts only in tenant namespaces it was granted", func(t *testing.T) {
		ctx := context.Background()
		granted := env.Namespace(t, "granted")
		other := env.Namespace(t, "other")
		env.AllowOperator(t, granted)
		for ns, allowed := range map[string]bool{granted: true, other: false} {
			sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "probe", Namespace: ns}}
			err := env.Operator.Create(ctx, sa)
			if allowed && err != nil {
				t.Fatalf("create ServiceAccount in %s: %v", ns, err)
			}
			if !allowed && !apierrors.IsForbidden(err) {
				t.Fatalf("create ServiceAccount in %s: got %v, want Forbidden", ns, err)
			}

			// The API server authorizes impersonation with exactly this check.
			review := &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: ns, Verb: "impersonate", Resource: "serviceaccounts", Name: "probe",
				},
			}}
			if err := env.Operator.Create(ctx, review); err != nil {
				t.Fatal(err)
			}
			if review.Status.Allowed != allowed {
				t.Fatalf("impersonate in %s allowed=%v, want %v", ns, review.Status.Allowed, allowed)
			}
		}
	})
}

// The tenant admin onboards their own tenant namespace (DESIGN.md D47): both bindings grant only
// what the built-in admin role already holds there, so Kubernetes lets a namespace admin create them.
func TestTenantAdminOnboarding(t *testing.T) {
	t.Run("shall let a namespace admin bind the operator and the key owner", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		user, err := env.AddUser("tenant-admin-"+ns, namespaceAdminRole(t), ns)
		if err != nil {
			t.Fatal(err)
		}
		bindings := []*rbacv1.RoleBinding{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "sops-operator", Namespace: ns},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "sops-operator-tenant"},
				Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "sops-operator-controller-manager", Namespace: "operator-ns"}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "team-a-sops-tenant-key-owner", Namespace: ns},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "sops-key-owner"},
				Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "team-a-sops-tenant", Namespace: ns}},
			},
		}
		for _, b := range bindings {
			if err := user.Create(ctx, b); err != nil {
				t.Fatalf("namespace admin creating %s: %v", b.Name, err)
			}
		}
	})

}

// namespaceAdminRole returns a ClusterRole with the rules of the built-in admin role. envtest runs no
// controller-manager, so admin stays empty; this aggregates the same ClusterRoles it would.
func namespaceAdminRole(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	// admin aggregates edit, which aggregates view.
	role := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{GenerateName: "aggregated-admin-"}}
	for _, to := range []string{"admin", "edit", "view"} {
		var parts rbacv1.ClusterRoleList
		err := env.Admin.List(ctx, &parts, client.MatchingLabels{"rbac.authorization.k8s.io/aggregate-to-" + to: "true"})
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range parts.Items {
			role.Rules = append(role.Rules, p.Rules...)
		}
	}
	if len(role.Rules) == 0 {
		t.Fatal("no ClusterRoles aggregate to admin")
	}
	if err := env.Admin.Create(ctx, role); err != nil {
		t.Fatal(err)
	}
	return role.Name
}
