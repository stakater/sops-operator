package identity_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stakater/sops-operator/internal/identity"
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

func TestTenantIdentity(t *testing.T) {
	t.Run("shall act as the tenant's own ServiceAccount", func(t *testing.T) {
		if got := identity.UserName("team-a-ns", "team-a"); got != "system:serviceaccount:team-a-ns:team-a-sops-tenant" {
			t.Fatalf("UserName = %q", got)
		}
	})

	t.Run("shall read the key only when onboarded", func(t *testing.T) {
		ctx := context.Background()
		tenantNS := env.Namespace(t, "tenant")
		key := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "my-team", Namespace: tenantNS}}
		if err := env.Admin.Create(ctx, key); err != nil {
			t.Fatal(err)
		}
		f := identity.NewFactory(env.OperatorConfig, env.Scheme)
		c, err := f.ClientFor(tenantNS, "my-team")
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(key), &corev1.Secret{}); !apierrors.IsForbidden(err) {
			t.Fatalf("before onboarding: got %v, want Forbidden", err)
		}
		env.Onboard(t, tenantNS, "my-team")
		if err := c.Get(ctx, client.ObjectKeyFromObject(key), &corev1.Secret{}); err != nil {
			t.Fatalf("after onboarding: %v", err)
		}
	})

	t.Run("shall report Secret write only in granted namespaces", func(t *testing.T) {
		ctx := context.Background()
		tenantNS := env.Namespace(t, "tenant")
		granted := env.Namespace(t, "granted")
		other := env.Namespace(t, "other")
		env.Onboard(t, tenantNS, "my-team", granted)

		for ns, want := range map[string]bool{granted: true, other: false} {
			got, err := identity.CanWriteSecrets(ctx, env.Operator, tenantNS, "my-team", ns)
			if err != nil {
				t.Fatalf("CanWriteSecrets(%s): %v", ns, err)
			}
			if got != want {
				t.Fatalf("CanWriteSecrets(%s) = %v, want %v", ns, got, want)
			}
		}
	})
}
