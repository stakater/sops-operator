package secretwriter_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stakater/sops-operator/internal/identity"
	"github.com/stakater/sops-operator/internal/secretwriter"
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

// setup returns a tenant client that may create, update, list and watch Secrets in ns.
func setup(t *testing.T) (client.Client, string) {
	t.Helper()
	tenantNS := env.Namespace(t, "tenant")
	ns := env.Namespace(t, "target")
	env.Onboard(t, tenantNS, "my-team", ns)
	c, err := identity.NewFactory(env.OperatorConfig, env.Scheme).ClientFor(tenantNS, "my-team")
	if err != nil {
		t.Fatal(err)
	}
	return c, ns
}

const ownedLabel = "example.com/owned"

func secret(ns, value string, labels map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: ns, Labels: labels},
		Data:       map[string][]byte{"password": []byte(value)},
	}
}

func mine(ns, value string) *corev1.Secret {
	return secret(ns, value, map[string]string{ownedLabel: "true"})
}

func owned(m *metav1.PartialObjectMetadata) bool { return m.Labels[ownedLabel] == "true" }

func adminRead(t *testing.T, ns string) *corev1.Secret {
	t.Helper()
	var s corev1.Secret
	if err := env.Admin.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "db"}, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

func TestSecretWriter(t *testing.T) {
	t.Run("shall create and then update its Secret in place", func(t *testing.T) {
		ctx := context.Background()
		c, ns := setup(t)
		if err := secretwriter.Write(ctx, c, mine(ns, "v1"), owned); err != nil {
			t.Fatalf("create: %v", err)
		}
		created := adminRead(t, ns)
		if err := secretwriter.Write(ctx, c, mine(ns, "v2"), owned); err != nil {
			t.Fatalf("update: %v", err)
		}
		updated := adminRead(t, ns)
		if got := string(updated.Data["password"]); got != "v2" || updated.UID != created.UID {
			t.Fatalf("password = %q, uid %s (created %s); want v2 in the same Secret", got, updated.UID, created.UID)
		}
	})

	t.Run("shall update a Secret it owns that it did not create", func(t *testing.T) {
		ctx := context.Background()
		c, ns := setup(t)
		if err := env.Admin.Create(ctx, mine(ns, "restored")); err != nil {
			t.Fatal(err)
		}
		if err := secretwriter.Write(ctx, c, mine(ns, "v2"), owned); err != nil {
			t.Fatal(err)
		}
		if got := string(adminRead(t, ns).Data["password"]); got != "v2" {
			t.Fatalf("password = %q, want v2", got)
		}
	})

	t.Run("shall not change a Secret it does not own", func(t *testing.T) {
		ctx := context.Background()
		c, ns := setup(t)
		if err := env.Admin.Create(ctx, secret(ns, "foreign", nil)); err != nil {
			t.Fatal(err)
		}
		if err := secretwriter.Write(ctx, c, mine(ns, "mine"), owned); !errors.Is(err, secretwriter.ErrConflict) {
			t.Fatalf("got %v, want ErrConflict", err)
		}
		if got := string(adminRead(t, ns).Data["password"]); got != "foreign" {
			t.Fatal("foreign Secret was modified")
		}
	})

	t.Run("shall recreate a deleted Secret", func(t *testing.T) {
		ctx := context.Background()
		c, ns := setup(t)
		if err := secretwriter.Write(ctx, c, mine(ns, "v1"), owned); err != nil {
			t.Fatal(err)
		}
		if err := env.Admin.Delete(ctx, secret(ns, "", nil)); err != nil {
			t.Fatal(err)
		}
		if err := secretwriter.Write(ctx, c, mine(ns, "v2"), owned); err != nil {
			t.Fatal(err)
		}
		if got := string(adminRead(t, ns).Data["password"]); got != "v2" {
			t.Fatalf("password = %q, want v2", got)
		}
	})

	t.Run("shall not read Secrets", func(t *testing.T) {
		c, ns := setup(t)
		if err := env.Admin.Create(context.Background(), secret(ns, "x", nil)); err != nil {
			t.Fatal(err)
		}
		err := c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "db"}, &corev1.Secret{})
		if !apierrors.IsForbidden(err) {
			t.Fatalf("got %v, want Forbidden", err)
		}
	})
}
