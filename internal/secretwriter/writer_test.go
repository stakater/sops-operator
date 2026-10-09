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

// setup returns a tenant client that may only create and update Secrets in ns.
func setup(t *testing.T) (client.Client, string) {
	t.Helper()
	tenantNS := env.Namespace(t, "tenant")
	ns := env.Namespace(t, "target")
	env.Onboard(t, tenantNS, ns)
	c, err := identity.NewFactory(env.OperatorConfig, env.Scheme).ClientFor(tenantNS)
	if err != nil {
		t.Fatal(err)
	}
	return c, ns
}

func secret(ns, value string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: ns},
		Data:       map[string][]byte{"password": []byte(value)},
	}
}

func adminRead(t *testing.T, ns string) *corev1.Secret {
	t.Helper()
	var s corev1.Secret
	if err := env.Admin.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "db"}, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

func TestCreateThenUpdate(t *testing.T) {
	ctx := context.Background()
	c, ns := setup(t)
	uid, err := secretwriter.Write(ctx, c, secret(ns, "v1"), "")
	if err != nil || uid == "" {
		t.Fatalf("create: uid=%q err=%v", uid, err)
	}
	uid2, err := secretwriter.Write(ctx, c, secret(ns, "v2"), uid)
	if err != nil || uid2 != uid {
		t.Fatalf("update: uid=%q err=%v", uid2, err)
	}
	if got := string(adminRead(t, ns).Data["password"]); got != "v2" {
		t.Fatalf("password = %q, want v2", got)
	}
}

func TestExistingForeignSecretIsConflict(t *testing.T) {
	ctx := context.Background()
	c, ns := setup(t)
	if err := env.Admin.Create(ctx, secret(ns, "foreign")); err != nil {
		t.Fatal(err)
	}
	if _, err := secretwriter.Write(ctx, c, secret(ns, "mine"), ""); !errors.Is(err, secretwriter.ErrConflict) {
		t.Fatalf("got %v, want ErrConflict", err)
	}
	if got := string(adminRead(t, ns).Data["password"]); got != "foreign" {
		t.Fatal("foreign Secret was modified")
	}
}

func TestDeletedSecretIsRecreated(t *testing.T) {
	ctx := context.Background()
	c, ns := setup(t)
	uid, err := secretwriter.Write(ctx, c, secret(ns, "v1"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Admin.Delete(ctx, secret(ns, "")); err != nil {
		t.Fatal(err)
	}
	uid2, err := secretwriter.Write(ctx, c, secret(ns, "v2"), uid)
	if err != nil || uid2 == "" || uid2 == uid {
		t.Fatalf("recreate: uid=%q (old %q) err=%v", uid2, uid, err)
	}
}

func TestForeignReplacementIsNeverOverwritten(t *testing.T) {
	ctx := context.Background()
	c, ns := setup(t)
	uid, err := secretwriter.Write(ctx, c, secret(ns, "v1"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Admin.Delete(ctx, secret(ns, "")); err != nil {
		t.Fatal(err)
	}
	if err := env.Admin.Create(ctx, secret(ns, "foreign")); err != nil {
		t.Fatal(err)
	}
	if _, err := secretwriter.Write(ctx, c, secret(ns, "v2"), uid); !errors.Is(err, secretwriter.ErrConflict) {
		t.Fatalf("got %v, want ErrConflict", err)
	}
	if got := string(adminRead(t, ns).Data["password"]); got != "foreign" {
		t.Fatal("foreign replacement was overwritten")
	}
}

func TestTenantCannotReadSecrets(t *testing.T) {
	c, ns := setup(t)
	if err := env.Admin.Create(context.Background(), secret(ns, "x")); err != nil {
		t.Fatal(err)
	}
	err := c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "db"}, &corev1.Secret{})
	if !apierrors.IsForbidden(err) {
		t.Fatalf("got %v, want Forbidden", err)
	}
}
