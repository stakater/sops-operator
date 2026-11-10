package secretwatch_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/event"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/identity"
	"github.com/stakater/sops-operator/internal/secretwatch"
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

// secret returns a Secret named name in ns with the given labels and annotations.
func secret(ns, name string, labels, annotations map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels, Annotations: annotations},
		Data:       map[string][]byte{"password": []byte("v1")},
	}
}

// outputSecret returns a Secret as the operator writes it for the SopsSecret named owner.
func outputSecret(ns, name, owner string) *corev1.Secret {
	return secret(ns, name, enabled(), map[string]string{sopsv1alpha1.AnnotationSopsSecret: owner})
}

func enabled() map[string]string {
	return map[string]string{
		sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue,
		sopsv1alpha1.LabelEnabled:   sopsv1alpha1.EnabledValue,
	}
}

// nextEvent returns the next reported SopsSecret, failing after a few seconds without one.
func nextEvent(t *testing.T, events <-chan event.GenericEvent) types.NamespacedName {
	t.Helper()
	select {
	case e := <-events:
		return types.NamespacedName{Namespace: e.Object.GetNamespace(), Name: e.Object.GetName()}
	case <-time.After(10 * time.Second):
		t.Fatal("no event within 10s")
		return types.NamespacedName{}
	}
}

// Use case: an output Secret is deleted or edited, and its SopsSecret is reconciled at once instead
// of at the next resync.
func TestWatches(t *testing.T) {
	ctx := context.Background()
	tenantNS := env.Namespace(t, "tenant")
	ns := env.Namespace(t, "prod")
	env.Onboard(t, tenantNS, "my-team", ns)
	tenant := types.NamespacedName{Namespace: tenantNS, Name: "my-team"}
	owner := types.NamespacedName{Namespace: ns, Name: "db"}

	w := secretwatch.New(identity.NewFactory(env.OperatorConfig, env.Scheme).ConfigFor)
	events := w.Events()
	t.Cleanup(w.Stop)
	out := outputSecret(ns, "db", "db")
	if err := env.Admin.Create(ctx, out); err != nil {
		t.Fatal(err)
	}
	if err := w.Watch(ctx, owner, tenant); err != nil {
		t.Fatal(err)
	}

	t.Run("shall report a changed output Secret", func(t *testing.T) {
		out.Data["password"] = []byte("edited")
		if err := env.Admin.Update(ctx, out); err != nil {
			t.Fatal(err)
		}
		if got := nextEvent(t, events); got != owner {
			t.Fatalf("event for %v, want %v", got, owner)
		}
	})

	t.Run("shall report an output Secret whose metadata changed", func(t *testing.T) {
		out.Annotations["example.com/set-on-secret"] = "x"
		if err := env.Admin.Update(ctx, out); err != nil {
			t.Fatal(err)
		}
		if got := nextEvent(t, events); got != owner {
			t.Fatalf("event for %v, want %v", got, owner)
		}
	})

	t.Run("shall report a deleted output Secret and ignore Secrets without the label or the annotation", func(t *testing.T) {
		unlabelled := secret(ns, "unlabelled", nil, map[string]string{sopsv1alpha1.AnnotationSopsSecret: "unlabelled"})
		unannotated := secret(ns, "unannotated", enabled(), nil)
		for _, s := range []*corev1.Secret{unlabelled, unannotated} {
			if err := env.Admin.Create(ctx, s); err != nil {
				t.Fatal(err)
			}
			s.Data["password"] = []byte("edited")
			if err := env.Admin.Update(ctx, s); err != nil {
				t.Fatal(err)
			}
			if err := env.Admin.Delete(ctx, s); err != nil {
				t.Fatal(err)
			}
		}
		if err := env.Admin.Delete(ctx, out); err != nil {
			t.Fatal(err)
		}
		if got := nextEvent(t, events); got != owner {
			t.Fatalf("first event for %v, want %v: a Secret without the label or the annotation was reported", got, owner)
		}
	})

	t.Run("shall stop watching when the last SopsSecret is released", func(t *testing.T) {
		if got := w.Watching(); got != 1 {
			t.Fatalf("watching %d namespaces before release, want 1", got)
		}
		w.Release(owner)
		if got := w.Watching(); got != 0 {
			t.Fatalf("watching %d namespaces after release, want 0", got)
		}
		if w.Holds(owner) {
			t.Fatal("the released SopsSecret still holds a watch")
		}
	})
}

func TestWatchesSharedInNamespace(t *testing.T) {
	ctx := context.Background()
	tenantNS := env.Namespace(t, "tenant")
	ns := env.Namespace(t, "prod")
	env.Onboard(t, tenantNS, "my-team", ns)
	tenant := types.NamespacedName{Namespace: tenantNS, Name: "my-team"}
	first := types.NamespacedName{Namespace: ns, Name: "db"}
	second := types.NamespacedName{Namespace: ns, Name: "api"}
	w := secretwatch.New(identity.NewFactory(env.OperatorConfig, env.Scheme).ConfigFor)
	t.Cleanup(w.Stop)

	t.Run("shall run one watch for the SopsSecrets of a tenant in a namespace", func(t *testing.T) {
		for _, owner := range []types.NamespacedName{first, second} {
			if err := w.Watch(ctx, owner, tenant); err != nil {
				t.Fatal(err)
			}
		}
		if got := w.Watching(); got != 1 {
			t.Fatalf("watching %d times, want 1", got)
		}
	})

	t.Run("shall keep the watch while another SopsSecret holds it", func(t *testing.T) {
		w.Release(first)
		if got := w.Watching(); got != 1 || !w.Holds(second) {
			t.Fatalf("watching %d times after releasing one of two SopsSecrets, want 1", got)
		}
	})
}

// The watch runs as the tenant identity, so it reaches only the namespaces granted to the tenant with
// sops-tenant-secret-reconciler.
func TestWatchesFollowTenantGrants(t *testing.T) {
	ctx := context.Background()
	tenantNS := env.Namespace(t, "tenant")
	granted := env.Namespace(t, "granted")
	ungranted := env.Namespace(t, "ungranted")
	env.Onboard(t, tenantNS, "my-team", granted)
	tenant := types.NamespacedName{Namespace: tenantNS, Name: "my-team"}
	w := secretwatch.New(identity.NewFactory(env.OperatorConfig, env.Scheme).ConfigFor)
	t.Cleanup(w.Stop)

	t.Run("shall watch a namespace granted to the tenant", func(t *testing.T) {
		if err := w.Watch(ctx, types.NamespacedName{Namespace: granted, Name: "db"}, tenant); err != nil {
			t.Fatalf("watch in a granted namespace: %v", err)
		}
	})

	t.Run("shall not watch a namespace not granted to the tenant", func(t *testing.T) {
		wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := w.Watch(wctx, types.NamespacedName{Namespace: ungranted, Name: "db"}, tenant); err == nil {
			t.Fatal("the tenant identity watched Secrets in a namespace it was not granted")
		}
		if got := w.Watching(); got != 1 {
			t.Fatalf("watching %d namespaces, want only the granted one", got)
		}
	})
}

func TestKeyWatches(t *testing.T) {
	ctx := context.Background()
	tenantNS := env.Namespace(t, "tenant")
	env.Onboard(t, tenantNS, "my-team")
	tenant := types.NamespacedName{Namespace: tenantNS, Name: "my-team"}

	w := secretwatch.NewForKeys(identity.NewFactory(env.OperatorConfig, env.Scheme).ConfigFor)
	events := w.Events()
	t.Cleanup(w.Stop)
	key := secret(tenantNS, "my-team-sops-keys", enabled(), nil)
	if err := env.Admin.Create(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := w.Watch(ctx, tenant, tenant); err != nil {
		t.Fatalf("watch the tenant namespace as the tenant identity: %v", err)
	}

	t.Run("shall report a changed key Secret as its SopsTenant", func(t *testing.T) {
		key.Data["age.agekey"] = []byte("edited")
		if err := env.Admin.Update(ctx, key); err != nil {
			t.Fatal(err)
		}
		if got := nextEvent(t, events); got != tenant {
			t.Fatalf("event for %v, want the tenant %v", got, tenant)
		}
	})

	t.Run("shall report a key Secret that lost the enabled label", func(t *testing.T) {
		key.Labels = map[string]string{sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue}
		if err := env.Admin.Update(ctx, key); err != nil {
			t.Fatal(err)
		}
		if got := nextEvent(t, events); got != tenant {
			t.Fatalf("event for %v, want the tenant %v", got, tenant)
		}
	})

	t.Run("shall report a deleted key Secret and ignore backups, output Secrets and other Secrets", func(t *testing.T) {
		key.Labels = enabled()
		if err := env.Admin.Update(ctx, key); err != nil {
			t.Fatal(err)
		}
		backupLabels := enabled()
		backupLabels[sopsv1alpha1.LabelKeyBackup] = "true"
		ignored := []*corev1.Secret{
			secret(tenantNS, "my-team-sops-keys-20261109-120000", backupLabels, nil),
			secret(tenantNS, "other-sops-keys", enabled(), map[string]string{sopsv1alpha1.AnnotationSopsSecret: "other-sops-keys"}),
			secret(tenantNS, "db", enabled(), nil),
		}
		for _, s := range ignored {
			if err := env.Admin.Create(ctx, s); err != nil {
				t.Fatal(err)
			}
			if err := env.Admin.Delete(ctx, s); err != nil {
				t.Fatal(err)
			}
		}
		if err := env.Admin.Delete(ctx, key); err != nil {
			t.Fatal(err)
		}
		if got := nextEvent(t, events); got != tenant {
			t.Fatalf("event for %v, want the tenant %v: a backup, output Secret or other Secret was reported", got, tenant)
		}
	})
}
