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

// outputSecret returns a Secret as the operator writes it for the SopsSecret named owner.
func outputSecret(ns, name, owner string, managed bool) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Data:       map[string][]byte{"password": []byte("v1")},
	}
	if managed {
		s.Labels = map[string]string{sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue}
		s.Annotations = map[string]string{sopsv1alpha1.AnnotationSopsSecret: owner}
	}
	return s
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
// of at the next resync (DESIGN.md D28).
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
	out := outputSecret(ns, "db", "db", true)
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

	t.Run("shall report a deleted output Secret and ignore Secrets the operator does not manage", func(t *testing.T) {
		foreign := outputSecret(ns, "foreign", "", false)
		if err := env.Admin.Create(ctx, foreign); err != nil {
			t.Fatal(err)
		}
		if err := env.Admin.Delete(ctx, foreign); err != nil {
			t.Fatal(err)
		}
		if err := env.Admin.Delete(ctx, out); err != nil {
			t.Fatal(err)
		}
		// The first event is the managed Secret's: the foreign Secret, changed first, was not reported.
		if got := nextEvent(t, events); got != owner {
			t.Fatalf("event for %v, want %v", got, owner)
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
	})
}
