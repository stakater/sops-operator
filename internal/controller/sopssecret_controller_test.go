package controller_test

import (
	"context"
	"maps"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/controller"
	"k8s.io/utils/ptr"

	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/identity"
)

func create(t *testing.T, s *sopsv1alpha1.SopsSecret) {
	t.Helper()
	if err := env.Admin.Create(context.Background(), s); err != nil {
		t.Fatal(err)
	}
}

// outputSecret returns the Secret "db" in ns, the name every test SopsSecret here produces.
func outputSecret(t *testing.T, ns string) *corev1.Secret {
	t.Helper()
	var s corev1.Secret
	if err := env.Admin.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "db"}, &s); err != nil {
		t.Fatalf("get output Secret: %v", err)
	}
	return &s
}

func assertNoSecret(t *testing.T, ns, name string) {
	t.Helper()
	err := env.Admin.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &corev1.Secret{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("Secret %s/%s must not exist: %v", ns, name, err)
	}
}

func TestSecretRejection(t *testing.T) {
	prod := env.Namespace(t, "prod")
	dev := env.Namespace(t, "dev")
	ungranted := env.Namespace(t, "ungranted")
	tenantNS, recipient := onboardedTenant(t, prod, dev)
	_, otherRecipient, err := crypto.GenerateKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	value := map[string]any{"password": "hunter2"}

	cases := []struct {
		name   string
		build  func() *sopsv1alpha1.SopsSecret
		reason string
	}{
		{"shall report TenantNotFound when the tenant does not exist", func() *sopsv1alpha1.SopsSecret {
			s := encryptedSopsSecret(t, recipient, tenantNS, prod, "nf", prod+"/nf", value)
			s.Spec.TenantRef.Name = "missing"
			return s
		}, sopsv1alpha1.ReasonTenantNotFound},
		{"shall report AccessDenied in a namespace not granted to the tenant", func() *sopsv1alpha1.SopsSecret {
			return encryptedSopsSecret(t, recipient, tenantNS, ungranted, "ad", ungranted+"/ad", value)
		}, sopsv1alpha1.ReasonAccessDenied},
		{"shall report NotRecipient when encrypted for another key", func() *sopsv1alpha1.SopsSecret {
			return encryptedSopsSecret(t, otherRecipient, tenantNS, prod, "nr", prod+"/nr", value)
		}, sopsv1alpha1.ReasonNotRecipient},
		{"shall report DecryptFailed when tampered with", func() *sopsv1alpha1.SopsSecret {
			s := encryptedSopsSecret(t, recipient, tenantNS, prod, "tp", prod+"/tp", value)
			s.Sops.LastModified = "2020-01-01T00:00:00Z"
			return s
		}, sopsv1alpha1.ReasonDecryptFailed},
		{"shall report ScopeMismatch when copied to another namespace", func() *sopsv1alpha1.SopsSecret {
			s := encryptedSopsSecret(t, recipient, tenantNS, prod, "cp", prod+"/cp", value)
			s.Namespace = dev
			return s
		}, sopsv1alpha1.ReasonScopeMismatch},
		{"shall report ScopeMismatch when copied under another name", func() *sopsv1alpha1.SopsSecret {
			s := encryptedSopsSecret(t, recipient, tenantNS, prod, "orig", prod+"/orig", value)
			s.Name = "renamed"
			return s
		}, sopsv1alpha1.ReasonScopeMismatch},
		{"shall report ApplyFailed when the Secret is invalid", func() *sopsv1alpha1.SopsSecret {
			s := encryptedSopsSecret(t, recipient, tenantNS, prod, "tls", prod+"/tls", value)
			s.Spec.Type = corev1.SecretTypeTLS
			return s
		}, sopsv1alpha1.ReasonApplyFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.build()
			create(t, s)
			eventuallyReason(t, s, tc.reason)
			assertNoSecret(t, s.Namespace, s.Name)
		})
	}
}

func TestSecretDecryption(t *testing.T) {
	t.Run("shall write the decrypted Secret", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "hunter2"})
		s.Spec.Template.Metadata.Labels = map[string]string{"app": "billing", "argocd.argoproj.io/instance": "x"}
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)

		out := outputSecret(t, prod)
		if string(out.Data["password"]) != "hunter2" {
			t.Fatal("output Secret has the wrong value")
		}
		if out.Labels["app"] != "billing" || out.Labels["argocd.argoproj.io/instance"] != "x" ||
			out.Labels[sopsv1alpha1.LabelManagedBy] != sopsv1alpha1.ManagedByValue {
			t.Fatalf("labels = %v, want the template's labels as written", out.Labels)
		}
		if len(out.OwnerReferences) != 0 {
			t.Fatalf("ownerReferences = %+v, want none", out.OwnerReferences)
		}
	})

	t.Run("shall decrypt while the tenant's status is lost", func(t *testing.T) {
		ctx := context.Background()
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		operator, err := client.NewWithWatch(env.OperatorConfig, client.Options{Scheme: env.Scheme})
		if err != nil {
			t.Fatal(err)
		}
		statusLost := interceptor.NewClient(operator, interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				err := c.Get(ctx, key, obj, opts...)
				if tenant, ok := obj.(*sopsv1alpha1.SopsTenant); ok {
					tenant.Status = sopsv1alpha1.SopsTenantStatus{}
				}
				return err
			},
		})
		r := &controller.SopsSecretReconciler{Client: statusLost, Identities: identity.NewFactory(env.OperatorConfig, env.Scheme)}
		if reason, err := r.SyncForTest(ctx, s); err != nil || reason != sopsv1alpha1.ReasonDecrypted {
			t.Fatalf("sync = %q, %v; want Decrypted", reason, err)
		}
	})

	t.Run("shall report TenantNotReady for a brought key Secret without the enabled label", func(t *testing.T) {
		ctx := context.Background()
		tenantNS := env.Namespace(t, "tenant")
		prod := env.Namespace(t, "prod")
		env.Onboard(t, tenantNS, tenantName, prod)
		keyFile, recipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		key := keySecret(tenantNS, string(keyFile))
		key.Labels = nil
		if err := env.Admin.Create(ctx, key); err != nil {
			t.Fatal(err)
		}
		if err := env.Admin.Create(ctx, newTenant(tenantNS, ptr.To(false))); err != nil {
			t.Fatal(err)
		}
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonTenantNotReady)
	})

	t.Run("shall decrypt a SopsSecret whose name is longer than 63 characters", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		name := "db-" + strings.Repeat("x", 70) // valid object name, too long for a label value
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, name, prod+"/"+name, map[string]any{"password": "x"})
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
	})

	t.Run("shall propagate updates and repair drift", func(t *testing.T) {
		ctx := context.Background()
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)

		next := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v2"})
		update(t, s, func() { s.Spec, s.Sops = next.Spec, next.Sops })
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(string(outputSecret(t, prod).Data["password"])).To(Equal("v2"))
		}).WithTimeout(20 * time.Second).Should(Succeed())

		drifted := outputSecret(t, prod)
		drifted.Data["password"] = []byte("tampered")
		if err := env.Admin.Update(ctx, drifted); err != nil {
			t.Fatal(err)
		}
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(string(outputSecret(t, prod).Data["password"])).To(Equal("v2"))
		}).WithTimeout(20 * time.Second).Should(Succeed())
	})
}

func TestSecretSyncAccess(t *testing.T) {
	t.Run("shall report AccessDenied naming sops-tenant-secret-reconciler where only Secret write is granted", func(t *testing.T) {
		ctx := context.Background()
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t)
		role := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "write-only-"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"create", "update"}}},
		}
		if err := env.Admin.Create(ctx, role); err != nil {
			t.Fatal(err)
		}
		binding := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "write-only", Namespace: prod},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind,
				Name: sopsv1alpha1.TenantServiceAccountName(tenantName), Namespace: tenantNS}},
		}
		if err := env.Admin.Create(ctx, binding); err != nil {
			t.Fatal(err)
		}
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonAccessDenied)
		if c := readyCondition(s); !strings.Contains(c.Message, "sops-tenant-secret-reconciler") ||
			!strings.Contains(c.Message, "create, update, list, watch") {
			t.Fatalf("message %q does not name the role to bind and its verbs", c.Message)
		}
		assertNoSecret(t, prod, "db")
	})
}

func TestOutputSecretWatch(t *testing.T) {
	t.Run("shall hold the watch of the output Secret while the SopsSecret is Decrypted", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		eventuallyHeld(t, s, true)
	})

	t.Run("shall release the watch while the SopsSecret is suspended", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		create(t, s)
		eventuallyHeld(t, s, true)
		update(t, s, func() { s.Annotations = map[string]string{sopsv1alpha1.AnnotationSuspend: "true"} })
		eventuallyReason(t, s, sopsv1alpha1.ReasonSuspended)
		eventuallyHeld(t, s, false)
	})

	t.Run("shall release the watch when the SopsSecret is deleted", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		create(t, s)
		eventuallyHeld(t, s, true)
		if err := env.Admin.Delete(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		eventuallyHeld(t, s, false)
	})

	t.Run("shall restore a deleted output Secret", func(t *testing.T) {
		ctx := context.Background()
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		deleted := outputSecret(t, prod)
		if err := env.Admin.Delete(ctx, deleted); err != nil {
			t.Fatal(err)
		}
		NewWithT(t).Eventually(func(g Gomega) {
			var restored corev1.Secret
			g.Expect(env.Admin.Get(ctx, client.ObjectKey{Namespace: prod, Name: "db"}, &restored)).To(Succeed())
			g.Expect(restored.UID).NotTo(Equal(deleted.UID))
			g.Expect(string(restored.Data["password"])).To(Equal("v1"))
		}).WithTimeout(20 * time.Second).Should(Succeed())
	})

	t.Run("shall leave an up-to-date output Secret unchanged", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		s.Spec.Template.Metadata.Labels = map[string]string{"app": "billing"}
		s.Spec.Template.Metadata.Annotations = map[string]string{"example.com/note": "n"}
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		before := outputSecret(t, prod).ResourceVersion
		eventuallyResynced(t, s)
		eventuallyResynced(t, s)
		if after := outputSecret(t, prod).ResourceVersion; after != before {
			t.Fatalf("resourceVersion %s became %s: an unchanged Secret was rewritten", before, after)
		}
	})
}

// eventuallyHeld waits until the output Secret watch is held for s, or released when held is false.
func eventuallyHeld(t *testing.T, s *sopsv1alpha1.SopsSecret, held bool) {
	t.Helper()
	NewWithT(t).Eventually(func() bool {
		return watches.Holds(client.ObjectKeyFromObject(s))
	}).WithTimeout(20*time.Second).Should(Equal(held), "output Secret watch held for %s", client.ObjectKeyFromObject(s))
}

// eventuallyResynced waits until s is synced again after its last sync.
func eventuallyResynced(t *testing.T, s *sopsv1alpha1.SopsSecret) {
	t.Helper()
	if err := env.Admin.Get(context.Background(), client.ObjectKeyFromObject(s), s); err != nil {
		t.Fatal(err)
	}
	before := s.Status.LastSyncTime.DeepCopy()
	NewWithT(t).Eventually(func(g Gomega) {
		g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(s), s)).To(Succeed())
		g.Expect(s.Status.LastSyncTime.After(before.Time)).To(BeTrue())
	}).WithTimeout(20 * time.Second).Should(Succeed())
}

func TestSecretMetadata(t *testing.T) {
	t.Run("shall replace labels and annotations set directly on the output Secret with the SopsSecret's", func(t *testing.T) {
		ctx := context.Background()
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		s.Spec.Template.Metadata.Labels = map[string]string{"example.com/team": "a"}
		s.Spec.Template.Metadata.Annotations = map[string]string{"example.com/note": "n"}
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		tagged := outputSecret(t, prod)
		tagged.Labels["example.com/team"] = "b"
		tagged.Labels["example.com/set-on-secret"] = "x"
		tagged.Annotations["example.com/set-on-secret"] = "x"
		if err := env.Admin.Update(ctx, tagged); err != nil {
			t.Fatal(err)
		}
		NewWithT(t).Eventually(func(g Gomega) {
			out := outputSecret(t, prod)
			g.Expect(out.Labels).To(Equal(map[string]string{
				"example.com/team":          "a",
				sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue,
				sopsv1alpha1.LabelEnabled:   sopsv1alpha1.EnabledValue,
			}))
			g.Expect(out.Annotations).To(Equal(map[string]string{
				"example.com/note":                "n",
				sopsv1alpha1.AnnotationSopsSecret: "db",
			}))
		}).WithTimeout(20 * time.Second).Should(Succeed())
	})

	t.Run("shall mark the output Secret enabled whatever the template says", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		s.Spec.Template.Metadata.Labels = map[string]string{sopsv1alpha1.LabelEnabled: "false"}
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		if labels := outputSecret(t, prod).Labels; labels[sopsv1alpha1.LabelEnabled] != sopsv1alpha1.EnabledValue {
			t.Fatalf("labels %v, want %s=%s", labels, sopsv1alpha1.LabelEnabled, sopsv1alpha1.EnabledValue)
		}
	})

	t.Run("shall drop sops.stakater.com/ labels and annotations of the template", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		s.Spec.Template.Metadata.Labels = map[string]string{"app": "billing", "sops.stakater.com/custom": "x"}
		s.Spec.Template.Metadata.Annotations = map[string]string{
			"example.com/note":                "n",
			sopsv1alpha1.AnnotationSopsSecret: "other",
			sopsv1alpha1.AnnotationSuspend:    "true",
		}
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		out := outputSecret(t, prod)
		if want := map[string]string{
			"app":                       "billing",
			sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue,
			sopsv1alpha1.LabelEnabled:   sopsv1alpha1.EnabledValue,
		}; !maps.Equal(out.Labels, want) {
			t.Fatalf("labels %v, want %v", out.Labels, want)
		}
		if want := map[string]string{"example.com/note": "n", sopsv1alpha1.AnnotationSopsSecret: "db"}; !maps.Equal(out.Annotations, want) {
			t.Fatalf("annotations %v, want %v", out.Annotations, want)
		}
	})
}

func TestSecretOwnership(t *testing.T) {
	t.Run("shall not overwrite an existing Secret", func(t *testing.T) {
		ctx := context.Background()
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		foreign := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: prod},
			Data:       map[string][]byte{"password": []byte("foreign")},
		}
		if err := env.Admin.Create(ctx, foreign); err != nil {
			t.Fatal(err)
		}
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "mine"})
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonConflict)
		if string(outputSecret(t, prod).Data["password"]) != "foreign" {
			t.Fatal("foreign Secret was overwritten")
		}
	})

	t.Run("shall take over a retained Secret with a SopsSecret of the same name", func(t *testing.T) {
		ctx := context.Background()
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		build := func() *sopsv1alpha1.SopsSecret {
			s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
			s.Spec.DeletionPolicy = sopsv1alpha1.DeletionPolicyRetain
			return s
		}
		first := build()
		create(t, first)
		eventuallyReason(t, first, sopsv1alpha1.ReasonDecrypted)
		if refs := outputSecret(t, prod).OwnerReferences; len(refs) != 0 {
			t.Fatalf("Retain must not set ownerReferences, got %+v", refs)
		}

		if err := env.Admin.Delete(ctx, first); err != nil {
			t.Fatal(err)
		}
		NewWithT(t).Eventually(func() bool {
			return apierrors.IsNotFound(env.Admin.Get(ctx, client.ObjectKeyFromObject(first), &sopsv1alpha1.SopsSecret{}))
		}).WithTimeout(20 * time.Second).Should(BeTrue())

		retained := outputSecret(t, prod)
		second := build()
		create(t, second)
		eventuallyReason(t, second, sopsv1alpha1.ReasonDecrypted)
		if got := outputSecret(t, prod); got.UID != retained.UID {
			t.Fatalf("Secret %s replaced the retained Secret %s", got.UID, retained.UID)
		}
	})

	t.Run("shall keep updating its Secret after the SopsSecret's status is lost", func(t *testing.T) {
		ctx := context.Background()
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		before := outputSecret(t, prod)

		s.Status = sopsv1alpha1.SopsSecretStatus{}
		if err := env.Admin.Status().Update(ctx, s); err != nil {
			t.Fatal(err)
		}
		next := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v2"})
		update(t, s, func() { s.Spec, s.Sops = next.Spec, next.Sops })
		NewWithT(t).Eventually(func(g Gomega) {
			out := outputSecret(t, prod)
			g.Expect(string(out.Data["password"])).To(Equal("v2"))
			g.Expect(out.UID).To(Equal(before.UID))
		}).WithTimeout(20 * time.Second).Should(Succeed())
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
	})

	t.Run("shall take over a Secret written by v0.0.4 only once it carries the enabled label", func(t *testing.T) {
		ctx := context.Background()
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		old := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "db", Namespace: prod,
				Labels:      map[string]string{sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue},
				Annotations: map[string]string{sopsv1alpha1.AnnotationSopsSecret: "db"},
			},
			Data: map[string][]byte{"password": []byte("v1")},
		}
		if err := env.Admin.Create(ctx, old); err != nil {
			t.Fatal(err)
		}
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v2"})
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonConflict)
		if got := string(outputSecret(t, prod).Data["password"]); got != "v1" {
			t.Fatalf("password = %q, want the Secret unchanged until it is labelled", got)
		}
		labelled := outputSecret(t, prod)
		update(t, labelled, func() { labelled.Labels[sopsv1alpha1.LabelEnabled] = sopsv1alpha1.EnabledValue })
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		out := outputSecret(t, prod)
		if out.UID != old.UID || string(out.Data["password"]) != "v2" {
			t.Fatalf("Secret %s, want %s updated to v2", out.UID, old.UID)
		}
	})

}

func TestSuspension(t *testing.T) {
	t.Run("shall not apply a suspended SopsSecret", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "x"})
		s.Annotations = map[string]string{sopsv1alpha1.AnnotationSuspend: "true"}
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonSuspended)
		if c := readyCondition(s); c.Status != metav1.ConditionUnknown {
			t.Fatalf("suspended Ready status = %s, want Unknown", c.Status)
		}
		assertNoSecret(t, prod, "db")
	})

	t.Run("shall hold changes while suspended and apply them on resume", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)

		next := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v2"})
		update(t, s, func() {
			s.Spec, s.Sops = next.Spec, next.Sops
			s.Annotations = map[string]string{sopsv1alpha1.AnnotationSuspend: "true"}
		})
		eventuallyReason(t, s, sopsv1alpha1.ReasonSuspended)
		if got := string(outputSecret(t, prod).Data["password"]); got != "v1" {
			t.Fatalf("suspended SopsSecret changed the Secret to %q", got)
		}

		update(t, s, func() { delete(s.Annotations, sopsv1alpha1.AnnotationSuspend) })
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		if got := string(outputSecret(t, prod).Data["password"]); got != "v2" {
			t.Fatalf("resumed SopsSecret wrote %q, want v2", got)
		}
	})
}
