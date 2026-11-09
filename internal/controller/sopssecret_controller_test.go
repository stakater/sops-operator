package controller_test

import (
	"context"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/controller"
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
		if out.Labels["app"] != "billing" || out.Labels[sopsv1alpha1.LabelManagedBy] != sopsv1alpha1.ManagedByValue {
			t.Fatalf("labels = %v", out.Labels)
		}
		if _, ok := out.Labels["argocd.argoproj.io/instance"]; ok {
			t.Fatal("GitOps tracking label was copied")
		}
		if len(out.OwnerReferences) != 1 || out.OwnerReferences[0].UID != s.UID ||
			out.OwnerReferences[0].BlockOwnerDeletion == nil || *out.OwnerReferences[0].BlockOwnerDeletion {
			t.Fatalf("ownerReferences = %+v", out.OwnerReferences)
		}
		if s.Status.SecretUID != out.UID {
			t.Fatal("status.secretUID does not match the output Secret")
		}
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
		// v0.0.4's sops-secret-writer granted create and update only; the output Secret cannot be watched.
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
		if c := readyCondition(s); !strings.Contains(c.Message, "sops-tenant-secret-reconciler") {
			t.Fatalf("message %q does not name the role to bind", c.Message)
		}
		assertNoSecret(t, prod, "db")
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
}

func TestSecretMetadata(t *testing.T) {
	t.Run("shall replace labels and annotations set directly on the output Secret with the SopsSecret's", func(t *testing.T) {
		ctx := context.Background()
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		s.Spec.Template.Metadata.Labels = map[string]string{"example.com/team": "a"}
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		tagged := outputSecret(t, prod)
		tagged.Labels["example.com/team"] = "b"
		tagged.Labels["example.com/set-on-secret"] = "x"
		if err := env.Admin.Update(ctx, tagged); err != nil {
			t.Fatal(err)
		}
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(outputSecret(t, prod).Labels).To(Equal(map[string]string{
				"example.com/team":                "a",
				sopsv1alpha1.LabelManagedBy:       sopsv1alpha1.ManagedByValue,
				sopsv1alpha1.LabelTenant:          tenantName,
				sopsv1alpha1.LabelTenantNamespace: tenantNS,
			}))
		}).WithTimeout(20 * time.Second).Should(Succeed())
	})

	t.Run("shall label the output Secret with its tenant whatever the template says", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		s.Spec.Template.Metadata.Labels = map[string]string{
			sopsv1alpha1.LabelTenant:          "someone-else",
			sopsv1alpha1.LabelTenantNamespace: "elsewhere",
		}
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)
		labels := outputSecret(t, prod).Labels
		if labels[sopsv1alpha1.LabelTenant] != tenantName || labels[sopsv1alpha1.LabelTenantNamespace] != tenantNS {
			t.Fatalf("labels %v, want the tenant %s/%s", labels, tenantNS, tenantName)
		}
	})

	t.Run("shall leave an up-to-date output Secret unchanged", func(t *testing.T) {
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "v1"})
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

// eventuallyResynced waits until s is reconciled again after its last sync.
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

	t.Run("shall not reclaim a retained Secret", func(t *testing.T) {
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

		second := build()
		create(t, second)
		eventuallyReason(t, second, sopsv1alpha1.ReasonConflict)
	})

	t.Run("shall record secretUID from a stale copy", func(t *testing.T) {
		ctx := context.Background()
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "x"})
		s.Annotations = map[string]string{sopsv1alpha1.AnnotationSuspend: "true"}
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonSuspended)

		stale := s.DeepCopy()
		// A concurrent metadata change (e.g. from GitOps) makes the copy's resourceVersion stale.
		s.Labels = map[string]string{"touched": "true"}
		if err := env.Admin.Update(ctx, s); err != nil {
			t.Fatal(err)
		}

		r := &controller.SopsSecretReconciler{Client: env.Operator}
		if err := r.RecordDecryptedForTest(ctx, stale, "uid-from-write"); err != nil {
			t.Fatalf("recording the Secret UID from a stale copy: %v", err)
		}
		var got sopsv1alpha1.SopsSecret
		if err := env.Admin.Get(ctx, client.ObjectKeyFromObject(s), &got); err != nil {
			t.Fatal(err)
		}
		if got.Status.SecretUID != "uid-from-write" {
			t.Fatalf("status.secretUID = %q, want uid-from-write", got.Status.SecretUID)
		}
	})

	t.Run("shall not report Conflict from a stale cache", func(t *testing.T) {
		ctx := context.Background()
		prod := env.Namespace(t, "prod")
		tenantNS, recipient := onboardedTenant(t, prod)
		s := encryptedSopsSecret(t, recipient, tenantNS, prod, "db", prod+"/db", map[string]any{"password": "x"})
		create(t, s)
		eventuallyReason(t, s, sopsv1alpha1.ReasonDecrypted)

		// A cache that has not yet seen the status write that recorded secretUID.
		stale := s.DeepCopy()
		stale.Status = sopsv1alpha1.SopsSecretStatus{}
		cached, err := client.NewWithWatch(env.OperatorConfig, client.Options{Scheme: env.Scheme})
		if err != nil {
			t.Fatal(err)
		}
		staleClient := interceptor.NewClient(cached, interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if out, ok := obj.(*sopsv1alpha1.SopsSecret); ok && key == client.ObjectKeyFromObject(s) {
					stale.DeepCopyInto(out)
					return nil
				}
				return c.Get(ctx, key, obj, opts...)
			},
		})
		r := &controller.SopsSecretReconciler{
			Client:     staleClient,
			APIReader:  env.Operator,
			Identities: identity.NewFactory(env.OperatorConfig, env.Scheme),
		}
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(s)}); err != nil {
			t.Fatal(err)
		}
		var got sopsv1alpha1.SopsSecret
		if err := env.Admin.Get(ctx, client.ObjectKeyFromObject(s), &got); err != nil {
			t.Fatal(err)
		}
		if c := readyCondition(&got); c == nil || c.Reason != sopsv1alpha1.ReasonDecrypted {
			t.Fatalf("Ready = %+v, want Decrypted", c)
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

func TestSecretKeyNames(t *testing.T) {
	for _, name := range []string{sopsv1alpha1.TenantKeySecretName(tenantName), sopsv1alpha1.TenantNextKeySecretName(tenantName)} {
		t.Run("shall refuse to write the key Secret name "+name+" of a tenant in its namespace", func(t *testing.T) {
			tenantNS, recipient := onboardedTenant(t)
			before := &corev1.Secret{}
			beforeErr := env.Admin.Get(context.Background(), client.ObjectKey{Namespace: tenantNS, Name: name}, before)
			s := encryptedSopsSecret(t, recipient, tenantNS, tenantNS, name, tenantNS+"/"+name, map[string]any{"a": "b"})
			create(t, s)
			eventuallyReason(t, s, sopsv1alpha1.ReasonConflict)
			if c := readyCondition(s); !strings.Contains(c.Message, "SopsTenant") {
				t.Fatalf("message %q does not name the SopsTenant", c.Message)
			}
			if apierrors.IsNotFound(beforeErr) {
				assertNoSecret(t, tenantNS, name)
				return
			}
			assertUnchanged(t, before)
		})
	}
}
