package controller_test

import (
	"context"
	"maps"
	"os"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

func newTenant(ns string, generate *bool) *sopsv1alpha1.SopsTenant {
	return &sopsv1alpha1.SopsTenant{
		ObjectMeta: metav1.ObjectMeta{Name: tenantName, Namespace: ns},
		Spec:       sopsv1alpha1.SopsTenantSpec{GenerateKey: generate},
	}
}

// keySecret returns a key Secret a tenant admin brings for tenantName in ns, labelled for adoption.
func keySecret(ns string, keyFile string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: sopsv1alpha1.TenantKeySecretName(tenantName, 0), Namespace: ns,
			Labels: map[string]string{sopsv1alpha1.LabelEnabled: sopsv1alpha1.EnabledValue},
		},
		Data: map[string][]byte{crypto.KeyFileField: []byte(keyFile)},
	}
}

func TestTenantKeyAdoption(t *testing.T) {
	t.Run("shall not adopt a key Secret without the enabled label and name the label to add", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, tenantName)
		x, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		key := keySecret(ns, x.String()+"\n")
		key.Labels = nil
		if err := env.Admin.Create(ctx, key); err != nil {
			t.Fatal(err)
		}
		tenant := newTenant(ns, nil)
		if err := env.Admin.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyMissing)
		if c := readyCondition(tenant); !strings.Contains(c.Message, sopsv1alpha1.LabelEnabled) {
			t.Fatalf("message %q does not name the label to add", c.Message)
		}
		if tenantOf(t, ns).Status.PublicKey != "" {
			t.Fatal("an unadopted key was recorded in status.publicKey")
		}
		assertUnchanged(t, key)
	})

	t.Run("shall not adopt an output Secret named like the key Secret", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, tenantName)
		x, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		output := keySecret(ns, x.String()+"\n")
		output.Labels[sopsv1alpha1.LabelManagedBy] = sopsv1alpha1.ManagedByValue
		output.Annotations = map[string]string{sopsv1alpha1.AnnotationSopsSecret: output.Name}
		if err := env.Admin.Create(ctx, output); err != nil {
			t.Fatal(err)
		}
		tenant := newTenant(ns, nil)
		if err := env.Admin.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyMissing)
		assertUnchanged(t, output)
	})

	t.Run("shall not adopt a labelled key Secret that has an owner", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, tenantName)
		x, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		owner := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "owner", Namespace: ns}}
		if err := env.Admin.Create(ctx, owner); err != nil {
			t.Fatal(err)
		}
		owned := keySecret(ns, x.String()+"\n")
		owned.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: owner.Name, UID: owner.UID}}
		if err := env.Admin.Create(ctx, owned); err != nil {
			t.Fatal(err)
		}
		tenant := newTenant(ns, nil)
		if err := env.Admin.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyMissing)
		assertUnchanged(t, owned)
	})

}

func TestTenantKey(t *testing.T) {
	t.Run("shall generate a post-quantum key", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, tenantName)
		tenant := newTenant(ns, nil)
		if err := env.Admin.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(ctx, client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
			c := readyCondition(tenant)
			g.Expect(c).NotTo(BeNil())
			g.Expect(c.Status).To(Equal(metav1.ConditionTrue))
		}).WithTimeout(20 * time.Second).Should(Succeed())

		if want := tenantName + "-sops-keys-0"; tenant.Status.KeySecretName != want {
			t.Fatalf("status.keySecretName = %q, want %q", tenant.Status.KeySecretName, want)
		}
		var key corev1.Secret
		if err := env.Admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: tenantName + "-sops-keys-0"}, &key); err != nil {
			t.Fatal(err)
		}
		ks, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(ks.Recipients[0], "age1pq1") {
			t.Fatal("generated key is not post-quantum")
		}
		assertSealedKey(t, &key, ks.Recipients[0])
		assertKeyLabels(t, &key)
		if tenant.Status.PublicKey != ks.Recipients[0] {
			t.Fatalf("status.publicKey = %q, want the generated key's public key", tenant.Status.PublicKey)
		}
		if len(key.OwnerReferences) != 0 {
			t.Fatal("key Secret must not have an ownerReference")
		}
	})

	t.Run("shall generate a key for the console sample without a key Secret", func(t *testing.T) {
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, tenantName)
		tenant := createSample(t, "sops_v1alpha1_sopstenant.yaml", ns)
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyGenerated)
		keyName := client.ObjectKey{Namespace: ns, Name: sopsv1alpha1.TenantKeySecretName(tenant.Name, 0)}
		if err := env.Admin.Get(context.Background(), keyName, &corev1.Secret{}); err != nil {
			t.Fatalf("generated key Secret: %v", err)
		}
	})

	t.Run("shall load the existing key for the console sample", func(t *testing.T) {
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, "my-team-existing-key")
		keyFile, _, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		key := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: sopsv1alpha1.TenantKeySecretName("my-team-existing-key", 0), Namespace: ns,
				Labels: map[string]string{sopsv1alpha1.LabelEnabled: sopsv1alpha1.EnabledValue},
			},
			Data: map[string][]byte{crypto.KeyFileField: keyFile},
		}
		if err := env.Admin.Create(context.Background(), key); err != nil {
			t.Fatal(err)
		}
		tenant := createSample(t, "sops_v1alpha1_sopstenant_existing_key.yaml", ns)
		if sopsv1alpha1.TenantKeySecretName(tenant.Name, 0) != key.Name {
			t.Fatalf("the sample names tenant %q; its key Secret must be %s", tenant.Name, key.Name)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyLoaded)
	})

	t.Run("shall not generate a key for the existing-key sample", func(t *testing.T) {
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, "my-team-existing-key")
		tenant := createSample(t, "sops_v1alpha1_sopstenant_existing_key.yaml", ns)
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyMissing)
	})

	t.Run("shall make a brought key immutable with its public key and keep its private key", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, tenantName)
		x, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		key := keySecret(ns, x.String()+"\n")
		if err := env.Admin.Create(ctx, key); err != nil {
			t.Fatal(err)
		}
		if err := env.Admin.Create(ctx, newTenant(ns, nil)); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, newTenant(ns, nil), sopsv1alpha1.ReasonKeyLoaded)

		var after corev1.Secret
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(ctx, client.ObjectKeyFromObject(key), &after)).To(Succeed())
			g.Expect(after.Immutable).To(HaveValue(BeTrue()))
		}).WithTimeout(20 * time.Second).Should(Succeed())
		assertSealedKey(t, &after, x.Recipient().String())
		if string(after.Data[crypto.KeyFileField]) != x.String()+"\n" {
			t.Fatal("the private key was changed")
		}
	})

	t.Run("shall report an invalid key", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, tenantName)
		key := keySecret(ns, "-----BEGIN OPENSSH PRIVATE KEY-----\n")
		if err := env.Admin.Create(ctx, key); err != nil {
			t.Fatal(err)
		}
		if err := env.Admin.Create(ctx, newTenant(ns, nil)); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, newTenant(ns, nil), sopsv1alpha1.ReasonKeyInvalid)
		assertUnchanged(t, key)
	})

	t.Run("shall report a missing key when generation is disabled", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, tenantName)
		if err := env.Admin.Create(ctx, newTenant(ns, ptr.To(false))); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, newTenant(ns, nil), sopsv1alpha1.ReasonKeyMissing)
		err := env.Admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: sopsv1alpha1.TenantKeySecretName(tenantName, 0)}, &corev1.Secret{})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("key Secret must not be created: %v", err)
		}
	})

	t.Run("shall report AccessDenied when not onboarded", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		if err := env.Admin.Create(ctx, newTenant(ns, nil)); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, newTenant(ns, nil), sopsv1alpha1.ReasonAccessDenied)
		err := env.Admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: sopsv1alpha1.TenantKeySecretName(tenantName, 0)}, &corev1.Secret{})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("key Secret must not be created: %v", err)
		}
	})

	t.Run("shall count the SopsSecrets using it", func(t *testing.T) {
		ctx := context.Background()
		target := env.Namespace(t, "target")
		tenantNS, recipient := onboardedTenant(t, target)
		for _, name := range []string{"a", "b"} {
			s := encryptedSopsSecret(t, recipient, tenantNS, target, name, target+"/"+name, map[string]any{"k": "v"})
			if err := env.Admin.Create(ctx, s); err != nil {
				t.Fatal(err)
			}
		}
		tenant := newTenant(tenantNS, nil)
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(env.Admin.Get(ctx, client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
			g.Expect(tenant.Status.UsedBy).To(Equal(int32(2)))
		}).WithTimeout(20 * time.Second).Should(Succeed())
	})
}

func TestTenantPublicKey(t *testing.T) {
	t.Run("shall replace a wrong public key in a brought key Secret with the key's own", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, tenantName)
		x, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		other, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		key := keySecret(ns, x.String()+"\n")
		key.Data["age.pub"] = []byte(other.Recipient().String())
		if err := env.Admin.Create(ctx, key); err != nil {
			t.Fatal(err)
		}
		if err := env.Admin.Create(ctx, newTenant(ns, nil)); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, newTenant(ns, nil), sopsv1alpha1.ReasonKeyLoaded)
		if got := tenantOf(t, ns).Status.PublicKey; got != x.Recipient().String() {
			t.Fatalf("status.publicKey = %q, want the primary key from age.agekey", got)
		}
		var after corev1.Secret
		if err := env.Admin.Get(ctx, client.ObjectKeyFromObject(key), &after); err != nil {
			t.Fatal(err)
		}
		assertSealedKey(t, &after, x.Recipient().String())
	})
}

// createSample creates the SopsTenant sample file from config/samples in ns, as the console does
// in the user's current project.
func createSample(t *testing.T, file, ns string) *sopsv1alpha1.SopsTenant {
	t.Helper()
	b, err := os.ReadFile("../../config/samples/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var tenant sopsv1alpha1.SopsTenant
	if err := yaml.Unmarshal(b, &tenant); err != nil {
		t.Fatal(err)
	}
	tenant.Namespace = ns
	if err := env.Admin.Create(context.Background(), &tenant); err != nil {
		t.Fatal(err)
	}
	return &tenant
}

func TestTenantEvents(t *testing.T) {
	t.Run("shall record a KeyGenerated event on the tenant through the events API", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, tenantName)
		tenant := newTenant(ns, nil)
		if err := env.Admin.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyGenerated)
		NewWithT(t).Eventually(func(g Gomega) {
			var events eventsv1.EventList
			g.Expect(env.Admin.List(ctx, &events, client.InNamespace(ns))).To(Succeed())
			var got []eventsv1.Event
			for _, e := range events.Items {
				if e.Regarding.UID == tenant.UID && e.Reason == sopsv1alpha1.ReasonKeyGenerated {
					got = append(got, e)
				}
			}
			g.Expect(got).To(HaveLen(1), "KeyGenerated events regarding the tenant")
			g.Expect(got[0].Type).To(Equal(corev1.EventTypeNormal))
			g.Expect(got[0].ReportingController).To(Equal("sops-operator"))
			g.Expect(got[0].Action).To(Equal("GenerateKey"))
		}).WithTimeout(20 * time.Second).Should(Succeed())
	})
}

// The operator creates the tenant identity; only the cluster admin's RoleBindings give it access.
func TestTenantServiceAccount(t *testing.T) {
	const saName = tenantName + "-sops-tenant"

	t.Run("shall report AccessDenied naming the operator binding until the namespace is granted", func(t *testing.T) {
		ns := env.Namespace(t, "tenant")
		tenant := newTenant(ns, nil)
		if err := env.Admin.Create(context.Background(), tenant); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonAccessDenied)
		if msg := readyCondition(tenant).Message; !strings.Contains(msg, "sops-operator-tenant") {
			t.Fatalf("AccessDenied message does not name the ClusterRole to bind to the operator: %q", msg)
		}
	})

	t.Run("shall create the tenant ServiceAccount and name the binding it still needs", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.AllowOperator(t, ns)
		tenant := newTenant(ns, nil)
		if err := env.Admin.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonAccessDenied)
		if msg := readyCondition(tenant).Message; !strings.Contains(msg, "sops-key-owner") ||
			!strings.Contains(msg, ns+"/"+saName) {
			t.Fatalf("AccessDenied message does not name the ClusterRole and ServiceAccount to bind: %q", msg)
		}
		if tenant.Status.ServiceAccountName != saName {
			t.Fatalf("status.serviceAccountName = %q, want %q", tenant.Status.ServiceAccountName, saName)
		}
		var sa corev1.ServiceAccount
		if err := env.Admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: saName}, &sa); err != nil {
			t.Fatalf("tenant ServiceAccount: %v", err)
		}
		if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
			t.Fatal("the tenant ServiceAccount must not automount a token")
		}
		want := map[string]string{
			"app.kubernetes.io/managed-by": "sops-operator",
			"app.kubernetes.io/component":  "tenant-identity",
			"app.kubernetes.io/instance":   tenantName,
		}
		for k, v := range want {
			if sa.Labels[k] != v {
				t.Fatalf("label %s = %q, want %q", k, sa.Labels[k], v)
			}
		}
	})

	t.Run("shall generate the key as the tenant ServiceAccount once onboarded", func(t *testing.T) {
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, tenantName)
		tenant := newTenant(ns, nil)
		if err := env.Admin.Create(context.Background(), tenant); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyGenerated)
	})

	t.Run("shall leave an existing ServiceAccount unchanged", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: saName, Namespace: ns}}
		if err := env.Admin.Create(ctx, sa); err != nil {
			t.Fatal(err)
		}
		env.Onboard(t, ns, tenantName)
		tenant := newTenant(ns, nil)
		if err := env.Admin.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyGenerated)
		assertUnchanged(t, sa)
	})
}

// assertKeyLabels checks that a key Secret the operator created or adopted carries managed-by and the enabled label.
func assertKeyLabels(t *testing.T, key *corev1.Secret) {
	t.Helper()
	want := map[string]string{
		sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue,
		sopsv1alpha1.LabelEnabled:   sopsv1alpha1.EnabledValue,
	}
	if !maps.Equal(key.Labels, want) {
		t.Fatalf("key Secret %s labels %v, want %v", key.Name, key.Labels, want)
	}
}
