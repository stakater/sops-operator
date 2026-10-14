package controller_test

import (
	"context"
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

func keySecret(ns string, keyFile string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: tenantName, Namespace: ns},
		Data:       map[string][]byte{crypto.KeyFileField: []byte(keyFile)},
	}
}

func TestTenantKey(t *testing.T) {
	t.Run("shall generate a post-quantum key", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns)
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

		var key corev1.Secret
		if err := env.Admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: tenantName}, &key); err != nil {
			t.Fatal(err)
		}
		ks, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(ks.Recipients[0], "age1pq1") {
			t.Fatal("generated key is not post-quantum")
		}
		if got := strings.TrimSpace(string(key.Data[crypto.PublicKeyField])); got != ks.Recipients[0] {
			t.Fatal("the generated Secret does not hold the matching public key")
		}
		if key.Labels[sopsv1alpha1.LabelManagedBy] != sopsv1alpha1.ManagedByValue {
			t.Fatal("generated key is missing the managed-by label")
		}
		if len(key.OwnerReferences) != 0 {
			t.Fatal("key Secret must not have an ownerReference")
		}
	})

	t.Run("shall generate a key for the console sample without a key Secret", func(t *testing.T) {
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns)
		tenant := createSample(t, "sops_v1alpha1_sopstenant.yaml", ns)
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyGenerated)
		if err := env.Admin.Get(context.Background(), client.ObjectKeyFromObject(tenant), &corev1.Secret{}); err != nil {
			t.Fatalf("generated key Secret: %v", err)
		}
	})

	t.Run("shall load the existing key for the console sample", func(t *testing.T) {
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns)
		keyFile, _, err := crypto.GenerateKeyFile(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		key := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "my-team-existing-key", Namespace: ns},
			Data:       map[string][]byte{crypto.KeyFileField: keyFile},
		}
		if err := env.Admin.Create(context.Background(), key); err != nil {
			t.Fatal(err)
		}
		tenant := createSample(t, "sops_v1alpha1_sopstenant_existing_key.yaml", ns)
		if tenant.Name != key.Name {
			t.Fatalf("the sample names tenant %q; its key Secret must have the same name", tenant.Name)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyLoaded)
		assertUnchanged(t, key)
	})

	t.Run("shall not generate a key for the existing-key sample", func(t *testing.T) {
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns)
		tenant := createSample(t, "sops_v1alpha1_sopstenant_existing_key.yaml", ns)
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyMissing)
	})

	t.Run("shall load an existing key without changing it", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns)
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
		if err := env.Admin.Get(ctx, client.ObjectKeyFromObject(key), &after); err != nil {
			t.Fatal(err)
		}
		if after.ResourceVersion != key.ResourceVersion {
			t.Fatal("existing key Secret was modified")
		}
	})

	t.Run("shall report an invalid key", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns)
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

	t.Run("shall report an invalid key when the public key does not match", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns)
		x, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		other, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		key := keySecret(ns, x.String()+"\n")
		key.Data[crypto.PublicKeyField] = []byte(other.Recipient().String())
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
		env.Onboard(t, ns)
		if err := env.Admin.Create(ctx, newTenant(ns, ptr.To(false))); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, newTenant(ns, nil), sopsv1alpha1.ReasonKeyMissing)
		err := env.Admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: tenantName}, &corev1.Secret{})
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
		err := env.Admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: tenantName}, &corev1.Secret{})
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
		env.Onboard(t, ns)
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
	t.Run("shall create the tenant ServiceAccount and name the binding it still needs", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		tenant := newTenant(ns, nil)
		if err := env.Admin.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonAccessDenied)
		if msg := readyCondition(tenant).Message; !strings.Contains(msg, "sops-key-owner") ||
			!strings.Contains(msg, ns+"/sops") {
			t.Fatalf("AccessDenied message does not name the ClusterRole and ServiceAccount to bind: %q", msg)
		}
		var sa corev1.ServiceAccount
		if err := env.Admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: "sops"}, &sa); err != nil {
			t.Fatalf("tenant ServiceAccount: %v", err)
		}
		if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
			t.Fatal("the tenant ServiceAccount must not automount a token")
		}
		if sa.Labels[sopsv1alpha1.LabelManagedBy] != sopsv1alpha1.ManagedByValue {
			t.Fatal("the tenant ServiceAccount is missing the managed-by label")
		}
	})

	t.Run("shall leave an existing ServiceAccount unchanged", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "sops", Namespace: ns}}
		if err := env.Admin.Create(ctx, sa); err != nil {
			t.Fatal(err)
		}
		env.Onboard(t, ns)
		tenant := newTenant(ns, nil)
		if err := env.Admin.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyGenerated)
		assertUnchanged(t, sa)
	})
}
