package controller_test

import (
	"context"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

// backupKeys returns the public keys of the tenant's key backups.
func backupKeys(g Gomega, tenantNS string) []string {
	var list corev1.SecretList
	g.Expect(env.Admin.List(context.Background(), &list, client.InNamespace(tenantNS), client.MatchingLabels{
		sopsv1alpha1.LabelKeyBackup: "true", sopsv1alpha1.LabelTenant: tenantName,
		sopsv1alpha1.LabelTenantNamespace: tenantNS,
	})).To(Succeed())
	keys := []string{}
	for _, s := range list.Items {
		keys = append(keys, s.Annotations[sopsv1alpha1.AnnotationPublicKey])
	}
	return keys
}

func keySecretOf(t *testing.T, tenantNS string) *corev1.Secret {
	t.Helper()
	key := &corev1.Secret{}
	if err := env.Admin.Get(context.Background(), client.ObjectKey{Namespace: tenantNS, Name: sopsv1alpha1.TenantKeySecretName(tenantName)}, key); err != nil {
		t.Fatal(err)
	}
	return key
}

// keyedTenant returns an onboarded tenant namespace whose key is loaded, with its public key and key file.
func keyedTenant(t *testing.T) (tenantNS, recipient string, keyFile []byte) {
	t.Helper()
	tenantNS, recipient = onboardedTenant(t)
	NewWithT(t).Eventually(func(g Gomega) {
		g.Expect(tenantOf(t, tenantNS).Status.PublicKey).To(Equal(recipient))
	}).WithTimeout(20 * time.Second).Should(Succeed())
	return tenantNS, recipient, keySecretOf(t, tenantNS).Data[crypto.KeyFileField]
}

// eventuallyBackedUp waits until the tenant has exactly one backup, of keyFile with public key recipient.
func eventuallyBackedUp(t *testing.T, tenantNS, recipient string, keyFile []byte) {
	t.Helper()
	NewWithT(t).Eventually(func(g Gomega) {
		var list corev1.SecretList
		g.Expect(env.Admin.List(context.Background(), &list, client.InNamespace(tenantNS),
			client.MatchingLabels{sopsv1alpha1.LabelKeyBackup: "true"})).To(Succeed())
		g.Expect(list.Items).To(HaveLen(1))
		g.Expect(list.Items[0].Annotations).To(HaveKeyWithValue(sopsv1alpha1.AnnotationPublicKey, recipient))
		g.Expect(list.Items[0].Data[crypto.KeyFileField]).To(Equal(keyFile))
	}).WithTimeout(20 * time.Second).Should(Succeed())
}

func TestKeyBackup(t *testing.T) {
	t.Run("shall make no backup while the key is unchanged", func(t *testing.T) {
		tenantNS, _, _ := keyedTenant(t)
		NewWithT(t).Consistently(func(g Gomega) {
			g.Expect(backupKeys(g, tenantNS)).To(BeEmpty())
		}).WithTimeout(3 * resync).Should(Succeed())
	})

	t.Run("shall save the previous key once when the key is changed outside a rotation", func(t *testing.T) {
		tenantNS, recipient, keyFile := keyedTenant(t)
		other, _, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		key := keySecretOf(t, tenantNS)
		update(t, key, func() { key.Data[crypto.KeyFileField] = other })
		eventuallyReason(t, tenantOf(t, tenantNS), sopsv1alpha1.ReasonKeyMismatch)
		eventuallyBackedUp(t, tenantNS, recipient, keyFile)
		NewWithT(t).Consistently(func(g Gomega) {
			g.Expect(backupKeys(g, tenantNS)).To(Equal([]string{recipient}))
		}).WithTimeout(3 * resync).Should(Succeed())
	})

	t.Run("shall save a deleted key and name the backup instead of generating a new key", func(t *testing.T) {
		tenantNS, recipient, keyFile := keyedTenant(t)
		deleteObject(t, keySecretOf(t, tenantNS))
		tenant := tenantOf(t, tenantNS)
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyMissing)
		eventuallyBackedUp(t, tenantNS, recipient, keyFile)
		if c := readyCondition(tenant); !strings.Contains(c.Message, sopsv1alpha1.TenantKeySecretName(tenantName)+"-") {
			t.Fatalf("message %q does not name the backup", c.Message)
		}
		NewWithT(t).Consistently(func(g Gomega) {
			err := env.Admin.Get(context.Background(), client.ObjectKey{Namespace: tenantNS, Name: sopsv1alpha1.TenantKeySecretName(tenantName)}, &corev1.Secret{})
			g.Expect(err).To(HaveOccurred())
		}).WithTimeout(3 * resync).Should(Succeed())
	})

	t.Run("shall make no backup when only the key Secret's labels change", func(t *testing.T) {
		tenantNS, _, _ := keyedTenant(t)
		key := keySecretOf(t, tenantNS)
		update(t, key, func() { key.Labels["example.com/team"] = "a" })
		NewWithT(t).Consistently(func(g Gomega) {
			g.Expect(backupKeys(g, tenantNS)).To(BeEmpty())
		}).WithTimeout(3 * resync).Should(Succeed())
	})
}

func TestKeyBackupDuringRotation(t *testing.T) {
	t.Run("shall delete the tenant's key backups when the rotation completes", func(t *testing.T) {
		tenantNS, _, s, _ := rotatingTenant(t)
		backup := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: sopsv1alpha1.TenantKeySecretName(tenantName) + "-20260101-000000", Namespace: tenantNS,
				Labels: map[string]string{sopsv1alpha1.LabelKeyBackup: "true", sopsv1alpha1.LabelTenant: tenantName,
					sopsv1alpha1.LabelTenantNamespace: tenantNS},
				Annotations: map[string]string{sopsv1alpha1.AnnotationPublicKey: "age1old"}},
			Data: map[string][]byte{crypto.KeyFileField: []byte("old")},
		}
		if err := env.Admin.Create(context.Background(), backup); err != nil {
			t.Fatal(err)
		}
		migrate(t, s)
		tenant := tenantOf(t, tenantNS)
		setStartRotation(t, tenant, false)
		eventuallyRotated(t, tenant, sopsv1alpha1.ReasonRotationComplete)
		NewWithT(t).Eventually(func(g Gomega) {
			g.Expect(backupKeys(g, tenantNS)).To(BeEmpty())
		}).WithTimeout(20 * time.Second).Should(Succeed())
		NewWithT(t).Consistently(func(g Gomega) {
			g.Expect(backupKeys(g, tenantNS)).To(BeEmpty())
		}).WithTimeout(3 * resync).Should(Succeed())
	})
}
