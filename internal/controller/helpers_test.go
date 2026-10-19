package controller_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

const tenantName = "my-team"

// readyCondition returns the Ready condition of a SopsTenant or SopsSecret, or nil.
func readyCondition(obj client.Object) *metav1.Condition {
	switch o := obj.(type) {
	case *sopsv1alpha1.SopsTenant:
		return meta.FindStatusCondition(o.Status.Conditions, sopsv1alpha1.ConditionReady)
	case *sopsv1alpha1.SopsSecret:
		return meta.FindStatusCondition(o.Status.Conditions, sopsv1alpha1.ConditionReady)
	}
	return nil
}

// eventuallyReason waits until obj's Ready condition has the given reason; obj is refreshed in place.
func eventuallyReason(t *testing.T, obj client.Object, reason string) {
	t.Helper()
	NewWithT(t).Eventually(func(g Gomega) {
		g.Expect(env.Admin.Get(context.Background(), client.ObjectKeyFromObject(obj), obj)).To(Succeed())
		c := readyCondition(obj)
		g.Expect(c).NotTo(BeNil())
		g.Expect(c.Reason).To(Equal(reason), "message: %s", c.Message)
	}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(Succeed())
}

// onboardedTenant creates an onboarded tenant namespace with a generated key and returns the
// namespace and the key's recipient.
func onboardedTenant(t *testing.T, writeNS ...string) (string, string) {
	t.Helper()
	ctx := context.Background()
	tenantNS := env.Namespace(t, "tenant")
	env.Onboard(t, tenantNS, tenantName, writeNS...)
	tenant := &sopsv1alpha1.SopsTenant{ObjectMeta: metav1.ObjectMeta{Name: tenantName, Namespace: tenantNS}}
	if err := env.Admin.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	NewWithT(t).Eventually(func(g Gomega) {
		g.Expect(env.Admin.Get(ctx, client.ObjectKeyFromObject(tenant), tenant)).To(Succeed())
		g.Expect(meta.IsStatusConditionTrue(tenant.Status.Conditions, sopsv1alpha1.ConditionReady)).To(BeTrue())
	}).WithTimeout(20 * time.Second).Should(Succeed())

	var key corev1.Secret
	if err := env.Admin.Get(ctx, client.ObjectKey{Namespace: tenantNS, Name: sopsv1alpha1.TenantKeySecretName(tenantName)}, &key); err != nil {
		t.Fatal(err)
	}
	ks, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
	if err != nil {
		t.Fatal(err)
	}
	return tenantNS, ks.Recipients[0]
}

// encryptedSopsSecret builds a SopsSecret named name in ns whose values are encrypted for recipient,
// each with the scope line "<scope>/<key>".
func encryptedSopsSecret(t *testing.T, recipient, tenantNS, ns, name, scope string, values map[string]string) *sopsv1alpha1.SopsSecret {
	t.Helper()
	data := map[string]sopsv1alpha1.EncryptedValue{}
	for key, value := range values {
		enc, err := crypto.EncryptValue([]byte(scope+"/"+key+"\n"+value), []string{recipient})
		if err != nil {
			t.Fatal(err)
		}
		data[key] = sopsv1alpha1.EncryptedValue(enc)
	}
	return &sopsv1alpha1.SopsSecret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: sopsv1alpha1.SopsSecretSpec{
			TenantRef:     sopsv1alpha1.TenantReference{Name: tenantName, Namespace: tenantNS},
			EncryptedData: data,
		},
	}
}

// tampered flips a bit in the authentication tag at the end of a base64-encoded age file.
func tampered(t *testing.T, value sopsv1alpha1.EncryptedValue) sopsv1alpha1.EncryptedValue {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(string(value))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	return sopsv1alpha1.EncryptedValue(base64.StdEncoding.EncodeToString(raw))
}

// update applies mutate to obj and updates it, retrying on conflicts with the operator's writes.
func update(t *testing.T, obj client.Object, mutate func()) {
	t.Helper()
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := env.Admin.Get(context.Background(), client.ObjectKeyFromObject(obj), obj); err != nil {
			return err
		}
		mutate()
		return env.Admin.Update(context.Background(), obj)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// assertUnchanged fails when obj was written since the caller last read it.
func assertUnchanged(t *testing.T, obj client.Object) {
	t.Helper()
	current := obj.DeepCopyObject().(client.Object)
	if err := env.Admin.Get(context.Background(), client.ObjectKeyFromObject(obj), current); err != nil {
		t.Fatal(err)
	}
	if current.GetResourceVersion() != obj.GetResourceVersion() {
		t.Fatalf("%s was modified", client.ObjectKeyFromObject(obj))
	}
}
