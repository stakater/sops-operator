package controller_test

import (
	"bytes"
	"context"
	"maps"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

var backupName = regexp.MustCompile(`^` + tenantName + `-sops-keys-\d{8}-\d{6}$`)

// keyBackups returns the key backups of tenantName in ns, oldest first.
func keyBackups(t *testing.T, ns string) []corev1.Secret {
	t.Helper()
	var list corev1.SecretList
	if err := env.Admin.List(context.Background(), &list, client.InNamespace(ns),
		client.MatchingLabels{sopsv1alpha1.LabelKeyBackup: "true"}); err != nil {
		t.Fatal(err)
	}
	var out []corev1.Secret
	for _, s := range list.Items {
		if backupName.MatchString(s.Name) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// eventuallyBackups waits until tenantName in ns has exactly the backups of the given public keys.
func eventuallyBackups(t *testing.T, ns string, publicKeys ...string) []corev1.Secret {
	t.Helper()
	var backups []corev1.Secret
	NewWithT(t).Eventually(func(g Gomega) {
		backups = keyBackups(t, ns)
		var got []string
		for _, b := range backups {
			got = append(got, b.Annotations[sopsv1alpha1.AnnotationPublicKey])
		}
		g.Expect(got).To(ConsistOf(publicKeys), "public keys of the key backups")
	}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(Succeed())
	return backups
}

// tenantKey returns the key Secret of tenantName in ns.
func tenantKey(t *testing.T, ns string) *corev1.Secret {
	t.Helper()
	var key corev1.Secret
	if err := env.Admin.Get(context.Background(), client.ObjectKey{Namespace: ns,
		Name: sopsv1alpha1.TenantKeySecretName(tenantName)}, &key); err != nil {
		t.Fatal(err)
	}
	return &key
}

// eventuallyKeyFile waits until the key Secret of tenantName in ns holds keyFile and the enabled label.
func eventuallyKeyFile(t *testing.T, ns string, keyFile []byte) *corev1.Secret {
	t.Helper()
	var key corev1.Secret
	NewWithT(t).Eventually(func(g Gomega) {
		g.Expect(env.Admin.Get(context.Background(), client.ObjectKey{Namespace: ns,
			Name: sopsv1alpha1.TenantKeySecretName(tenantName)}, &key)).To(Succeed())
		g.Expect(bytes.Equal(key.Data[crypto.KeyFileField], keyFile)).To(BeTrue(), "the key Secret holds the expected key")
		g.Expect(key.Labels).To(HaveKeyWithValue(sopsv1alpha1.LabelEnabled, sopsv1alpha1.EnabledValue))
	}).WithTimeout(20 * time.Second).WithPolling(200 * time.Millisecond).Should(Succeed())
	return &key
}

// backupSecret returns a key backup of keyFile named after tenantName and at.
func backupSecret(ns string, keyFile []byte, recipient string, at time.Time) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: sopsv1alpha1.TenantKeyBackupName(tenantName, at), Namespace: ns,
			Labels: map[string]string{
				sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue,
				sopsv1alpha1.LabelEnabled:   sopsv1alpha1.EnabledValue,
				sopsv1alpha1.LabelKeyBackup: "true",
			},
			Annotations: map[string]string{sopsv1alpha1.AnnotationPublicKey: recipient},
		},
		Immutable: ptr.To(true),
		Data:      map[string][]byte{crypto.KeyFileField: keyFile},
	}
}

// eventuallyEvent waits until an event with reason, type and action regards the object with uid in ns.
func eventuallyEvent(t *testing.T, ns string, uid types.UID, reason, eventType, action string) {
	t.Helper()
	NewWithT(t).Eventually(func(g Gomega) {
		var events eventsv1.EventList
		g.Expect(env.Admin.List(context.Background(), &events, client.InNamespace(ns))).To(Succeed())
		found := false
		for _, e := range events.Items {
			if e.Regarding.UID == uid && e.Reason == reason && e.Type == eventType && e.Action == action {
				found = true
			}
		}
		g.Expect(found).To(BeTrue(), "a %s event %s with action %s", eventType, reason, action)
	}).WithTimeout(20 * time.Second).Should(Succeed())
}

func TestKeyBackup(t *testing.T) {
	t.Run("shall back up a generated key in an immutable Secret named after the key Secret and the UTC time", func(t *testing.T) {
		ns, recipient := onboardedTenant(t)
		backups := eventuallyBackups(t, ns, recipient)
		b := backups[0]
		if !backupName.MatchString(b.Name) {
			t.Fatalf("backup name %q does not match %s", b.Name, backupName)
		}
		if b.Immutable == nil || !*b.Immutable {
			t.Fatal("the key backup is not immutable")
		}
		want := map[string]string{
			sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue,
			sopsv1alpha1.LabelEnabled:   sopsv1alpha1.EnabledValue,
			sopsv1alpha1.LabelKeyBackup: "true",
		}
		if !maps.Equal(b.Labels, want) {
			t.Fatalf("backup labels %v, want %v", b.Labels, want)
		}
		assertOnlyKeyFile(t, &b)
		if !bytes.Equal(b.Data[crypto.KeyFileField], tenantKey(t, ns).Data[crypto.KeyFileField]) {
			t.Fatal("the backup does not hold the key of the key Secret")
		}
		if len(b.OwnerReferences) != 0 {
			t.Fatal("a key backup must not have an owner")
		}
	})

	t.Run("shall back up a brought key the first time it loads it without changing the key", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, tenantName)
		keyFile, recipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		key := keySecret(ns, string(keyFile))
		if err := env.Admin.Create(ctx, key); err != nil {
			t.Fatal(err)
		}
		tenant := newTenant(ns, nil)
		if err := env.Admin.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyLoaded)
		backups := eventuallyBackups(t, ns, recipient)
		if !bytes.Equal(backups[0].Data[crypto.KeyFileField], keyFile) {
			t.Fatal("the backup does not hold the brought key")
		}
		assertUnchanged(t, key)
	})

	t.Run("shall keep a single backup of the key across resyncs", func(t *testing.T) {
		ns, recipient := onboardedTenant(t)
		eventuallyBackups(t, ns, recipient)
		NewWithT(t).Consistently(func() int {
			return len(keyBackups(t, ns))
		}).WithTimeout(3*resync).WithPolling(200*time.Millisecond).Should(Equal(1), "number of key backups")
	})
}

func TestKeyRestore(t *testing.T) {
	t.Run("shall restore a deleted key from its backup and record a KeyRestored event", func(t *testing.T) {
		ns, recipient := onboardedTenant(t)
		eventuallyBackups(t, ns, recipient)
		key := tenantKey(t, ns)
		if err := env.Admin.Delete(context.Background(), key); err != nil {
			t.Fatal(err)
		}
		restored := eventuallyKeyFile(t, ns, key.Data[crypto.KeyFileField])
		if restored.UID == key.UID {
			t.Fatal("the key Secret was not recreated")
		}
		tenant := tenantOf(t, ns)
		eventuallyEvent(t, ns, tenant.UID, sopsv1alpha1.ReasonKeyRestored, corev1.EventTypeWarning, sopsv1alpha1.ActionRestoreKey)
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyLoaded)
		if tenant.Status.PublicKey != recipient {
			t.Fatalf("status.publicKey = %q, want the restored key", tenant.Status.PublicKey)
		}
		eventuallyBackups(t, ns, recipient)
	})

	t.Run("shall restore a key whose content was replaced", func(t *testing.T) {
		ns, recipient := onboardedTenant(t)
		eventuallyBackups(t, ns, recipient)
		key := tenantKey(t, ns)
		original := key.Data[crypto.KeyFileField]
		other, _, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		update(t, key, func() { key.Data[crypto.KeyFileField] = other })
		eventuallyKeyFile(t, ns, original)
		if got := tenantOf(t, ns).Status.PublicKey; got != recipient {
			t.Fatalf("status.publicKey = %q, want the restored key", got)
		}
		eventuallyBackups(t, ns, recipient)
	})

	t.Run("shall restore a key that lost its enabled label", func(t *testing.T) {
		ns, recipient := onboardedTenant(t)
		eventuallyBackups(t, ns, recipient)
		key := tenantKey(t, ns)
		update(t, key, func() { delete(key.Labels, sopsv1alpha1.LabelEnabled) })
		eventuallyKeyFile(t, ns, key.Data[crypto.KeyFileField])
	})

	t.Run("shall restore the newest backup for a recreated tenant instead of generating a key", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, tenantName)
		older, olderRecipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		newer, newerRecipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range []*corev1.Secret{
			backupSecret(ns, older, olderRecipient, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
			backupSecret(ns, newer, newerRecipient, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)),
		} {
			if err := env.Admin.Create(ctx, b); err != nil {
				t.Fatal(err)
			}
		}
		tenant := newTenant(ns, nil)
		if err := env.Admin.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		eventuallyKeyFile(t, ns, newer)
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyLoaded)
		if tenant.Status.PublicKey != newerRecipient {
			t.Fatalf("status.publicKey = %q, want the newest backup's key", tenant.Status.PublicKey)
		}
		eventuallyBackups(t, ns, olderRecipient, newerRecipient)
	})

	t.Run("shall load the surviving key of a recreated tenant without changing it", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, tenantName)
		keyFile, recipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		key := keySecret(ns, string(keyFile))
		for _, s := range []*corev1.Secret{key, backupSecret(ns, keyFile, recipient, time.Now())} {
			if err := env.Admin.Create(ctx, s); err != nil {
				t.Fatal(err)
			}
		}
		tenant := newTenant(ns, nil)
		if err := env.Admin.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyLoaded)
		if tenant.Status.PublicKey != recipient {
			t.Fatalf("status.publicKey = %q, want the surviving key", tenant.Status.PublicKey)
		}
		assertUnchanged(t, key)
		eventuallyBackups(t, ns, recipient)
	})
}

func TestKeyWatch(t *testing.T) {
	t.Run("shall hold the watch of the key Secret while the tenant exists and release it on deletion", func(t *testing.T) {
		ns, _ := onboardedTenant(t)
		tenant := tenantOf(t, ns)
		owner := client.ObjectKeyFromObject(tenant)
		NewWithT(t).Eventually(func() bool { return keyWatches.Holds(owner) }).
			WithTimeout(20*time.Second).Should(BeTrue(), "key Secret watch held for %s", owner)
		if err := env.Admin.Delete(context.Background(), tenant); err != nil {
			t.Fatal(err)
		}
		NewWithT(t).Eventually(func() bool { return keyWatches.Holds(owner) }).
			WithTimeout(20*time.Second).Should(BeFalse(), "key Secret watch held for %s", owner)
	})
}

func TestKeyNoRegeneration(t *testing.T) {
	t.Run("shall not generate a key while SopsSecrets use the tenant", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		prod := env.Namespace(t, "prod")
		_, recipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		s := encryptedSopsSecret(t, recipient, ns, prod, "db", prod+"/db", map[string]any{"password": "v1"})
		create(t, s)
		env.Onboard(t, ns, tenantName, prod)
		tenant := newTenant(ns, nil)
		if err := env.Admin.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyMissing)
		if msg := readyCondition(tenant).Message; !strings.Contains(msg, "1 SopsSecrets") {
			t.Fatalf("message %q does not say that a SopsSecret uses the tenant", msg)
		}
		NewWithT(t).Consistently(func() bool {
			err := env.Admin.Get(ctx, client.ObjectKey{Namespace: ns,
				Name: sopsv1alpha1.TenantKeySecretName(tenantName)}, &corev1.Secret{})
			return apierrors.IsNotFound(err) && len(keyBackups(t, ns)) == 0
		}).WithTimeout(2*resync).WithPolling(200*time.Millisecond).Should(BeTrue(), "no key Secret and no backup")
	})

	t.Run("shall label and back up a key generated by v0.0.4", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, tenantName)
		keyFile, recipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		old := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: sopsv1alpha1.TenantKeySecretName(tenantName), Namespace: ns,
				Labels: map[string]string{sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue},
			},
			Data: map[string][]byte{crypto.KeyFileField: keyFile, "age.pub": []byte(recipient)},
		}
		if err := env.Admin.Create(ctx, old); err != nil {
			t.Fatal(err)
		}
		tenant := newTenant(ns, nil)
		if err := env.Admin.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		eventuallyReason(t, tenant, sopsv1alpha1.ReasonKeyLoaded)
		eventuallyBackups(t, ns, recipient)
		if key := eventuallyKeyFile(t, ns, keyFile); key.UID != old.UID {
			t.Fatal("the key Secret was replaced instead of labelled")
		}
	})

	t.Run("shall restore a backup for a tenant with generateKey false", func(t *testing.T) {
		ctx := context.Background()
		ns := env.Namespace(t, "tenant")
		env.Onboard(t, ns, tenantName)
		keyFile, recipient, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		if err := env.Admin.Create(ctx, backupSecret(ns, keyFile, recipient, time.Now())); err != nil {
			t.Fatal(err)
		}
		if err := env.Admin.Create(ctx, newTenant(ns, ptr.To(false))); err != nil {
			t.Fatal(err)
		}
		eventuallyKeyFile(t, ns, keyFile)
	})
}

func TestKeyWithoutStatus(t *testing.T) {
	t.Run("shall restore the backed-up key, not generate one, after the tenant's status is lost", func(t *testing.T) {
		ctx := context.Background()
		ns, recipient := onboardedTenant(t)
		eventuallyBackups(t, ns, recipient)
		key := tenantKey(t, ns)
		tenant := tenantOf(t, ns)
		tenant.Status = sopsv1alpha1.SopsTenantStatus{}
		if err := env.Admin.Status().Update(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		if err := env.Admin.Delete(ctx, key); err != nil {
			t.Fatal(err)
		}
		eventuallyKeyFile(t, ns, key.Data[crypto.KeyFileField])
		eventuallyBackups(t, ns, recipient)
	})

	t.Run("shall restore the newest backup over a replaced key after the tenant's status is lost", func(t *testing.T) {
		ctx := context.Background()
		ns, recipient := onboardedTenant(t)
		eventuallyBackups(t, ns, recipient)
		key := tenantKey(t, ns)
		original := key.Data[crypto.KeyFileField]
		other, _, err := crypto.GenerateKeyFile()
		if err != nil {
			t.Fatal(err)
		}
		tenant := tenantOf(t, ns)
		tenant.Status = sopsv1alpha1.SopsTenantStatus{}
		if err := env.Admin.Status().Update(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		update(t, key, func() { key.Data[crypto.KeyFileField] = other })
		eventuallyKeyFile(t, ns, original)
		eventuallyBackups(t, ns, recipient)
	})
}
