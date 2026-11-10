/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

// listKeys returns the key Secrets <tenant>-sops-keys-<index> of tenant t, highest index first,
// whether or not the operator may use them.
func listKeys(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant) ([]corev1.Secret, error) {
	var list corev1.SecretList
	if err := tc.List(ctx, &list, client.InNamespace(t.Namespace)); err != nil {
		return nil, err
	}
	var out []corev1.Secret
	for _, s := range list.Items {
		if sopsv1alpha1.TenantKeyIndex(t.Name, s.Name) >= 0 {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return sopsv1alpha1.TenantKeyIndex(t.Name, out[i].Name) > sopsv1alpha1.TenantKeyIndex(t.Name, out[j].Name)
	})
	return out, nil
}

// usableKeys returns the identities of every key Secret in keys the operator may use, in the order of
// keys, or nil when there is none.
func usableKeys(keys []corev1.Secret) *crypto.KeySet {
	var files []byte
	for i := range keys {
		if !adopted(&keys[i]) {
			continue
		}
		if _, err := crypto.ParseKeyFile(keys[i].Data[crypto.KeyFileField]); err == nil {
			files = append(files, keys[i].Data[crypto.KeyFileField]...)
			files = append(files, '\n')
		}
	}
	if files == nil {
		return nil
	}
	ks, err := crypto.ParseKeyFile(files)
	if err != nil {
		return nil
	}
	return ks
}

// reconcileKey returns the Ready reason and message for the tenant key. It decides from objects only,
// never from the tenant's status: the key Secrets <tenant>-sops-keys-<index> and the SopsSecrets of the
// tenant. The highest index is the current key, which must carry the enabled label and hold a valid key;
// there is no fall-back to a lower one. Every usable key Secret is made immutable with its public key in
// age.pub. Without a key Secret, a key from v0.0.4 is moved into <tenant>-sops-keys-0, or a key is
// generated when no SopsSecret uses the tenant.
func (r *SopsTenantReconciler) reconcileKey(ctx context.Context, t *sopsv1alpha1.SopsTenant) (string, string, error) {
	tc, err := r.Identities.ClientFor(t.Namespace, t.Name)
	if err != nil {
		return "", "", err
	}
	keys, err := listKeys(ctx, tc, t)
	if apierrors.IsForbidden(err) {
		return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot list its key Secrets; " + onboardHint(t), nil
	}
	if err != nil {
		return "", "", err
	}
	if len(keys) == 0 {
		return r.firstKey(ctx, tc, t)
	}
	for i := range keys {
		if err := sealKey(ctx, tc, &keys[i]); err != nil {
			if apierrors.IsForbidden(err) {
				return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot update its key Secrets; " + onboardHint(t), nil
			}
			return "", "", err
		}
	}
	current := &keys[0]
	switch {
	case fromSopsSecret(current):
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("Secret %s/%s is the output Secret of a SopsSecret, not a key",
			current.Namespace, current.Name), nil
	case !adopted(current):
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("Secret %s/%s is not adopted as the current key of this tenant; "+
			"to use it, add the label %s=%s", current.Namespace, current.Name, sopsv1alpha1.LabelEnabled, sopsv1alpha1.EnabledValue), nil
	}
	ks, err := crypto.ParseKeyFile(current.Data[crypto.KeyFileField])
	if err != nil {
		return sopsv1alpha1.ReasonKeyInvalid, fmt.Sprintf("Secret %s/%s: %v", current.Namespace, current.Name, err), nil
	}
	if pub := string(current.Data[crypto.PublicKeyField]); pub != ks.Recipients[0] {
		return sopsv1alpha1.ReasonKeyInvalid, fmt.Sprintf("Secret %s/%s is immutable and its %s does not match %s",
			current.Namespace, current.Name, crypto.PublicKeyField, crypto.KeyFileField), nil
	}
	t.Status.PublicKey, t.Status.KeySecretName = ks.Recipients[0], current.Name
	return sopsv1alpha1.ReasonKeyLoaded, "key loaded", nil
}

// sealKey makes the usable key Secret key immutable with the public key of its primary identity in
// age.pub. It changes neither a Secret it may not use nor one that is immutable already.
func sealKey(ctx context.Context, tc client.Client, key *corev1.Secret) error {
	if !adopted(key) || ptr.Deref(key.Immutable, false) {
		return nil
	}
	ks, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
	if err != nil {
		return nil
	}
	if key.Data == nil {
		key.Data = map[string][]byte{}
	}
	key.Data[crypto.PublicKeyField] = []byte(ks.Recipients[0])
	key.Immutable = ptr.To(true)
	if err := tc.Update(ctx, key); err != nil {
		return fmt.Errorf("make key Secret %s/%s immutable: %w", key.Namespace, key.Name, err)
	}
	return nil
}

// firstKey writes the first key Secret <tenant>-sops-keys-0 of a tenant without key Secrets: the key
// of the v0.0.4 key Secret <tenant>-sops-keys when there is one, otherwise a generated key. While
// SopsSecrets of the tenant exist, a key existed and their files need it: no key is generated. They
// are read uncached, so a cache that has not synced yet cannot hide them.
func (r *SopsTenantReconciler) firstKey(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant) (string, string, error) {
	first := sopsv1alpha1.TenantKeySecretName(t.Name, 0)
	legacy := &corev1.Secret{}
	err := tc.Get(ctx, client.ObjectKey{Namespace: t.Namespace, Name: sopsv1alpha1.LegacyKeySecretName(t.Name)}, legacy)
	switch {
	case apierrors.IsForbidden(err):
		return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot read its key Secrets; " + onboardHint(t), nil
	case err == nil && !fromSopsSecret(legacy):
		if !adopted(legacy) {
			return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("Secret %s/%s is not adopted as the key of this tenant; "+
				"to use it, add the label %s=%s", legacy.Namespace, legacy.Name, sopsv1alpha1.LabelEnabled, sopsv1alpha1.EnabledValue), nil
		}
		ks, err := crypto.ParseKeyFile(legacy.Data[crypto.KeyFileField])
		if err != nil {
			return sopsv1alpha1.ReasonKeyInvalid, fmt.Sprintf("Secret %s/%s: %v", legacy.Namespace, legacy.Name, err), nil
		}
		return r.createKey(ctx, tc, t, legacy.Data[crypto.KeyFileField], ks.Recipients[0], false)
	case err != nil && !apierrors.IsNotFound(err):
		return "", "", err
	}
	if !t.ShouldGenerateKey() {
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("key Secret %s/%s not found and generateKey is false", t.Namespace, first), nil
	}
	users, err := r.liveUsers(ctx, t)
	if err != nil {
		return "", "", err
	}
	if users > 0 {
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("key Secret %s/%s not found, and %d SopsSecrets use this tenant: "+
			"a new key would decrypt none of their files; restore the key Secret", t.Namespace, first, users), nil
	}
	keyFile, recipient, err := crypto.GenerateKeyFile()
	if err != nil {
		return "", "", err
	}
	return r.createKey(ctx, tc, t, keyFile, recipient, true)
}

// createKey creates the immutable key Secret <tenant>-sops-keys-0 holding keyFile and its public key
// recipient; generated reports whether the operator generated the key.
func (r *SopsTenantReconciler) createKey(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant,
	keyFile []byte, recipient string, generated bool) (string, string, error) {
	key := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sopsv1alpha1.TenantKeySecretName(t.Name, 0),
			Namespace: t.Namespace,
			Labels:    keyLabels(),
		},
		Immutable: ptr.To(true),
		Type:      corev1.SecretTypeOpaque,
		Data:      map[string][]byte{crypto.KeyFileField: keyFile, crypto.PublicKeyField: []byte(recipient)},
	}
	if err := tc.Create(ctx, key); err != nil {
		if apierrors.IsForbidden(err) {
			return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot create its key Secret; " + onboardHint(t), nil
		}
		// AlreadyExists: a key Secret appeared since the list; the next reconcile uses it.
		return "", "", fmt.Errorf("create key Secret %s/%s: %w", key.Namespace, key.Name, err)
	}
	t.Status.PublicKey, t.Status.KeySecretName = recipient, key.Name
	if !generated {
		return sopsv1alpha1.ReasonKeyLoaded, fmt.Sprintf("key moved from Secret %s into %s",
			sopsv1alpha1.LegacyKeySecretName(t.Name), key.Name), nil
	}
	r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, sopsv1alpha1.ReasonKeyGenerated, sopsv1alpha1.ActionGenerateKey,
		"generated a post-quantum key in Secret %s", key.Name)
	return sopsv1alpha1.ReasonKeyGenerated, "generated a post-quantum key", nil
}
