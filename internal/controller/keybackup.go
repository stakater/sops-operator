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
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

// readKeys reads the key Secret, nil when it does not exist, and the key backups of tenant t. A
// refused read is returned as the AccessDenied reason and message.
func readKeys(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant) (*corev1.Secret, []corev1.Secret,
	string, string, error) {
	key := &corev1.Secret{}
	err := tc.Get(ctx, client.ObjectKey{Namespace: t.Namespace, Name: sopsv1alpha1.TenantKeySecretName(t.Name)}, key)
	switch {
	case apierrors.IsNotFound(err):
		key = nil
	case apierrors.IsForbidden(err):
		return nil, nil, sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot read its key Secret; " + onboardHint(t), nil
	case err != nil:
		return nil, nil, "", "", err
	}
	backups, err := listBackups(ctx, tc, t)
	if apierrors.IsForbidden(err) {
		return nil, nil, sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot list its key backups; " + onboardHint(t), nil
	}
	if err != nil {
		return nil, nil, "", "", err
	}
	return key, backups, "", "", nil
}

// listBackups returns the key backups of tenant t, oldest first: the Secrets labelled as key backups
// in the tenant namespace named <tenant>-sops-keys-<YYYYMMDD-HHMMSS>.
func listBackups(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant) ([]corev1.Secret, error) {
	var list corev1.SecretList
	if err := tc.List(ctx, &list, client.InNamespace(t.Namespace),
		client.MatchingLabels{sopsv1alpha1.LabelKeyBackup: "true"}); err != nil {
		return nil, err
	}
	prefix := sopsv1alpha1.TenantKeySecretName(t.Name) + "-"
	var out []corev1.Secret
	for _, s := range list.Items {
		stamp, ok := strings.CutPrefix(s.Name, prefix)
		if !ok {
			continue
		}
		if _, err := time.Parse(sopsv1alpha1.KeyBackupTimeFormat, stamp); err == nil {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// backupOf returns the backup of the key whose public key is recipient, or nil.
func backupOf(backups []corev1.Secret, recipient string) *corev1.Secret {
	for i := range backups {
		if recipient != "" && backups[i].Annotations[sopsv1alpha1.AnnotationPublicKey] == recipient {
			return &backups[i]
		}
	}
	return nil
}

// restoreSource returns the backup the key Secret must hold outside a rotation: the backup of the
// recorded key. A tenant without a recorded key (recreated) keeps a key Secret that one of its
// backups holds, and otherwise restores the newest backup. key is nil when the key Secret is missing.
func restoreSource(recorded string, key *corev1.Secret, backups []corev1.Secret) *corev1.Secret {
	if recorded != "" {
		return backupOf(backups, recorded)
	}
	if key != nil && adopted(key) {
		for i := range backups {
			if holdsSame(key, &backups[i]) {
				return &backups[i]
			}
		}
	}
	if len(backups) == 0 {
		return nil
	}
	return &backups[len(backups)-1]
}

// holdsSame reports whether the key Secrets a and b hold the same key file.
func holdsSame(a, b *corev1.Secret) bool {
	return bytes.Equal(a.Data[crypto.KeyFileField], b.Data[crypto.KeyFileField])
}

// needsRestore reports whether the key Secret key, which is no output Secret, differs from the
// backup from or lost the enabled label.
func needsRestore(key, from *corev1.Secret) bool {
	return !fromSopsSecret(key) && (!adopted(key) || !holdsSame(key, from))
}

// ensureBackup writes an immutable backup of the key file keyFile, whose public key is recipient,
// unless backups already has one. The name carries the time of r's clock in UTC; a name taken by a
// backup of another key written in the same second fails, and the retry takes the next second.
func (r *SopsTenantReconciler) ensureBackup(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant,
	backups []corev1.Secret, keyFile []byte, recipient string) (*corev1.Secret, error) {
	if b := backupOf(backups, recipient); b != nil {
		return b, nil
	}
	b := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        sopsv1alpha1.TenantKeyBackupName(t.Name, r.now()),
			Namespace:   t.Namespace,
			Labels:      backupLabels(),
			Annotations: map[string]string{sopsv1alpha1.AnnotationPublicKey: recipient},
		},
		Immutable: ptr.To(true),
		Type:      corev1.SecretTypeOpaque,
		Data:      map[string][]byte{crypto.KeyFileField: keyFile},
	}
	if err := tc.Create(ctx, b); err != nil {
		return nil, fmt.Errorf("back up the key %s in %s/%s: %w", recipient, t.Namespace, b.Name, err)
	}
	return b, nil
}

// writeKey writes the key file of backup from into the key Secret: it creates the Secret when key is
// nil, and otherwise replaces its data and adds the enabled label. It returns the public key written.
func writeKey(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant, key, from *corev1.Secret) (string, error) {
	keys, err := crypto.ParseKeyFile(from.Data[crypto.KeyFileField])
	if err != nil {
		return "", fmt.Errorf("key backup %s/%s does not hold a valid key: %w", from.Namespace, from.Name, err)
	}
	data := map[string][]byte{crypto.KeyFileField: from.Data[crypto.KeyFileField]}
	if key == nil {
		err = tc.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: sopsv1alpha1.TenantKeySecretName(t.Name), Namespace: t.Namespace, Labels: keyLabels(),
			},
			Type: corev1.SecretTypeOpaque,
			Data: data,
		})
	} else {
		if key.Labels == nil {
			key.Labels = map[string]string{}
		}
		key.Labels[sopsv1alpha1.LabelEnabled] = sopsv1alpha1.EnabledValue
		key.Data = data
		err = tc.Update(ctx, key)
	}
	if err != nil {
		return "", fmt.Errorf("write the key of backup %s into %s/%s: %w", from.Name, t.Namespace,
			sopsv1alpha1.TenantKeySecretName(t.Name), err)
	}
	return keys.Recipients[0], nil
}
