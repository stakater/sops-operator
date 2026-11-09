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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

// backupTimeFormat is the readable UTC timestamp in a backup's name, <tenant>-sops-keys-<timestamp>.
const backupTimeFormat = "20060102-150405"

// remembered returns the key file last loaded for tenant t, held in memory only.
func (r *SopsTenantReconciler) remembered(t *sopsv1alpha1.SopsTenant) []byte {
	if v, ok := r.lastKeys.Load(t.Namespace + "/" + t.Name); ok {
		return v.([]byte)
	}
	return nil
}

func (r *SopsTenantReconciler) remember(t *sopsv1alpha1.SopsTenant, keyFile []byte) {
	r.lastKeys.Store(t.Namespace+"/"+t.Name, bytes.Clone(keyFile))
}

// keyBackups lists the backups of tenant t's keys.
func keyBackups(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant) ([]corev1.Secret, error) {
	var list corev1.SecretList
	if err := tc.List(ctx, &list, client.InNamespace(t.Namespace), client.MatchingLabels{
		sopsv1alpha1.LabelKeyBackup: "true", sopsv1alpha1.LabelTenant: t.Name, sopsv1alpha1.LabelTenantNamespace: t.Namespace,
	}); err != nil {
		return nil, fmt.Errorf("list key backups in %s: %w", t.Namespace, err)
	}
	return list.Items, nil
}

// backUpChanged saves the key file last loaded for tenant t as a backup when the key Secret's content
// is now current, or the Secret is gone (current nil), and differs from it. Outside a rotation keys do
// not change, so the previous key is kept for a tenant admin to restore; during a rotation changes are
// expected and nothing is saved. It returns the backup's name, or "" when none was needed.
func (r *SopsTenantReconciler) backUpChanged(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant,
	current []byte) (string, error) {
	previous := r.remembered(t)
	if t.Status.Rotation != nil || previous == nil || bytes.Equal(previous, current) {
		return "", nil
	}
	keys, err := crypto.ParseKeyFile(previous)
	if err != nil {
		return "", nil
	}
	recipient := keys.Recipients[0]
	backups, err := keyBackups(ctx, tc, t)
	if err != nil {
		return "", err
	}
	for _, b := range backups {
		if b.Annotations[sopsv1alpha1.AnnotationPublicKey] == recipient {
			return b.Name, nil
		}
	}
	labels := keyLabels(t)
	labels[sopsv1alpha1.LabelKeyBackup] = "true"
	backup := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        sopsv1alpha1.TenantKeySecretName(t.Name) + "-" + r.now().UTC().Format(backupTimeFormat),
			Namespace:   t.Namespace,
			Labels:      labels,
			Annotations: map[string]string{sopsv1alpha1.AnnotationPublicKey: recipient},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{crypto.KeyFileField: previous},
	}
	if err := tc.Create(ctx, backup); err != nil {
		return "", fmt.Errorf("back up key %s: %w", recipient, err)
	}
	r.Recorder.Eventf(t, nil, corev1.EventTypeWarning, sopsv1alpha1.ReasonKeyBackedUp, sopsv1alpha1.ActionBackUpKey,
		"key Secret %s changed outside a key rotation; saved the previous key %s in Secret %s",
		sopsv1alpha1.TenantKeySecretName(t.Name), recipient, backup.Name)
	return backup.Name, nil
}

// deleteBackups deletes every backup of tenant t's keys. A completed rotation verified that every
// SopsSecret uses the new key, so no earlier key is needed any more.
func deleteBackups(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant) error {
	backups, err := keyBackups(ctx, tc, t)
	if err != nil {
		return err
	}
	for i := range backups {
		if err := tc.Delete(ctx, &backups[i]); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("delete key backup %s: %w", backups[i].Name, err)
		}
	}
	return nil
}
