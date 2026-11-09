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
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
)

// healthy reports whether a SopsSecret's current generation was decrypted.
func healthy(s *sopsv1alpha1.SopsSecret) bool {
	c := meta.FindStatusCondition(s.Status.Conditions, sopsv1alpha1.ConditionReady)
	return c != nil && c.Status == metav1.ConditionTrue && c.Reason == sopsv1alpha1.ReasonDecrypted &&
		c.ObservedGeneration == s.Generation && s.Status.ObservedGeneration == s.Generation
}

// names returns up to MaxPendingSecrets SopsSecrets as sorted <namespace>/<name>.
func names(secrets []sopsv1alpha1.SopsSecret) []string {
	out := make([]string, 0, len(secrets))
	for _, s := range secrets {
		out = append(out, s.Namespace+"/"+s.Name)
	}
	sort.Strings(out)
	if len(out) > sopsv1alpha1.MaxPendingSecrets {
		out = out[:sopsv1alpha1.MaxPendingSecrets]
	}
	return out
}

// setRotated sets the Rotated condition False: the rotation was refused or is not complete.
func setRotated(t *sopsv1alpha1.SopsTenant, reason, message string) {
	meta.SetStatusCondition(&t.Status.Conditions, metav1.Condition{
		Type: sopsv1alpha1.ConditionRotated, Status: metav1.ConditionFalse, Reason: reason, Message: message,
		ObservedGeneration: t.Generation,
	})
}

// startRotation starts a key rotation asked for with spec.startRotation once every SopsSecret in
// users is healthy. It stamps their generations as accepted with the old key and records the
// rotation in the status before any key changes, so a rotation interrupted at any later step is
// resumed instead of restored over. It reports whether the rotation started.
func (r *SopsTenantReconciler) startRotation(ctx context.Context, t *sopsv1alpha1.SopsTenant,
	users []sopsv1alpha1.SopsSecret) (bool, error) {
	if !t.Spec.StartRotation {
		if c := meta.FindStatusCondition(t.Status.Conditions, sopsv1alpha1.ConditionRotated); c != nil &&
			c.Reason == sopsv1alpha1.ReasonRotationRefused {
			meta.RemoveStatusCondition(&t.Status.Conditions, sopsv1alpha1.ConditionRotated)
		}
		return false, nil
	}
	var unhealthy []sopsv1alpha1.SopsSecret
	for _, s := range users {
		if !healthy(&s) {
			unhealthy = append(unhealthy, s)
		}
	}
	if len(unhealthy) > 0 {
		setRotated(t, sopsv1alpha1.ReasonRotationRefused, fmt.Sprintf(
			"%d SopsSecrets are not Decrypted; the rotation starts once they are: %s",
			len(unhealthy), strings.Join(names(unhealthy), ", ")))
		return false, nil
	}
	startedAt := metav1.NewTime(r.now()).Rfc3339Copy()
	if err := r.stampAccepted(ctx, users, startedAt); err != nil {
		return false, err
	}
	phase := sopsv1alpha1.RotationPhaseInProgress
	if !t.ShouldGenerateKey() {
		phase = sopsv1alpha1.RotationPhaseWaitingForKey
	}
	t.Status.Rotation = &sopsv1alpha1.TenantRotationStatus{
		Phase: phase, StartedAt: startedAt, PreviousPublicKey: t.Status.PublicKey,
		Pending: int32(len(users)), PendingSecrets: names(users),
	}
	if err := r.Status().Update(ctx, t); err != nil {
		return false, fmt.Errorf("record the rotation start: %w", err)
	}
	return true, nil
}

// stampAccepted records, before the rotation is published, that the generation of every SopsSecret
// in users is accepted with the old key alone. All of them are healthy at the start, so a later
// failure in the SopsSecret controller cannot lose the acceptance.
func (r *SopsTenantReconciler) stampAccepted(ctx context.Context, users []sopsv1alpha1.SopsSecret,
	startedAt metav1.Time) error {
	for i := range users {
		s := &users[i]
		if prev := s.Status.Rotation; prev != nil && prev.StartedAt.Equal(&startedAt) {
			continue
		}
		base := s.DeepCopy()
		s.Status.Rotation = &sopsv1alpha1.SecretRotationStatus{StartedAt: startedAt, AcceptedGeneration: s.Generation}
		if err := r.Status().Patch(ctx, s, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("stamp rotation on SopsSecret %s/%s: %w", s.Namespace, s.Name, err)
		}
	}
	return nil
}

// rotatingKey returns the Ready reason and message for the tenant key during a rotation and puts the
// new key in place. The old key stays in its backup and is never written back into the key Secret
// here. The new key is the one backed up besides the old key; before there is one, it is a key the
// tenant admin put into the key Secret, or with generateKey a key the operator generates. Once the
// new key is backed up, the key Secret is restored from that backup like the key outside a rotation.
func (r *SopsTenantReconciler) rotatingKey(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant) (string, string, error) {
	rot := t.Status.Rotation
	keyName := sopsv1alpha1.TenantKeySecretName(t.Name)
	key, backups, reason, message, err := readKeys(ctx, tc, t)
	if reason != "" || err != nil {
		return reason, message, err
	}
	next := newKeyBackup(backups, rot.PreviousPublicKey)
	if next == nil {
		keyFile, recipient := newKeyIn(key, rot.PreviousPublicKey)
		if keyFile == nil && t.ShouldGenerateKey() {
			if keyFile, recipient, err = crypto.GenerateKeyFile(); err != nil {
				return "", "", err
			}
		}
		if keyFile == nil {
			rot.Phase = sopsv1alpha1.RotationPhaseWaitingForKey
			return sopsv1alpha1.ReasonKeyLoaded, "key loaded; the rotation waits for the new key", nil
		}
		if next, err = r.ensureBackup(ctx, tc, t, backups, keyFile, recipient); err != nil {
			return "", "", err
		}
	}
	placed := t.Status.PublicKey != rot.PreviousPublicKey
	if key == nil || needsRestore(key, next) {
		recipient, err := writeKey(ctx, tc, t, key, next)
		if apierrors.IsForbidden(err) {
			return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot write its key Secret; " + onboardHint(t), nil
		}
		if err != nil {
			return "", "", err
		}
		if placed && t.Status.PublicKey == recipient {
			r.Recorder.Eventf(t, nil, corev1.EventTypeWarning, sopsv1alpha1.ReasonKeyRestored, sopsv1alpha1.ActionRestoreKey,
				"restored the new key in Secret %s from backup %s", keyName, next.Name)
		}
	}
	t.Status.PublicKey = next.Annotations[sopsv1alpha1.AnnotationPublicKey]
	rot.Phase = sopsv1alpha1.RotationPhaseInProgress
	if !placed {
		r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, sopsv1alpha1.ReasonRotationPending, sopsv1alpha1.ActionStartRotation,
			"the new key is in Secret %s and backup %s; the old key stays in its backup", keyName, next.Name)
	}
	return sopsv1alpha1.ReasonKeyLoaded, "key loaded; rotating to the new key", nil
}

// newKeyBackup returns the newest backup of a key other than the old key previous, or nil.
func newKeyBackup(backups []corev1.Secret, previous string) *corev1.Secret {
	for i := len(backups) - 1; i >= 0; i-- {
		if backups[i].Annotations[sopsv1alpha1.AnnotationPublicKey] != previous {
			return &backups[i]
		}
	}
	return nil
}

// newKeyIn returns the key file and public key of the key Secret key when it holds a valid key other
// than the old key previous and is enabled for the operator; otherwise nil.
func newKeyIn(key *corev1.Secret, previous string) ([]byte, string) {
	if key == nil || !adopted(key) {
		return nil, ""
	}
	keys, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
	if err != nil || keys.Recipients[0] == previous {
		return nil, ""
	}
	return key.Data[crypto.KeyFileField], keys.Recipients[0]
}

// reconcileRotation reports the progress of a running rotation. It changes t.Status; the caller
// writes it.
func reconcileRotation(t *sopsv1alpha1.SopsTenant, users []sopsv1alpha1.SopsSecret) {
	rot := t.Status.Rotation
	if rot == nil {
		return
	}
	keyName := sopsv1alpha1.TenantKeySecretName(t.Name)
	if rot.Phase == sopsv1alpha1.RotationPhaseWaitingForKey {
		setRotated(t, sopsv1alpha1.ReasonWaitingForKey, fmt.Sprintf(
			"replace the key in Secret %s/%s with the new key, labelled %s=%s; the old key %s stays in its backup",
			t.Namespace, keyName, sopsv1alpha1.LabelEnabled, sopsv1alpha1.EnabledValue, rot.PreviousPublicKey))
		return
	}
	var pending []sopsv1alpha1.SopsSecret
	for _, s := range users {
		if !migratedIn(&s, rot) {
			pending = append(pending, s)
		}
	}
	rot.Migrated, rot.Pending = int32(len(users)-len(pending)), int32(len(pending))
	rot.PendingSecrets = names(pending)
	if t.Spec.StartRotation {
		setRotated(t, sopsv1alpha1.ReasonRotationPending, fmt.Sprintf(
			"%d SopsSecrets do not use the new key yet; add %s to .sops.yaml and run scripts/rotate.sh",
			len(pending), t.Status.PublicKey))
		return
	}
	setRotated(t, sopsv1alpha1.ReasonRotationBlocked, fmt.Sprintf(
		"the rotation completes once %d more SopsSecrets use the new key: %s",
		len(pending), strings.Join(rot.PendingSecrets, ", ")))
}

// migratedIn reports whether a SopsSecret's current generation was decrypted with the new key of
// the rotation rot. The observed generation alone does not tell: it moves on every outcome, while
// status.rotation is written only when the SopsSecret was decrypted.
func migratedIn(s *sopsv1alpha1.SopsSecret, rot *sopsv1alpha1.TenantRotationStatus) bool {
	rs := s.Status.Rotation
	return rs != nil && rs.StartedAt.Equal(&rot.StartedAt) && rs.Migrated && rs.MigratedGeneration == s.Generation
}
