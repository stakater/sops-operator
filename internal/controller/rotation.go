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

// healthy reports whether a SopsSecret's current generation was decrypted (DESIGN.md §4.4, start).
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

func setRotated(t *sopsv1alpha1.SopsTenant, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&t.Status.Conditions, metav1.Condition{
		Type: sopsv1alpha1.ConditionRotated, Status: status, Reason: reason, Message: message,
		ObservedGeneration: t.Generation,
	})
}

// reconcileRotation runs the key rotation of DESIGN.md §4.4. It changes t.Status; the caller
// writes it. Key Secrets are accessed through tc, the tenant identity.
func (r *SopsTenantReconciler) reconcileRotation(ctx context.Context, t *sopsv1alpha1.SopsTenant, tc client.Client,
	users []sopsv1alpha1.SopsSecret) error {
	if t.Status.Rotation == nil {
		return r.startRotation(ctx, t, tc, users)
	}
	rot := t.Status.Rotation
	// The phase is written with the rest of the status at the end of a reconcile, so a completion
	// that crashed after replacing the key is recognised by the key itself: finish it.
	var current corev1.Secret
	if err := tc.Get(ctx, client.ObjectKey{Namespace: t.Namespace, Name: sopsv1alpha1.TenantKeySecretName(t.Name)}, &current); err != nil {
		return err
	}
	if holdsKey(&current, rot.NextPublicKey) {
		rot.Phase = sopsv1alpha1.RotationPhaseCompleting
	}
	var nextSecret corev1.Secret
	err := tc.Get(ctx, client.ObjectKey{Namespace: t.Namespace, Name: rot.NextKeySecretName}, &nextSecret)
	switch {
	case apierrors.IsNotFound(err) && rot.Phase == sopsv1alpha1.RotationPhaseCompleting:
		return r.completeRotation(ctx, t, tc, users, &current, nil)
	case apierrors.IsNotFound(err):
		return r.abandonRotation(ctx, t, users)
	case err != nil:
		return err
	}
	if rot.Phase == sopsv1alpha1.RotationPhaseCompleting {
		// The key Secret already holds the next key: the content of the next key Secret is not needed.
		return r.completeRotation(ctx, t, tc, users, &current, &nextSecret)
	}
	nextKeys, err := crypto.ParseKeyFile(nextSecret.Data[crypto.KeyFileField])
	if err != nil || nextKeys.Recipients[0] != rot.NextPublicKey {
		setRotated(t, metav1.ConditionFalse, sopsv1alpha1.ReasonNextKeyMissing, fmt.Sprintf(
			"Secret %s does not hold the next key %s; restore it from a backup", rot.NextKeySecretName, rot.NextPublicKey))
		return nil
	}

	var pending []sopsv1alpha1.SopsSecret
	for _, s := range users {
		if !migratedIn(&s, rot) {
			pending = append(pending, s)
		}
	}
	rot.Migrated, rot.Pending = int32(len(users)-len(pending)), int32(len(pending))
	rot.PendingSecrets = names(pending)
	switch {
	case t.Spec.StartRotation:
		setRotated(t, metav1.ConditionFalse, sopsv1alpha1.ReasonRotationPending, fmt.Sprintf(
			"%d SopsSecrets do not use the next key yet; add %s to .sops.yaml and run scripts/rotate.sh",
			len(pending), rot.NextPublicKey))
	case len(pending) > 0:
		setRotated(t, metav1.ConditionFalse, sopsv1alpha1.ReasonRotationBlocked, fmt.Sprintf(
			"the rotation completes once %d more SopsSecrets use the next key: %s",
			len(pending), strings.Join(rot.PendingSecrets, ", ")))
		for i := range pending {
			r.Recorder.Eventf(&pending[i], t, corev1.EventTypeWarning, sopsv1alpha1.ReasonRotationBlocked,
				sopsv1alpha1.ActionCompleteRotation, "tenant %s/%s waits for this file to use the next key %s; "+
					"run scripts/rotate.sh and commit", t.Namespace, t.Name, rot.NextPublicKey)
		}
	default:
		// The decision to replace the key rests on a live list, not on the informer cache: a file
		// re-applied without the next-key entry must not count as migrated.
		live, err := r.liveUsers(ctx, t)
		if err != nil {
			return err
		}
		var stillPending []sopsv1alpha1.SopsSecret
		for _, s := range live {
			if !migratedIn(&s, rot) {
				stillPending = append(stillPending, s)
			}
		}
		if len(stillPending) > 0 {
			rot.Migrated, rot.Pending = int32(len(live)-len(stillPending)), int32(len(stillPending))
			rot.PendingSecrets = names(stillPending)
			setRotated(t, metav1.ConditionFalse, sopsv1alpha1.ReasonRotationBlocked, fmt.Sprintf(
				"the rotation completes once %d more SopsSecrets use the next key: %s",
				len(stillPending), strings.Join(rot.PendingSecrets, ", ")))
			return nil
		}
		rot.Phase = sopsv1alpha1.RotationPhaseCompleting
		return r.completeRotation(ctx, t, tc, live, &current, &nextSecret)
	}
	return nil
}

// migratedIn reports whether a SopsSecret's current generation was decrypted with the next key
// of the rotation rot.
func migratedIn(s *sopsv1alpha1.SopsSecret, rot *sopsv1alpha1.TenantRotationStatus) bool {
	rs := s.Status.Rotation
	return rs != nil && rs.StartedAt.Equal(&rot.StartedAt) && rs.Migrated && s.Status.ObservedGeneration == s.Generation
}

// completeRotation replaces the current key with the next key, deletes the next key Secret and
// clears the rotation status (DESIGN.md §4.4, completion). Every step can be repeated: next is
// nil when an earlier attempt already deleted the next key Secret.
func (r *SopsTenantReconciler) completeRotation(ctx context.Context, t *sopsv1alpha1.SopsTenant, tc client.Client,
	users []sopsv1alpha1.SopsSecret, current, next *corev1.Secret) error {
	rot := t.Status.Rotation
	keyName := sopsv1alpha1.TenantKeySecretName(t.Name)
	if next != nil {
		if !holdsKey(current, rot.NextPublicKey) {
			current.Data = map[string][]byte{
				crypto.KeyFileField: next.Data[crypto.KeyFileField], crypto.PublicKeyField: []byte(rot.NextPublicKey),
			}
			if err := tc.Update(ctx, current); err != nil {
				return fmt.Errorf("replace the key in %s/%s: %w", t.Namespace, keyName, err)
			}
		}
		if err := tc.Delete(ctx, next); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("delete %s/%s: %w", t.Namespace, next.Name, err)
		}
	}
	for i := range users {
		if err := clearRotation(ctx, r.Client, &users[i]); err != nil {
			return err
		}
	}
	t.Status.LastRotation = &sopsv1alpha1.LastRotation{
		StartedAt: rot.StartedAt, CompletedAt: metav1.NewTime(r.now()), PreviousPublicKey: t.Status.PublicKey,
	}
	t.Status.PublicKey = rot.NextPublicKey
	t.Status.Rotation = nil
	setRotated(t, metav1.ConditionTrue, sopsv1alpha1.ReasonRotationComplete,
		"the next key replaced the old key; remove the old public key from .sops.yaml and run scripts/rotate.sh")
	r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, sopsv1alpha1.ReasonRotationComplete,
		sopsv1alpha1.ActionCompleteRotation, "the next key replaced the old key in Secret %s", keyName)
	return nil
}

// abandonRotation ends a rotation whose next key is gone. Every file is still encrypted for
// the current key unless it was encrypted for the next key alone; then abandoning is refused.
func (r *SopsTenantReconciler) abandonRotation(ctx context.Context, t *sopsv1alpha1.SopsTenant,
	users []sopsv1alpha1.SopsSecret) error {
	rot := t.Status.Rotation
	var nextOnly []sopsv1alpha1.SopsSecret
	for _, s := range users {
		if !encryptedFor(&s, t.Status.PublicKey) {
			nextOnly = append(nextOnly, s)
		}
	}
	if t.Spec.StartRotation || len(nextOnly) > 0 {
		msg := fmt.Sprintf("Secret %s with the next key %s is missing; restore it from a backup",
			rot.NextKeySecretName, rot.NextPublicKey)
		if len(nextOnly) > 0 {
			msg += fmt.Sprintf(". These SopsSecrets are encrypted for the next key only: %s", strings.Join(names(nextOnly), ", "))
		} else {
			msg += ", or set startRotation to false to abandon the rotation"
		}
		setRotated(t, metav1.ConditionFalse, sopsv1alpha1.ReasonNextKeyMissing, msg)
		return nil
	}
	// The SopsSecret controller never clears a rotation status, so the tenant does.
	for i := range users {
		if err := clearRotation(ctx, r.Client, &users[i]); err != nil {
			return err
		}
	}
	t.Status.Rotation = nil
	setRotated(t, metav1.ConditionFalse, sopsv1alpha1.ReasonRotationAbandoned,
		"the rotation was abandoned because its next key is missing; every file still decrypts with the current key")
	return nil
}

// encryptedFor reports whether a SopsSecret's file has an entry for recipient.
func encryptedFor(s *sopsv1alpha1.SopsSecret, recipient string) bool {
	for _, a := range s.Sops.Age {
		if a.Recipient == recipient {
			return true
		}
	}
	return false
}

// clearRotation removes a SopsSecret's rotation status.
func clearRotation(ctx context.Context, c client.Client, s *sopsv1alpha1.SopsSecret) error {
	if s.Status.Rotation == nil {
		return nil
	}
	base := s.DeepCopy()
	s.Status.Rotation = nil
	return client.IgnoreNotFound(c.Status().Patch(ctx, s, client.MergeFrom(base)))
}

func (r *SopsTenantReconciler) startRotation(ctx context.Context, t *sopsv1alpha1.SopsTenant, tc client.Client,
	users []sopsv1alpha1.SopsSecret) error {
	nextName := sopsv1alpha1.TenantNextKeySecretName(t.Name)
	var orphan corev1.Secret
	err := tc.Get(ctx, client.ObjectKey{Namespace: t.Namespace, Name: nextName}, &orphan)
	orphaned := err == nil
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if !t.Spec.StartRotation {
		if c := meta.FindStatusCondition(t.Status.Conditions, sopsv1alpha1.ConditionRotated); c != nil &&
			c.Reason == sopsv1alpha1.ReasonRotationRefused {
			meta.RemoveStatusCondition(&t.Status.Conditions, sopsv1alpha1.ConditionRotated)
		}
		// A next key without a rotation was created just before a crash and never published.
		if orphaned && orphan.Labels[sopsv1alpha1.LabelManagedBy] == sopsv1alpha1.ManagedByValue {
			return client.IgnoreNotFound(tc.Delete(ctx, &orphan))
		}
		return nil
	}

	if orphaned && orphan.Labels[sopsv1alpha1.LabelManagedBy] != sopsv1alpha1.ManagedByValue {
		setRotated(t, metav1.ConditionFalse, sopsv1alpha1.ReasonRotationRefused, fmt.Sprintf(
			"Secret %s/%s was not created by the operator; remove it to start the rotation", t.Namespace, nextName))
		return nil
	}

	var unhealthy []sopsv1alpha1.SopsSecret
	for _, s := range users {
		if !healthy(&s) {
			unhealthy = append(unhealthy, s)
		}
	}
	if len(unhealthy) > 0 {
		setRotated(t, metav1.ConditionFalse, sopsv1alpha1.ReasonRotationRefused, fmt.Sprintf(
			"%d SopsSecrets are not Decrypted; the rotation starts once they are: %s",
			len(unhealthy), strings.Join(names(unhealthy), ", ")))
		return nil
	}

	recipient, startedAt := "", metav1.NewTime(r.now())
	if orphaned {
		keys, err := crypto.ParseKeyFile(orphan.Data[crypto.KeyFileField])
		if err != nil {
			// Never published, so nothing depends on it: start over with a fresh key.
			if err := tc.Delete(ctx, &orphan); client.IgnoreNotFound(err) != nil {
				return err
			}
			orphaned = false
		} else {
			recipient, startedAt = keys.Recipients[0], orphan.CreationTimestamp
			r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, sopsv1alpha1.ReasonRotationPending,
				sopsv1alpha1.ActionStartRotation, "adopted the next key in Secret %s", nextName)
		}
	}
	if !orphaned {
		keyFile, rec, err := crypto.GenerateKeyFile(r.now())
		if err != nil {
			return err
		}
		next := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: nextName, Namespace: t.Namespace,
				Labels: map[string]string{sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{crypto.KeyFileField: keyFile, crypto.PublicKeyField: []byte(rec)},
		}
		if err := tc.Create(ctx, next); err != nil {
			return fmt.Errorf("create next key Secret %s/%s: %w", t.Namespace, nextName, err)
		}
		recipient = rec
		r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, sopsv1alpha1.ReasonRotationPending,
			sopsv1alpha1.ActionStartRotation, "created the next key in Secret %s", nextName)
	}
	if err := r.stampAccepted(ctx, users, startedAt); err != nil {
		return err
	}
	t.Status.Rotation = &sopsv1alpha1.TenantRotationStatus{
		Phase: sopsv1alpha1.RotationPhaseInProgress, StartedAt: startedAt,
		NextKeySecretName: nextName, NextPublicKey: recipient,
		Pending: int32(len(users)), PendingSecrets: names(users),
	}
	setRotated(t, metav1.ConditionFalse, sopsv1alpha1.ReasonRotationPending, fmt.Sprintf(
		"%d SopsSecrets do not use the next key yet; add %s to .sops.yaml and run scripts/rotate.sh",
		len(users), recipient))
	return nil
}

// stampAccepted records, before the rotation is published, that the generation of every SopsSecret
// in users is accepted with the current key alone (DESIGN.md §4.4). All of them are healthy at the
// start, so a later failure in the SopsSecret controller cannot lose the acceptance.
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

// holdsKey reports whether the key Secret's primary key is recipient.
func holdsKey(key *corev1.Secret, recipient string) bool {
	keys, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
	return err == nil && keys.Recipients[0] == recipient
}

// liveUsers lists the tenant's SopsSecrets uncached. Field indexes do not exist on the uncached
// reader, so it lists all SopsSecrets and filters by spec.tenantRef.
func (r *SopsTenantReconciler) liveUsers(ctx context.Context, t *sopsv1alpha1.SopsTenant) ([]sopsv1alpha1.SopsSecret, error) {
	var reader client.Reader = r.Client
	if r.APIReader != nil {
		reader = r.APIReader
	}
	var all sopsv1alpha1.SopsSecretList
	if err := reader.List(ctx, &all); err != nil {
		return nil, err
	}
	var out []sopsv1alpha1.SopsSecret
	for _, s := range all.Items {
		if ref := s.Spec.TenantRef; ref.Namespace == t.Namespace && ref.Name == t.Name {
			out = append(out, s)
		}
	}
	return out, nil
}
