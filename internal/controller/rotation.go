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
	return nil // progress and completion: Task 6
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
		if err := r.Status().Patch(ctx, s, client.MergeFrom(base)); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("stamp rotation on SopsSecret %s/%s: %w", s.Namespace, s.Name, err)
		}
	}
	return nil
}
