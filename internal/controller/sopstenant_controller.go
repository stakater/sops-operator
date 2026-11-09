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
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/identity"
	"github.com/stakater/sops-operator/internal/secretwatch"
)

// SopsTenantReconciler loads or generates a tenant key and reports its state. It accesses the
// key Secret only as the tenant identity.
type SopsTenantReconciler struct {
	client.Client
	Identities *identity.Factory
	// Watches, when set, watches the key Secret as the tenant identity, so a deleted or changed key is
	// restored from its backup at once; otherwise it is restored at the next resync.
	Watches        *secretwatch.Watches
	Recorder       events.EventRecorder
	ResyncInterval time.Duration
	// Now is the clock of the key backup names; time.Now when nil.
	Now func() time.Time
}

// Reconcile implements reconcile.Reconciler.
func (r *SopsTenantReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var tenant sopsv1alpha1.SopsTenant
	if err := r.Get(ctx, req.NamespacedName, &tenant); err != nil {
		if apierrors.IsNotFound(err) {
			r.release(req.NamespacedName)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !tenant.DeletionTimestamp.IsZero() {
		r.release(req.NamespacedName)
		return ctrl.Result{}, nil
	}
	var users sopsv1alpha1.SopsSecretList
	if err := r.List(ctx, &users, client.MatchingFields{IndexTenantRef: TenantRefKey(tenant.Namespace, tenant.Name)}); err != nil {
		return ctrl.Result{}, err
	}
	reason, message, err := r.ensureServiceAccount(ctx, &tenant)
	if err == nil && reason == "" {
		reason, message, err = r.reconcileTenantKey(ctx, &tenant, users.Items)
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	status := metav1.ConditionFalse
	if reason == sopsv1alpha1.ReasonKeyLoaded || reason == sopsv1alpha1.ReasonKeyGenerated {
		status = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&tenant.Status.Conditions, metav1.Condition{
		Type:               sopsv1alpha1.ConditionReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: tenant.Generation,
	})
	tenant.Status.ObservedGeneration = tenant.Generation
	tenant.Status.ServiceAccountName = sopsv1alpha1.TenantServiceAccountName(tenant.Name)
	tenant.Status.KeySecretName = sopsv1alpha1.TenantKeySecretName(tenant.Name)
	tenant.Status.UsedBy = int32(len(users.Items))
	if err := r.Status().Update(ctx, &tenant); err != nil {
		return ctrl.Result{}, err
	}
	r.watchKey(ctx, &tenant, reason)
	return ctrl.Result{RequeueAfter: r.ResyncInterval}, nil
}

func (r *SopsTenantReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// watchKey holds the watch of the key Secret while the tenant identity may read it, and releases it
// while access is denied: the watch would only wait for a list it is refused.
func (r *SopsTenantReconciler) watchKey(ctx context.Context, t *sopsv1alpha1.SopsTenant, reason string) {
	if r.Watches == nil {
		return
	}
	owner := client.ObjectKeyFromObject(t)
	if reason == sopsv1alpha1.ReasonAccessDenied {
		r.Watches.Release(owner)
		return
	}
	if err := r.Watches.Watch(ctx, owner, owner); err != nil {
		// The resync still restores the key; the next reconcile tries the watch again.
		log.FromContext(ctx).Error(err, "watch the key Secret", "tenant", owner)
	}
}

func (r *SopsTenantReconciler) release(owner types.NamespacedName) {
	if r.Watches != nil {
		r.Watches.Release(owner)
	}
}

// ensureServiceAccount creates the tenant identity if it does not exist. It grants nothing: only
// the cluster admin's RoleBindings give it access. An existing ServiceAccount is never changed.
// It returns AccessDenied while the cluster admin has not let the operator act in the namespace.
func (r *SopsTenantReconciler) ensureServiceAccount(ctx context.Context, t *sopsv1alpha1.SopsTenant) (string, string, error) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sopsv1alpha1.TenantServiceAccountName(t.Name),
			Namespace: t.Namespace,
			Labels: map[string]string{
				sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue,
				sopsv1alpha1.LabelComponent: sopsv1alpha1.ComponentTenantIdentity,
				sopsv1alpha1.LabelInstance:  t.Name,
			},
		},
		AutomountServiceAccountToken: ptr.To(false),
	}
	err := r.Create(ctx, sa)
	switch {
	case err == nil, apierrors.IsAlreadyExists(err):
		return "", "", nil
	case apierrors.IsForbidden(err):
		return sopsv1alpha1.ReasonAccessDenied, fmt.Sprintf("the operator cannot create ServiceAccount %s/%s; the "+
			"cluster admin must bind ClusterRole sops-operator-tenant to the operator's ServiceAccount in %s",
			sa.Namespace, sa.Name, sa.Namespace), nil
	}
	return "", "", fmt.Errorf("create ServiceAccount %s/%s: %w", sa.Namespace, sa.Name, err)
}

// adoptKey checks that the key Secret key is enabled for the operator. A key Secret the operator
// generated before key Secrets carried the label is marked; any other unmarked Secret is refused with
// KeyMissing naming the label a tenant admin adds to adopt it.
func adoptKey(ctx context.Context, tc client.Client, key *corev1.Secret) (string, string, error) {
	if adopted(key) {
		return "", "", nil
	}
	if !createdByOperator(key) {
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("Secret %s/%s is not adopted as the key of this tenant; "+
			"to use it, add the label %s=%s", key.Namespace, key.Name, sopsv1alpha1.LabelEnabled, sopsv1alpha1.EnabledValue), nil
	}
	if key.Labels == nil {
		key.Labels = map[string]string{}
	}
	key.Labels[sopsv1alpha1.LabelEnabled] = sopsv1alpha1.EnabledValue
	if err := tc.Update(ctx, key); err != nil {
		return "", "", fmt.Errorf("label key Secret %s/%s: %w", key.Namespace, key.Name, err)
	}
	return "", "", nil
}

// adopted reports whether the key Secret s is enabled for the operator and is no output Secret of a
// SopsSecret, which is enabled too but carries an annotation and usually an owner. The tenant follows
// from the Secret's name and namespace.
func adopted(s *corev1.Secret) bool {
	return s.Labels[sopsv1alpha1.LabelEnabled] == sopsv1alpha1.EnabledValue && !fromSopsSecret(s)
}

// createdByOperator reports whether a key Secret without the enabled label was generated by an
// earlier version of the operator, which marked key and output Secrets with managed-by only.
func createdByOperator(s *corev1.Secret) bool {
	return s.Labels[sopsv1alpha1.LabelManagedBy] == sopsv1alpha1.ManagedByValue && !fromSopsSecret(s)
}

// fromSopsSecret reports whether s may be an output Secret: it names a SopsSecret or has an owner.
func fromSopsSecret(s *corev1.Secret) bool {
	_, annotated := s.Annotations[sopsv1alpha1.AnnotationSopsSecret]
	return annotated || len(s.OwnerReferences) != 0
}

// keyLabels are the labels of a key Secret the operator creates.
func keyLabels() map[string]string {
	return map[string]string{
		sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue,
		sopsv1alpha1.LabelEnabled:   sopsv1alpha1.EnabledValue,
	}
}

// reconcileTenantKey returns the Ready reason and message for the tenant key, outside a rotation or
// during one, and runs the rotation: its start, its key, and its progress.
func (r *SopsTenantReconciler) reconcileTenantKey(ctx context.Context, t *sopsv1alpha1.SopsTenant,
	users []sopsv1alpha1.SopsSecret) (string, string, error) {
	tc, err := r.Identities.ClientFor(t.Namespace, t.Name)
	if err != nil {
		return "", "", err
	}
	if t.Status.Rotation == nil {
		reason, message, err := r.reconcileKey(ctx, tc, t)
		if err != nil || reason != sopsv1alpha1.ReasonKeyLoaded && reason != sopsv1alpha1.ReasonKeyGenerated {
			return reason, message, err
		}
		if started, err := r.startRotation(ctx, t, users); err != nil || !started {
			return reason, message, err
		}
	}
	reason, message, err := r.rotatingKey(ctx, tc, t)
	if err != nil || reason != sopsv1alpha1.ReasonKeyLoaded {
		return reason, message, err
	}
	reconcileRotation(t, users)
	return reason, message, nil
}

// reconcileKey returns the Ready reason and message for the tenant key. Outside a rotation the key
// Secret holds the key recorded in status.publicKey: a deleted or changed key Secret, or one that lost
// the enabled label, is restored from the backup of that key. A key is generated only for a tenant
// that never had one: no key Secret, no recorded key and no backup.
func (r *SopsTenantReconciler) reconcileKey(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant) (string, string, error) {
	keyName := sopsv1alpha1.TenantKeySecretName(t.Name)
	key, backups, reason, message, err := readKeys(ctx, tc, t)
	if reason != "" || err != nil {
		return reason, message, err
	}
	recorded := t.Status.PublicKey
	if from := restoreSource(recorded, key, backups); from != nil && (key == nil || needsRestore(key, from)) {
		return r.restoreKey(ctx, tc, t, key, from)
	}
	if key == nil {
		return r.generateKey(ctx, tc, t, recorded)
	}
	if reason, message, err := adoptKey(ctx, tc, key); reason != "" || err != nil {
		return reason, message, err
	}
	keys, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
	if err != nil {
		return sopsv1alpha1.ReasonKeyInvalid, err.Error(), nil
	}
	if recorded != "" && !slices.Contains(keys.Recipients, recorded) {
		return sopsv1alpha1.ReasonKeyMismatch, fmt.Sprintf("Secret %s does not hold the key recorded in "+
			"status.publicKey (%s) and there is no backup of it; restore the matching key", keyName, recorded), nil
	}
	if _, err := r.ensureBackup(ctx, tc, t, backups, key.Data[crypto.KeyFileField], keys.Recipients[0]); err != nil {
		return "", "", err
	}
	t.Status.PublicKey = keys.Recipients[0]
	return sopsv1alpha1.ReasonKeyLoaded, "key loaded", nil
}

// restoreKey writes the key of backup from into the key Secret, which is nil when it is missing.
func (r *SopsTenantReconciler) restoreKey(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant,
	key, from *corev1.Secret) (string, string, error) {
	recipient, err := writeKey(ctx, tc, t, key, from)
	if apierrors.IsForbidden(err) {
		return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot restore its key Secret; " + onboardHint(t), nil
	}
	if err != nil {
		return "", "", err
	}
	t.Status.PublicKey = recipient
	r.Recorder.Eventf(t, nil, corev1.EventTypeWarning, sopsv1alpha1.ReasonKeyRestored, sopsv1alpha1.ActionRestoreKey,
		"restored the key in Secret %s from backup %s", sopsv1alpha1.TenantKeySecretName(t.Name), from.Name)
	return sopsv1alpha1.ReasonKeyLoaded, "key restored from backup " + from.Name, nil
}

// generateKey generates the key of a tenant without a key Secret and backs it up. A tenant with a
// recorded key never gets a new one: its key is lost unless the tenant admin restores it.
func (r *SopsTenantReconciler) generateKey(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant,
	recorded string) (string, string, error) {
	keyName := sopsv1alpha1.TenantKeySecretName(t.Name)
	if recorded != "" {
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("key Secret %s/%s not found and there is no backup of "+
			"the recorded key %s; restore the key Secret", t.Namespace, keyName, recorded), nil
	}
	if !t.ShouldGenerateKey() {
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("key Secret %s/%s not found and generateKey is false", t.Namespace, keyName), nil
	}
	keyFile, recipient, err := crypto.GenerateKeyFile()
	if err != nil {
		return "", "", err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      keyName,
			Namespace: t.Namespace,
			Labels:    keyLabels(),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{crypto.KeyFileField: keyFile},
	}
	if err := tc.Create(ctx, secret); err != nil {
		if apierrors.IsForbidden(err) {
			return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot create its key Secret; " +
				onboardHint(t), nil
		}
		// AlreadyExists: a key appeared since the read; the retry loads it.
		return "", "", err
	}
	// A failed backup is retried by the next reconcile, which loads the key and backs it up.
	if _, err := r.ensureBackup(ctx, tc, t, nil, keyFile, recipient); err != nil {
		return "", "", err
	}
	t.Status.PublicKey = recipient
	r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, sopsv1alpha1.ReasonKeyGenerated, sopsv1alpha1.ActionGenerateKey,
		"generated a post-quantum key in Secret %s", keyName)
	return sopsv1alpha1.ReasonKeyGenerated, "generated a post-quantum key", nil
}

// onboardHint names the RoleBinding the cluster admin creates to onboard a tenant.
func onboardHint(t *sopsv1alpha1.SopsTenant) string {
	return fmt.Sprintf("the cluster admin must bind ClusterRole sops-key-owner to ServiceAccount %s/%s in %s",
		t.Namespace, sopsv1alpha1.TenantServiceAccountName(t.Name), t.Namespace)
}

// SetupWithManager registers the controller.
func (r *SopsTenantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	b := ctrl.NewControllerManagedBy(mgr).
		For(&sopsv1alpha1.SopsTenant{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&sopsv1alpha1.SopsSecret{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
				ref := o.(*sopsv1alpha1.SopsSecret).Spec.TenantRef
				return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}}}
			}),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, rotationProgressChanged{})))
	if r.Watches != nil {
		b = b.WatchesRawSource(source.Channel(r.Watches.Events(), &handler.EnqueueRequestForObject{}))
	}
	return b.Named("sopstenant").Complete(r)
}

// rotationProgressChanged passes SopsSecret updates that change what a rotation counts: the
// rotation status or the Ready reason.
type rotationProgressChanged struct{ predicate.Funcs }

func (rotationProgressChanged) Update(e event.UpdateEvent) bool {
	oldS, okOld := e.ObjectOld.(*sopsv1alpha1.SopsSecret)
	newS, okNew := e.ObjectNew.(*sopsv1alpha1.SopsSecret)
	if !okOld || !okNew {
		return false
	}
	reason := func(s *sopsv1alpha1.SopsSecret) string {
		if c := meta.FindStatusCondition(s.Status.Conditions, sopsv1alpha1.ConditionReady); c != nil {
			return c.Reason
		}
		return ""
	}
	return !equality.Semantic.DeepEqual(oldS.Status.Rotation, newS.Status.Rotation) || reason(oldS) != reason(newS)
}
