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
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	// APIReader reads SopsSecrets uncached before a key is generated.
	APIReader  client.Reader
	Identities *identity.Factory
	// Watches, when set, watches the key Secret as the tenant identity, so a deleted or changed key is
	// restored from its backup at once; otherwise it is restored at the next resync.
	Watches        *secretwatch.Watches
	Recorder       events.EventRecorder
	ResyncInterval time.Duration
	// Now is the clock of key backup names; time.Now when nil.
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
	reason, message, err := r.ensureServiceAccount(ctx, &tenant)
	if err == nil && reason == "" {
		reason, message, err = r.reconcileKey(ctx, &tenant)
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	var users sopsv1alpha1.SopsSecretList
	if err := r.List(ctx, &users, client.MatchingFields{IndexTenantRef: TenantRefKey(tenant.Namespace, tenant.Name)}); err != nil {
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

// backupLabels are the labels of a key backup: those of a key Secret and the backup label.
func backupLabels() map[string]string {
	labels := keyLabels()
	labels[sopsv1alpha1.LabelKeyBackup] = "true"
	return labels
}

// keyLabels are the labels of a key Secret the operator creates.
func keyLabels() map[string]string {
	return map[string]string{
		sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue,
		sopsv1alpha1.LabelEnabled:   sopsv1alpha1.EnabledValue,
	}
}

// reconcileKey returns the Ready reason and message for the tenant key. It decides from objects only,
// never from the tenant's status: the key Secret, its backups and the SopsSecrets of the tenant. With a
// backup, the key Secret holds the newest backup's key: a deleted or changed key Secret, or one that
// lost the enabled label, is restored from it. Without a backup, a valid key Secret is backed up. A key
// is generated only when there is no key Secret, no backup and no SopsSecret of the tenant.
func (r *SopsTenantReconciler) reconcileKey(ctx context.Context, t *sopsv1alpha1.SopsTenant) (string, string, error) {
	// The public key is reported only for a key this reconcile loaded; no earlier value survives.
	t.Status.PublicKey = ""
	tc, err := r.Identities.ClientFor(t.Namespace, t.Name)
	if err != nil {
		return "", "", err
	}
	keyName := sopsv1alpha1.TenantKeySecretName(t.Name)
	key := &corev1.Secret{}
	err = tc.Get(ctx, client.ObjectKey{Namespace: t.Namespace, Name: keyName}, key)
	switch {
	case apierrors.IsNotFound(err):
		key = nil
	case apierrors.IsForbidden(err):
		return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot read its key Secret; " + onboardHint(t), nil
	case err != nil:
		return "", "", err
	}
	backups, err := listBackups(ctx, tc, t)
	if apierrors.IsForbidden(err) {
		return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot list its key backups; " + onboardHint(t), nil
	}
	if err != nil {
		return "", "", err
	}
	if key != nil && fromSopsSecret(key) {
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("Secret %s/%s is the output Secret of a SopsSecret, not a key",
			t.Namespace, keyName), nil
	}
	if len(backups) > 0 {
		newest := &backups[len(backups)-1]
		if key == nil || needsRestore(key, newest) {
			return r.restoreKey(ctx, tc, t, key, newest)
		}
		t.Status.PublicKey = newest.Annotations[sopsv1alpha1.AnnotationPublicKey]
		return sopsv1alpha1.ReasonKeyLoaded, "key loaded", nil
	}
	if key == nil {
		return r.generateKey(ctx, tc, t)
	}
	if reason, message, err := adoptKey(ctx, tc, key); reason != "" || err != nil {
		return reason, message, err
	}
	keys, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
	if err != nil {
		return sopsv1alpha1.ReasonKeyInvalid, err.Error(), nil
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

// generateKey generates the key of a tenant that has neither a key Secret nor a backup. It writes the
// backup first and then the key Secret, so a key that exists anywhere is never generated again. While
// SopsSecrets of the tenant exist, a key existed and their files need it: no key is generated. They are
// read uncached, so a cache that has not synced yet cannot hide them.
func (r *SopsTenantReconciler) generateKey(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant) (string, string, error) {
	keyName := sopsv1alpha1.TenantKeySecretName(t.Name)
	if !t.ShouldGenerateKey() {
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("key Secret %s/%s not found and generateKey is false", t.Namespace, keyName), nil
	}
	users, err := r.liveUsers(ctx, t)
	if err != nil {
		return "", "", err
	}
	if users > 0 {
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("key Secret %s/%s and its backups not found, and %d SopsSecrets "+
			"use this tenant: a new key would decrypt none of their files; restore the key Secret or a backup",
			t.Namespace, keyName, users), nil
	}
	keyFile, recipient, err := crypto.GenerateKeyFile()
	if err != nil {
		return "", "", err
	}
	backup, err := r.ensureBackup(ctx, tc, t, nil, keyFile, recipient)
	if apierrors.IsForbidden(err) {
		return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot create its key backup; " + onboardHint(t), nil
	}
	if err != nil {
		return "", "", err
	}
	if _, err := writeKey(ctx, tc, t, nil, backup); err != nil {
		if apierrors.IsForbidden(err) {
			return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot create its key Secret; " + onboardHint(t), nil
		}
		// AlreadyExists: a key Secret appeared since the read; the next reconcile restores the backup over it.
		return "", "", err
	}
	t.Status.PublicKey = recipient
	r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, sopsv1alpha1.ReasonKeyGenerated, sopsv1alpha1.ActionGenerateKey,
		"generated a post-quantum key in Secret %s", keyName)
	return sopsv1alpha1.ReasonKeyGenerated, "generated a post-quantum key", nil
}

// liveUsers counts the SopsSecrets of tenant t, read uncached. Field indexes do not exist on the
// uncached reader, so it lists all SopsSecrets and filters by spec.tenantRef.
func (r *SopsTenantReconciler) liveUsers(ctx context.Context, t *sopsv1alpha1.SopsTenant) (int, error) {
	var all sopsv1alpha1.SopsSecretList
	if err := r.APIReader.List(ctx, &all); err != nil {
		return 0, err
	}
	n := 0
	for _, s := range all.Items {
		if ref := s.Spec.TenantRef; ref.Namespace == t.Namespace && ref.Name == t.Name {
			n++
		}
	}
	return n, nil
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
			builder.WithPredicates(predicate.GenerationChangedPredicate{}))
	if r.Watches != nil {
		b = b.WatchesRawSource(source.Channel(r.Watches.Events(), &handler.EnqueueRequestForObject{}))
	}
	return b.Named("sopstenant").Complete(r)
}
