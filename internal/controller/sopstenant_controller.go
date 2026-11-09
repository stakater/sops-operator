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
	"sync"
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
	// APIReader reads SopsSecrets uncached for the completion decision; Client is used when nil.
	APIReader  client.Reader
	Identities *identity.Factory
	Recorder   events.EventRecorder
	// KeyWatches, when set, watches the tenant's key Secrets, so a changed or deleted key is noticed, and
	// its previous key saved, at once rather than at the next resync.
	KeyWatches     *secretwatch.Watches
	ResyncInterval time.Duration
	Now            func() time.Time

	// lastKeys holds, per tenant, the key file last loaded, so a key changed or deleted outside a
	// rotation can be saved as a backup. It lives in memory only.
	lastKeys sync.Map
}

func (r *SopsTenantReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Reconcile implements reconcile.Reconciler.
func (r *SopsTenantReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var tenant sopsv1alpha1.SopsTenant
	if err := r.Get(ctx, req.NamespacedName, &tenant); err != nil {
		if apierrors.IsNotFound(err) && r.KeyWatches != nil {
			r.KeyWatches.Release(req.NamespacedName)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	reason, message, err := r.ensureServiceAccount(ctx, &tenant)
	if err == nil && reason == "" {
		reason, message, err = r.reconcileKey(ctx, &tenant)
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	r.watchKeys(ctx, &tenant, reason)
	var users sopsv1alpha1.SopsSecretList
	if err := r.List(ctx, &users, client.MatchingFields{IndexTenantRef: TenantRefKey(tenant.Namespace, tenant.Name)}); err != nil {
		return ctrl.Result{}, err
	}
	if reason == sopsv1alpha1.ReasonKeyLoaded || reason == sopsv1alpha1.ReasonKeyGenerated {
		tc, err := r.Identities.ClientFor(tenant.Namespace, tenant.Name)
		if err != nil {
			return ctrl.Result{}, err
		}
		if err := r.reconcileRotation(ctx, &tenant, tc, users.Items); err != nil {
			return ctrl.Result{}, err
		}
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
	return ctrl.Result{RequeueAfter: r.ResyncInterval}, nil
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

// adoptKey checks that the key Secret key belongs to tenant t. A key Secret the operator generated
// before key Secrets carried the tenant labels is labelled; any other unlabelled Secret is refused with
// KeyMissing naming the labels a tenant admin adds to adopt it.
func adoptKey(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant, key *corev1.Secret) (string, string, error) {
	if adopted(key, t) {
		return "", "", nil
	}
	if !createdByOperator(key) {
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("Secret %s/%s is not adopted as the key of this tenant; "+
			"to use it, add the labels %s=%s and %s=%s", key.Namespace, key.Name,
			sopsv1alpha1.LabelTenant, t.Name, sopsv1alpha1.LabelTenantNamespace, t.Namespace), nil
	}
	if key.Labels == nil {
		key.Labels = map[string]string{}
	}
	key.Labels[sopsv1alpha1.LabelTenant] = t.Name
	key.Labels[sopsv1alpha1.LabelTenantNamespace] = t.Namespace
	if err := tc.Update(ctx, key); err != nil {
		return "", "", fmt.Errorf("label key Secret %s/%s: %w", key.Namespace, key.Name, err)
	}
	return "", "", nil
}

// reconcileKey returns the Ready reason and message for the tenant key. Only a 404 on the key
// Secret, without a next key, leads to generation; an existing key is changed only by the completion
// of a rotation (DESIGN.md §4.4).
func (r *SopsTenantReconciler) reconcileKey(ctx context.Context, t *sopsv1alpha1.SopsTenant) (string, string, error) {
	tc, err := r.Identities.ClientFor(t.Namespace, t.Name)
	if err != nil {
		return "", "", err
	}
	var key corev1.Secret
	err = tc.Get(ctx, client.ObjectKey{Namespace: t.Namespace, Name: sopsv1alpha1.TenantKeySecretName(t.Name)}, &key)
	switch {
	case err == nil:
		return r.loadKey(ctx, tc, t, &key)
	case apierrors.IsForbidden(err):
		return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot read its key Secret; " + onboardHint(t), nil
	case !apierrors.IsNotFound(err):
		return "", "", err
	}
	return r.missingKey(ctx, tc, t)
}

// loadKey loads the existing key Secret key. A key whose content changed outside a rotation is saved
// as a backup first (DESIGN.md §4.2).
func (r *SopsTenantReconciler) loadKey(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant,
	key *corev1.Secret) (string, string, error) {
	backup, err := r.backUpChanged(ctx, tc, t, key.Data[crypto.KeyFileField])
	if err != nil {
		return "", "", err
	}
	if reason, message, err := adoptKey(ctx, tc, t, key); reason != "" || err != nil {
		return reason, message, err
	}
	keys, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
	if err != nil {
		return sopsv1alpha1.ReasonKeyInvalid, err.Error() + restoreHint(backup), nil
	}
	// status.publicKey records the key in use; a key file without that identity means the Secret was
	// replaced (DESIGN.md §4.4, guards). It does not move during a rotation: completion and abandon rely
	// on the recorded key. The key may already be the next key: a completion that replaced it and then
	// crashed before writing the status; the rotation finishes it.
	completing := t.Status.Rotation != nil && keys.Recipients[0] == t.Status.Rotation.NextPublicKey
	if t.Status.PublicKey != "" && !slices.Contains(keys.Recipients, t.Status.PublicKey) && !completing {
		return sopsv1alpha1.ReasonKeyMismatch, fmt.Sprintf("the key in %s does not hold the key recorded in "+
			"status.publicKey (%s)%s", key.Name, t.Status.PublicKey, restoreHint(backup)), nil
	}
	if !completing && t.Status.Rotation == nil {
		t.Status.PublicKey = keys.Recipients[0]
	}
	r.remember(t, key.Data[crypto.KeyFileField])
	return sopsv1alpha1.ReasonKeyLoaded, "key loaded", nil
}

// restoreHint tells where the previous key was saved.
func restoreHint(backup string) string {
	if backup == "" {
		return "; restore the matching key"
	}
	return "; the previous key is saved in Secret " + backup
}

// missingKey handles a missing key Secret. A key is generated only for a tenant that never had one:
// once a key was recorded, a deleted key is reported, with the backup of it when the operator saved one.
func (r *SopsTenantReconciler) missingKey(ctx context.Context, tc client.Client, t *sopsv1alpha1.SopsTenant) (string, string, error) {
	keyName := sopsv1alpha1.TenantKeySecretName(t.Name)
	backup, err := r.backUpChanged(ctx, tc, t, nil)
	if err != nil {
		return "", "", err
	}
	var next corev1.Secret
	nextName := sopsv1alpha1.TenantNextKeySecretName(t.Name)
	if err := tc.Get(ctx, client.ObjectKey{Namespace: t.Namespace, Name: nextName}, &next); err == nil {
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("key Secret %s/%s not found while %s exists; restore "+
			"the key instead of generating one", t.Namespace, keyName, nextName), nil
	} else if !apierrors.IsNotFound(err) {
		return "", "", err
	}
	if t.Status.PublicKey != "" {
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("key Secret %s/%s with key %s was deleted%s",
			t.Namespace, keyName, t.Status.PublicKey, restoreHint(backup)), nil
	}
	if !t.ShouldGenerateKey() {
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("key Secret %s/%s not found and generateKey is false", t.Namespace, keyName), nil
	}
	keyFile, recipient, err := crypto.GenerateKeyFile()
	if err != nil {
		return "", "", err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: keyName, Namespace: t.Namespace, Labels: keyLabels(t)},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{crypto.KeyFileField: keyFile},
	}
	if err := tc.Create(ctx, secret); err != nil {
		if apierrors.IsForbidden(err) {
			return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot create its key Secret; " +
				onboardHint(t), nil
		}
		// AlreadyExists: a key appeared since the read; the retry loads it.
		return "", "", err
	}
	t.Status.PublicKey = recipient
	r.remember(t, keyFile)
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
// watchKeys holds the watch of the tenant's key Secrets while the tenant identity may read them.
func (r *SopsTenantReconciler) watchKeys(ctx context.Context, t *sopsv1alpha1.SopsTenant, reason string) {
	if r.KeyWatches == nil {
		return
	}
	tenant := client.ObjectKeyFromObject(t)
	if reason == sopsv1alpha1.ReasonAccessDenied {
		r.KeyWatches.Release(tenant)
		return
	}
	if err := r.KeyWatches.Watch(ctx, tenant, tenant); err != nil {
		// The resync still notices a changed key; the next reconcile tries the watch again.
		log.FromContext(ctx).Error(err, "watch key Secrets", "tenant", tenant)
	}
}

func (r *SopsTenantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	b := ctrl.NewControllerManagedBy(mgr).
		For(&sopsv1alpha1.SopsTenant{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&sopsv1alpha1.SopsSecret{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
				ref := o.(*sopsv1alpha1.SopsSecret).Spec.TenantRef
				return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}}}
			}),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, rotationProgressChanged{})))
	if r.KeyWatches != nil {
		b = b.WatchesRawSource(source.Channel(r.KeyWatches.Events(), &handler.EnqueueRequestForObject{}))
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
