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
	"strings"
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
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/identity"
)

// SopsTenantReconciler loads or generates a tenant key and reports its state. It accesses the
// key Secret only as the tenant identity.
type SopsTenantReconciler struct {
	client.Client
	// APIReader reads SopsSecrets uncached for the completion decision; Client is used when nil.
	APIReader      client.Reader
	Identities     *identity.Factory
	Recorder       events.EventRecorder
	ResyncInterval time.Duration
	Now            func() time.Time
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
		return ctrl.Result{}, client.IgnoreNotFound(err)
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

// reconcileKey returns the Ready reason and message for the tenant key. Only a 404 on the key
// Secret, without a next key, leads to generation; the tenant identity cannot modify or delete an existing key.
func (r *SopsTenantReconciler) reconcileKey(ctx context.Context, t *sopsv1alpha1.SopsTenant) (string, string, error) {
	tc, err := r.Identities.ClientFor(t.Namespace, t.Name)
	if err != nil {
		return "", "", err
	}
	keyName := sopsv1alpha1.TenantKeySecretName(t.Name)
	var key corev1.Secret
	err = tc.Get(ctx, client.ObjectKey{Namespace: t.Namespace, Name: keyName}, &key)
	switch {
	case err == nil:
		keys, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
		if err != nil {
			return sopsv1alpha1.ReasonKeyInvalid, err.Error(), nil
		}
		// A public key that does not match would make developers encrypt for a key nobody holds.
		if pub, ok := key.Data[crypto.PublicKeyField]; ok && strings.TrimSpace(string(pub)) != keys.Recipients[0] {
			return sopsv1alpha1.ReasonKeyInvalid, fmt.Sprintf("%s does not match the primary key in %s",
				crypto.PublicKeyField, crypto.KeyFileField), nil
		}
		// status.publicKey records the key in use; a key file without that identity means the Secret
		// was replaced, for example by restoring an old backup (DESIGN.md §4.4, guards). Manual
		// rotation adds identities, so the record follows the primary identity while it is present. It does not
		// move while completing or during a rotation: completion and abandon rely on the recorded key.
		// The key may already be the next key: a completion that replaced it and then crashed before
		// writing the status; the rotation finishes it.
		completing := t.Status.Rotation != nil && keys.Recipients[0] == t.Status.Rotation.NextPublicKey
		if t.Status.PublicKey != "" && !slices.Contains(keys.Recipients, t.Status.PublicKey) && !completing {
			return sopsv1alpha1.ReasonKeyMismatch, fmt.Sprintf("the key in %s does not hold the key recorded in "+
				"status.publicKey (%s); restore the matching key", keyName, t.Status.PublicKey), nil
		}
		if !completing && t.Status.Rotation == nil {
			t.Status.PublicKey = keys.Recipients[0]
		}
		return sopsv1alpha1.ReasonKeyLoaded, "key loaded", nil
	case apierrors.IsForbidden(err):
		return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot read its key Secret; " + onboardHint(t), nil
	case !apierrors.IsNotFound(err):
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

	// No key Secret and no next key: whatever key appears next, generated or brought, is the new key.
	t.Status.PublicKey = ""

	if !t.ShouldGenerateKey() {
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("key Secret %s/%s not found and generateKey is false", t.Namespace, keyName), nil
	}
	keyFile, recipient, err := crypto.GenerateKeyFile(r.now())
	if err != nil {
		return "", "", err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      keyName,
			Namespace: t.Namespace,
			Labels:    map[string]string{sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{crypto.KeyFileField: keyFile, crypto.PublicKeyField: []byte(recipient)},
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
	return ctrl.NewControllerManagedBy(mgr).
		For(&sopsv1alpha1.SopsTenant{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&sopsv1alpha1.SopsSecret{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
				ref := o.(*sopsv1alpha1.SopsSecret).Spec.TenantRef
				return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}}}
			}),
			builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, rotationProgressChanged{}))).
		Named("sopstenant").
		Complete(r)
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
