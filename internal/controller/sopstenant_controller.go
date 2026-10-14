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
	"strings"
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
	if err := r.ensureServiceAccount(ctx, tenant.Namespace); err != nil {
		return ctrl.Result{}, err
	}
	reason, message, err := r.reconcileKey(ctx, &tenant)
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
	tenant.Status.UsedBy = int32(len(users.Items))
	if err := r.Status().Update(ctx, &tenant); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: r.ResyncInterval}, nil
}

// ensureServiceAccount creates the tenant identity if it does not exist. It grants nothing: only
// the cluster admin's RoleBindings give it access. An existing ServiceAccount is never changed.
func (r *SopsTenantReconciler) ensureServiceAccount(ctx context.Context, namespace string) error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      identity.ServiceAccountName,
			Namespace: namespace,
			Labels:    map[string]string{sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue},
		},
		AutomountServiceAccountToken: ptr.To(false),
	}
	if err := r.Create(ctx, sa); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create ServiceAccount %s/%s: %w", namespace, identity.ServiceAccountName, err)
	}
	return nil
}

// reconcileKey returns the Ready reason and message for the tenant key. Only a 404 on the key
// Secret leads to generation; the tenant identity cannot modify or delete an existing key.
func (r *SopsTenantReconciler) reconcileKey(ctx context.Context, t *sopsv1alpha1.SopsTenant) (string, string, error) {
	tc, err := r.Identities.ClientFor(t.Namespace)
	if err != nil {
		return "", "", err
	}
	var key corev1.Secret
	err = tc.Get(ctx, client.ObjectKeyFromObject(t), &key)
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
		return sopsv1alpha1.ReasonKeyLoaded, "key loaded", nil
	case apierrors.IsForbidden(err):
		return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot read its key Secret; " + onboardHint(t.Namespace), nil
	case !apierrors.IsNotFound(err):
		return "", "", err
	}

	if !t.ShouldGenerateKey() {
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("key Secret %s/%s not found and generateKey is false", t.Namespace, t.Name), nil
	}
	keyFile, recipient, err := crypto.GenerateKeyFile(r.now())
	if err != nil {
		return "", "", err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      t.Name,
			Namespace: t.Namespace,
			Labels:    map[string]string{sopsv1alpha1.LabelManagedBy: sopsv1alpha1.ManagedByValue},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{crypto.KeyFileField: keyFile, crypto.PublicKeyField: []byte(recipient)},
	}
	if err := tc.Create(ctx, secret); err != nil {
		if apierrors.IsForbidden(err) {
			return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot create its key Secret; " +
				onboardHint(t.Namespace), nil
		}
		// AlreadyExists: a key appeared since the read; the retry loads it.
		return "", "", err
	}
	r.Recorder.Eventf(t, nil, corev1.EventTypeNormal, sopsv1alpha1.ReasonKeyGenerated, sopsv1alpha1.ActionGenerateKey,
		"generated a post-quantum key in Secret %s", t.Name)
	return sopsv1alpha1.ReasonKeyGenerated, "generated a post-quantum key", nil
}

// onboardHint names the RoleBinding the cluster admin creates to onboard a tenant.
func onboardHint(namespace string) string {
	return fmt.Sprintf("the cluster admin must bind ClusterRole sops-key-owner to ServiceAccount %s/%s in %s",
		namespace, identity.ServiceAccountName, namespace)
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
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("sopstenant").
		Complete(r)
}
