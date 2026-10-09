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
	"k8s.io/client-go/tools/record"
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
	Recorder       record.EventRecorder
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
		if _, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField]); err != nil {
			return sopsv1alpha1.ReasonKeyInvalid, err.Error(), nil
		}
		return sopsv1alpha1.ReasonKeyLoaded, "key loaded", nil
	case apierrors.IsForbidden(err):
		return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot read its key Secret; " +
			"the cluster admin must onboard this tenant", nil
	case !apierrors.IsNotFound(err):
		return "", "", err
	}

	if !t.ShouldGenerateKey() {
		return sopsv1alpha1.ReasonKeyMissing, fmt.Sprintf("key Secret %s/%s not found and generateKey is false", t.Namespace, t.Name), nil
	}
	keyFile, _, err := crypto.GenerateKeyFile(r.now())
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
		Data: map[string][]byte{crypto.KeyFileField: keyFile},
	}
	if err := tc.Create(ctx, secret); err != nil {
		if apierrors.IsForbidden(err) {
			return sopsv1alpha1.ReasonAccessDenied, "the tenant identity cannot create its key Secret; " +
				"the cluster admin must onboard this tenant", nil
		}
		// AlreadyExists: a key appeared since the read; the retry loads it.
		return "", "", err
	}
	r.Recorder.Eventf(t, corev1.EventTypeNormal, sopsv1alpha1.ReasonKeyGenerated,
		"generated a post-quantum key in Secret %s", t.Name)
	return sopsv1alpha1.ReasonKeyGenerated, "generated a post-quantum key", nil
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
