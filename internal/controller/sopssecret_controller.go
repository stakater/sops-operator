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
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/crypto"
	"github.com/stakater/sops-operator/internal/document"
	"github.com/stakater/sops-operator/internal/identity"
	"github.com/stakater/sops-operator/internal/secretwriter"
)

// trackingPrefixes are GitOps tracking label/annotation prefixes never copied to output Secrets.
var trackingPrefixes = []string{"argocd.argoproj.io/", "kustomize.toolkit.fluxcd.io/", "helm.toolkit.fluxcd.io/"}

// SopsSecretReconciler decrypts SopsSecrets into Secrets, acting as the referenced tenant identity.
type SopsSecretReconciler struct {
	client.Client
	// APIReader reads SopsSecrets uncached, so status.secretUID written by the previous reconcile
	// is always seen; a stale cache would otherwise report Conflict for the operator's own Secret.
	APIReader      client.Reader
	Identities     *identity.Factory
	ResyncInterval time.Duration
	Now            func() time.Time
}

type outcome struct {
	reason  string
	message string
	uid     types.UID
	// rotation is written to status.rotation when setRotation is true; other outcomes keep the
	// recorded rotation status, so a transient failure does not lose the accepted generation.
	rotation    *sopsv1alpha1.SecretRotationStatus
	setRotation bool
}

func (r *SopsSecretReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Reconcile implements reconcile.Reconciler.
func (r *SopsSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reader := client.Reader(r.Client)
	if r.APIReader != nil {
		reader = r.APIReader
	}
	var s sopsv1alpha1.SopsSecret
	if err := reader.Get(ctx, req.NamespacedName, &s); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !s.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	o := outcome{reason: sopsv1alpha1.ReasonSuspended, message: "reconciliation is suspended"}
	if s.Annotations[sopsv1alpha1.AnnotationSuspend] != "true" {
		var err error
		if o, err = r.sync(ctx, &s); err != nil {
			return ctrl.Result{}, err
		}
	}
	if err := r.updateStatus(ctx, &s, o); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: r.ResyncInterval}, nil
}

// sync runs the checks of DESIGN.md §6.2 in order. Policy failures are returned as outcomes;
// only transient errors are returned as errors.
func (r *SopsSecretReconciler) sync(ctx context.Context, s *sopsv1alpha1.SopsSecret) (outcome, error) {
	ref := s.Spec.TenantRef
	tenantName := TenantRefKey(ref.Namespace, ref.Name)

	var tenant sopsv1alpha1.SopsTenant
	if err := r.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, &tenant); err != nil {
		if apierrors.IsNotFound(err) {
			return outcome{reason: sopsv1alpha1.ReasonTenantNotFound, message: fmt.Sprintf("SopsTenant %s not found", tenantName)}, nil
		}
		return outcome{}, err
	}
	if !meta.IsStatusConditionTrue(tenant.Status.Conditions, sopsv1alpha1.ConditionReady) {
		return outcome{reason: sopsv1alpha1.ReasonTenantNotReady, message: fmt.Sprintf("SopsTenant %s is not ready", tenantName)}, nil
	}

	allowed, err := identity.CanWriteSecrets(ctx, r.Client, ref.Namespace, ref.Name, s.Namespace)
	if err != nil {
		return outcome{}, err
	}
	if !allowed {
		return outcome{reason: sopsv1alpha1.ReasonAccessDenied,
			message: fmt.Sprintf("tenant %s is not granted Secret write in namespace %s", tenantName, s.Namespace)}, nil
	}

	tc, err := r.Identities.ClientFor(ref.Namespace, ref.Name)
	if err != nil {
		return outcome{}, err
	}
	var key corev1.Secret
	if err := tc.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: sopsv1alpha1.TenantKeySecretName(ref.Name)}, &key); err != nil {
		if apierrors.IsNotFound(err) || apierrors.IsForbidden(err) {
			return outcome{reason: sopsv1alpha1.ReasonTenantNotReady, message: fmt.Sprintf("key of tenant %s is not readable", tenantName)}, nil
		}
		return outcome{}, err
	}
	keys, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
	if err != nil {
		return outcome{reason: sopsv1alpha1.ReasonTenantNotReady, message: fmt.Sprintf("key of tenant %s is invalid", tenantName)}, nil
	}

	doc, err := document.Canonical(s)
	if err != nil {
		return outcome{reason: sopsv1alpha1.ReasonDecryptFailed, message: err.Error()}, nil
	}
	want := document.ScopeFor(s.Namespace, s.Name)
	rot := tenant.Status.Rotation
	var next *crypto.KeySet
	if rot != nil {
		next = r.nextKey(ctx, tc, ref)
	}
	plain, migrated, err := decryptRotating(doc, keys, next, want)
	switch {
	case errors.Is(err, crypto.ErrScopeMismatch):
		return outcome{reason: sopsv1alpha1.ReasonScopeMismatch, message: err.Error()}, nil
	case errors.Is(err, crypto.ErrNotRecipient):
		return outcome{reason: sopsv1alpha1.ReasonNotRecipient,
			message: fmt.Sprintf("the document is not encrypted for the key of tenant %s", tenantName)}, nil
	case err != nil:
		return outcome{reason: sopsv1alpha1.ReasonDecryptFailed, message: err.Error()}, nil
	}
	var rs *sopsv1alpha1.SecretRotationStatus
	if rot != nil {
		rs = rotationStatus(s, rot, migrated)
		if !migrated && (rs.NextRecipient == nil || rs.FromGeneration != s.Generation) {
			if entry, err := crypto.WrapDataKey(doc, keys, rot.NextPublicKey); err == nil {
				rs.NextRecipient = &sopsv1alpha1.SopsAgeRecipient{Recipient: entry.Recipient, Enc: entry.Enc}
				rs.FromGeneration = s.Generation
			}
		}
		if !migrated && rs.AcceptedGeneration != s.Generation {
			return outcome{reason: sopsv1alpha1.ReasonNextKeyRequired, rotation: rs, setRotation: true,
				message: fmt.Sprintf("tenant %s is rotating keys: add the next key %s to .sops.yaml and encrypt "+
					"this file again, or run scripts/rotate.sh", tenantName, rot.NextPublicKey)}, nil
		}
	}
	payload, err := document.ParsePlain(plain)
	if err != nil {
		return outcome{reason: sopsv1alpha1.ReasonDecryptFailed, message: err.Error()}, nil
	}
	if payload.Scope != want {
		return outcome{reason: sopsv1alpha1.ReasonScopeMismatch,
			message: fmt.Sprintf("the document is scoped to a different namespace or name than %q", want)}, nil
	}

	uid, err := secretwriter.Write(ctx, tc, desiredSecret(s, payload), s.Status.SecretUID)
	switch {
	case errors.Is(err, secretwriter.ErrConflict):
		return outcome{reason: sopsv1alpha1.ReasonConflict,
			message: fmt.Sprintf("Secret %s/%s exists and is not managed by this SopsSecret", s.Namespace, s.Name)}, nil
	case apierrors.IsForbidden(err):
		return outcome{reason: sopsv1alpha1.ReasonAccessDenied,
			message: fmt.Sprintf("tenant %s is not granted Secret write in namespace %s", tenantName, s.Namespace)}, nil
	case apierrors.IsInvalid(err), apierrors.IsBadRequest(err), apierrors.IsRequestEntityTooLargeError(err):
		return outcome{reason: sopsv1alpha1.ReasonApplyFailed, message: err.Error()}, nil
	case err != nil:
		return outcome{}, err
	}
	return outcome{reason: sopsv1alpha1.ReasonDecrypted, message: "Secret is up to date", uid: uid,
		rotation: rs, setRotation: true}, nil
}

// nextKey returns the tenant's next key, or nil when it cannot be read; the tenant reports why.
func (r *SopsSecretReconciler) nextKey(ctx context.Context, tc client.Client, ref sopsv1alpha1.TenantReference) *crypto.KeySet {
	var key corev1.Secret
	name := sopsv1alpha1.TenantNextKeySecretName(ref.Name)
	if err := tc.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: name}, &key); err != nil {
		return nil
	}
	keys, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
	if err != nil {
		return nil
	}
	return keys
}

// decryptRotating decrypts with the next key first, then with the current key. migrated
// reports that the next key decrypted the document.
func decryptRotating(doc []byte, current, next *crypto.KeySet, want string) (plain []byte, migrated bool, err error) {
	if next != nil {
		plain, err = crypto.Decrypt(doc, next, want)
		if err == nil {
			return plain, true, nil
		}
		if !errors.Is(err, crypto.ErrNotRecipient) {
			return nil, false, err
		}
	}
	plain, err = crypto.Decrypt(doc, current, want)
	return plain, false, err
}

// rotationStatus returns the SopsSecret's rotation status for the tenant rotation rot. The
// generation decrypted before the rotation started is accepted with the current key alone; any
// later generation must use the next key (DESIGN.md §4.4).
func rotationStatus(s *sopsv1alpha1.SopsSecret, rot *sopsv1alpha1.TenantRotationStatus, migrated bool) *sopsv1alpha1.SecretRotationStatus {
	prev := s.Status.Rotation
	rs := &sopsv1alpha1.SecretRotationStatus{StartedAt: rot.StartedAt, Migrated: migrated}
	if prev != nil && prev.StartedAt.Equal(&rot.StartedAt) {
		rs.AcceptedGeneration, rs.NextRecipient, rs.FromGeneration = prev.AcceptedGeneration, prev.NextRecipient, prev.FromGeneration
	} else if healthy(s) {
		rs.AcceptedGeneration = s.Generation
	}
	if migrated {
		rs.NextRecipient, rs.FromGeneration = nil, 0
	}
	return rs
}

func desiredSecret(s *sopsv1alpha1.SopsSecret, p *document.Payload) *corev1.Secret {
	labels := withoutTracking(s.Spec.Template.Metadata.Labels)
	labels[sopsv1alpha1.LabelManagedBy] = sopsv1alpha1.ManagedByValue
	annotations := withoutTracking(s.Spec.Template.Metadata.Annotations)
	annotations[sopsv1alpha1.AnnotationSopsSecret] = s.Name
	secretType := s.Spec.Type
	if secretType == "" {
		secretType = corev1.SecretTypeOpaque
	}
	out := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        s.Name,
			Namespace:   s.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Type: secretType,
		Data: p.Data,
	}
	if s.Spec.DeletionPolicy != sopsv1alpha1.DeletionPolicyRetain {
		out.OwnerReferences = []metav1.OwnerReference{{
			APIVersion:         sopsv1alpha1.GroupVersion.String(),
			Kind:               "SopsSecret",
			Name:               s.Name,
			UID:                s.UID,
			Controller:         ptr.To(true),
			BlockOwnerDeletion: ptr.To(false),
		}}
	}
	return out
}

func withoutTracking(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		tracked := false
		for _, p := range trackingPrefixes {
			if strings.HasPrefix(k, p) {
				tracked = true
				break
			}
		}
		if !tracked {
			out[k] = v
		}
	}
	return out
}

// updateStatus writes the outcome with a merge patch without optimistic locking, so a stale
// resourceVersion cannot lose status.secretUID: without it the operator could no longer update
// the Secret it created (D28).
func (r *SopsSecretReconciler) updateStatus(ctx context.Context, s *sopsv1alpha1.SopsSecret, o outcome) error {
	base := s.DeepCopy()
	status := metav1.ConditionFalse
	switch o.reason {
	case sopsv1alpha1.ReasonDecrypted:
		status = metav1.ConditionTrue
		now := metav1.NewTime(r.now())
		s.Status.LastSyncTime = &now
		s.Status.SecretUID = o.uid
	case sopsv1alpha1.ReasonSuspended:
		status = metav1.ConditionUnknown
	}
	meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{
		Type:               sopsv1alpha1.ConditionReady,
		Status:             status,
		Reason:             o.reason,
		Message:            o.message,
		ObservedGeneration: s.Generation,
	})
	if o.setRotation {
		s.Status.Rotation = o.rotation
	}
	s.Status.ObservedGeneration = s.Generation
	return r.Status().Patch(ctx, s, client.MergeFrom(base))
}

// SetupWithManager registers the controller. Status updates do not retrigger reconciliation;
// tenant changes reconcile every SopsSecret that references the tenant.
func (r *SopsSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sopsv1alpha1.SopsSecret{}, builder.WithPredicates(
			predicate.Or(predicate.GenerationChangedPredicate{}, predicate.AnnotationChangedPredicate{}))).
		Watches(&sopsv1alpha1.SopsTenant{}, handler.EnqueueRequestsFromMapFunc(r.sopsSecretsOfTenant)).
		Named("sopssecret").
		Complete(r)
}

func (r *SopsSecretReconciler) sopsSecretsOfTenant(ctx context.Context, o client.Object) []reconcile.Request {
	var list sopsv1alpha1.SopsSecretList
	if err := r.List(ctx, &list, client.MatchingFields{IndexTenantRef: TenantRefKey(o.GetNamespace(), o.GetName())}); err != nil {
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(list.Items))
	for _, s := range list.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&s)})
	}
	return reqs
}
