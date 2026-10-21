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
	"sigs.k8s.io/controller-runtime/pkg/log"
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
	// rotation is written to status.rotation when setRotation is true, which happens only while the
	// tenant rotates. Other outcomes keep the recorded status, so neither a transient failure nor a
	// lagging tenant view loses the accepted generation; the tenant controller clears it.
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

	// Output Secrets carry the operator's label, so one named like a key Secret could pose as it.
	owner, err := r.keySecretTenant(ctx, s)
	if err != nil {
		return outcome{}, err
	}
	if owner != "" {
		return outcome{reason: sopsv1alpha1.ReasonConflict, message: fmt.Sprintf(
			"Secret %s/%s is a key Secret name of SopsTenant %s; a SopsSecret cannot write it",
			s.Namespace, s.Name, TenantRefKey(s.Namespace, owner))}, nil
	}

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
	next, err := r.rotationKey(ctx, tc, ref, rot, keys)
	if err != nil {
		return outcome{}, err
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
		if !migrated {
			offerEntry(ctx, s, rs, doc, keys, next)
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
		rotation: rs, setRotation: rs != nil}, nil
}

// keySecretTenant returns the name of the SopsTenant in the SopsSecret's namespace whose key Secret
// or next key Secret has the SopsSecret's name, or "" when there is none.
func (r *SopsSecretReconciler) keySecretTenant(ctx context.Context, s *sopsv1alpha1.SopsSecret) (string, error) {
	for _, suffix := range []string{sopsv1alpha1.NextKeySecretSuffix, sopsv1alpha1.KeySecretSuffix} {
		name, ok := strings.CutSuffix(s.Name, suffix)
		if !ok || name == "" {
			continue
		}
		err := r.Get(ctx, types.NamespacedName{Namespace: s.Namespace, Name: name}, &sopsv1alpha1.SopsTenant{})
		if err == nil {
			return name, nil
		}
		if !apierrors.IsNotFound(err) {
			return "", err
		}
	}
	return "", nil
}

// rotationKey returns the next key of the tenant rotation rot, or nil when there is no rotation. When
// the key Secret already holds the next key (completion replaced it and the tenant status does not
// know yet), the next key is the current primary key.
func (r *SopsSecretReconciler) rotationKey(ctx context.Context, tc client.Client, ref sopsv1alpha1.TenantReference,
	rot *sopsv1alpha1.TenantRotationStatus, current *crypto.KeySet) (*crypto.KeySet, error) {
	switch {
	case rot == nil:
		return nil, nil
	case current.Recipients[0] == rot.NextPublicKey:
		return &crypto.KeySet{Identities: current.Identities[:1], Recipients: current.Recipients[:1]}, nil
	}
	return r.nextKey(ctx, tc, ref, rot.NextPublicKey)
}

// nextKey returns the tenant's next key. It returns nil when the Secret does not exist, is not a
// valid key file or does not hold the published next key (the tenant reports why), and an error
// for any other read failure.
func (r *SopsSecretReconciler) nextKey(ctx context.Context, tc client.Client, ref sopsv1alpha1.TenantReference,
	published string) (*crypto.KeySet, error) {
	var key corev1.Secret
	name := sopsv1alpha1.TenantNextKeySecretName(ref.Name)
	if err := tc.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: name}, &key); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	keys, err := crypto.ParseKeyFile(key.Data[crypto.KeyFileField])
	if err != nil || keys.Recipients[0] != published {
		return nil, nil
	}
	return keys, nil
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

// offerEntry renews the next-key entry in rs when it was not made for the SopsSecret's generation.
// The entry is made only for the next key that was read; without one, no entry is offered.
func offerEntry(ctx context.Context, s *sopsv1alpha1.SopsSecret, rs *sopsv1alpha1.SecretRotationStatus, doc []byte,
	keys, next *crypto.KeySet) {
	if rs.NextRecipient != nil && rs.FromGeneration == s.Generation {
		return
	}
	rs.NextRecipient, rs.FromGeneration = nil, 0
	if next == nil {
		return
	}
	entry, err := crypto.WrapDataKey(doc, keys, next.Recipients[0])
	if err != nil {
		log.FromContext(ctx).Error(err, "wrap the data key for the next key", "sopsSecret", client.ObjectKeyFromObject(s))
		return
	}
	rs.NextRecipient = &sopsv1alpha1.SopsAgeRecipient{Recipient: entry.Recipient, Enc: entry.Enc}
	rs.FromGeneration = s.Generation
}

// rotationStatus returns the SopsSecret's rotation status for the tenant rotation rot. The
// generation stamped by the tenant controller when the rotation started is accepted with the
// current key alone; any later generation must use the next key (DESIGN.md §4.4).
func rotationStatus(s *sopsv1alpha1.SopsSecret, rot *sopsv1alpha1.TenantRotationStatus, migrated bool) *sopsv1alpha1.SecretRotationStatus {
	prev := s.Status.Rotation
	rs := &sopsv1alpha1.SecretRotationStatus{StartedAt: rot.StartedAt, Migrated: migrated}
	if prev != nil && prev.StartedAt.Equal(&rot.StartedAt) {
		rs.AcceptedGeneration, rs.NextRecipient, rs.FromGeneration = prev.AcceptedGeneration, prev.NextRecipient, prev.FromGeneration
	}
	if migrated {
		rs.MigratedGeneration = s.Generation
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
