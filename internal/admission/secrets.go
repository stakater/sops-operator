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

// Package admission refuses direct changes to the Secrets the operator owns: output Secrets, written
// only from their SopsSecret, and tenant keys, changed only by a key rotation once a SopsSecret uses
// them (DESIGN.md D53).
package admission

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	sopsv1alpha1 "github.com/stakater/sops-operator/api/v1alpha1"
	"github.com/stakater/sops-operator/internal/controller"
	"github.com/stakater/sops-operator/internal/identity"
)

// Path is where the operator serves the webhook.
const Path = "/validate-v1-secret"

// systemUsers delete Secrets on behalf of Kubernetes: garbage collection of an output Secret whose
// SopsSecret was deleted, and deletion of a namespace.
var systemUsers = []string{
	"system:serviceaccount:kube-system:generic-garbage-collector",
	"system:serviceaccount:kube-system:namespace-controller",
	"system:kube-controller-manager",
}

// SecretValidator validates updates and deletions of Secrets enabled for the operator.
type SecretValidator struct {
	// Client reads SopsSecrets and SopsTenants, and counts a tenant's SopsSecrets through the
	// controllers' tenantRef index.
	Client  client.Reader
	Decoder admission.Decoder
}

// Handle implements admission.Handler. A request is judged by the Secret as it was before the change,
// so removing its label does not escape the check. The tenant follows from where the Secret is: an
// output Secret has its SopsSecret's name, a key Secret is <tenant>-sops-keys or -next in the tenant's
// namespace.
func (v *SecretValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	if req.Operation != admissionv1.Update && req.Operation != admissionv1.Delete {
		return admission.Allowed("")
	}
	var old corev1.Secret
	if err := v.Decoder.DecodeRaw(req.OldObject, &old); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	if old.Labels[sopsv1alpha1.LabelEnabled] != sopsv1alpha1.EnabledValue || slices.Contains(systemUsers, req.UserInfo.Username) {
		return admission.Allowed("")
	}
	if _, output := old.Annotations[sopsv1alpha1.AnnotationSopsSecret]; output {
		return v.output(ctx, req, &old)
	}
	return v.key(ctx, req, &old)
}

// output allows changes to an output Secret by its SopsSecret's tenant identity only. A Secret whose
// SopsSecret is gone, retained after its deletion, is the user's again.
func (v *SecretValidator) output(ctx context.Context, req admission.Request, old *corev1.Secret) admission.Response {
	var owner sopsv1alpha1.SopsSecret
	err := v.Client.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: old.Name}, &owner)
	switch {
	case apierrors.IsNotFound(err):
		return admission.Allowed("")
	case err != nil:
		return admission.Errored(http.StatusInternalServerError, err)
	}
	ref := owner.Spec.TenantRef
	if req.UserInfo.Username == identity.UserName(ref.Namespace, ref.Name) {
		return admission.Allowed("")
	}
	return admission.Denied(fmt.Sprintf("Secret %s/%s is written from SopsSecret %s; change the SopsSecret instead",
		old.Namespace, old.Name, owner.Name))
}

// key allows changes to a tenant's key Secret by its tenant identity, or by anyone while no SopsSecret
// uses the tenant: once one does, only a key rotation changes the key.
func (v *SecretValidator) key(ctx context.Context, req admission.Request, old *corev1.Secret) admission.Response {
	tenant := tenantOfKey(old.Name)
	if tenant == "" {
		return admission.Allowed("")
	}
	err := v.Client.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: tenant}, &sopsv1alpha1.SopsTenant{})
	switch {
	case apierrors.IsNotFound(err):
		return admission.Allowed("")
	case err != nil:
		return admission.Errored(http.StatusInternalServerError, err)
	}
	if req.UserInfo.Username == identity.UserName(old.Namespace, tenant) {
		return admission.Allowed("")
	}
	var users sopsv1alpha1.SopsSecretList
	if err := v.Client.List(ctx, &users, client.MatchingFields{
		controller.IndexTenantRef: controller.TenantRefKey(old.Namespace, tenant),
	}); err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	if len(users.Items) == 0 {
		return admission.Allowed("")
	}
	return admission.Denied(fmt.Sprintf("Secret %s/%s holds a key of SopsTenant %s/%s, which %d SopsSecrets use; "+
		"change the key with a key rotation (spec.startRotation: true)", old.Namespace, old.Name, old.Namespace, tenant,
		len(users.Items)))
}

// tenantOfKey returns the tenant whose key Secret, or next key Secret, is named name, or "".
func tenantOfKey(name string) string {
	for _, suffix := range []string{sopsv1alpha1.TenantNextKeySecretName(""), sopsv1alpha1.TenantKeySecretName("")} {
		if tenant, ok := strings.CutSuffix(name, suffix); ok && tenant != "" {
			return tenant
		}
	}
	return ""
}
