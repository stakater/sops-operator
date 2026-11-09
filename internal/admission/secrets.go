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

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
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

// SecretValidator validates updates and deletions of Secrets carrying the tenant labels.
type SecretValidator struct {
	// Client counts a tenant's SopsSecrets through the controllers' tenantRef index.
	Client  client.Reader
	Decoder admission.Decoder
}

// Handle implements admission.Handler. A request is judged by the Secret as it was before the change,
// so removing its labels does not escape the check.
func (v *SecretValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	if req.Operation != admissionv1.Update && req.Operation != admissionv1.Delete {
		return admission.Allowed("")
	}
	var old corev1.Secret
	if err := v.Decoder.DecodeRaw(req.OldObject, &old); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	tenant, tenantNS := old.Labels[sopsv1alpha1.LabelTenant], old.Labels[sopsv1alpha1.LabelTenantNamespace]
	username := req.UserInfo.Username
	if tenant == "" || tenantNS == "" || username == identity.UserName(tenantNS, tenant) ||
		slices.Contains(systemUsers, username) {
		return admission.Allowed("")
	}
	if owner, ok := old.Annotations[sopsv1alpha1.AnnotationSopsSecret]; ok {
		return admission.Denied(fmt.Sprintf("Secret %s/%s is written from SopsSecret %s; change the SopsSecret instead",
			old.Namespace, old.Name, owner))
	}
	if old.Namespace != tenantNS || (old.Name != sopsv1alpha1.TenantKeySecretName(tenant) &&
		old.Name != sopsv1alpha1.TenantNextKeySecretName(tenant)) {
		return admission.Allowed("")
	}
	var users sopsv1alpha1.SopsSecretList
	if err := v.Client.List(ctx, &users, client.MatchingFields{
		controller.IndexTenantRef: controller.TenantRefKey(tenantNS, tenant),
	}); err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	if len(users.Items) == 0 {
		return admission.Allowed("")
	}
	return admission.Denied(fmt.Sprintf("Secret %s/%s holds a key of SopsTenant %s/%s, which %d SopsSecrets use; "+
		"change the key with a key rotation (spec.startRotation: true)", old.Namespace, old.Name, tenantNS, tenant,
		len(users.Items)))
}
