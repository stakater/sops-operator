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

package v1alpha1

// ConditionReady is the only condition type of SopsTenant and SopsSecret.
const ConditionReady = "Ready"

// SopsTenant Ready reasons.
const (
	ReasonKeyLoaded    = "KeyLoaded"
	ReasonKeyGenerated = "KeyGenerated"
	ReasonKeyMissing   = "KeyMissing"
	ReasonKeyInvalid   = "KeyInvalid"
	ReasonAccessDenied = "AccessDenied"
)

// Event actions of the tenant key.
const (
	ActionGenerateKey = "GenerateKey"
)

// SopsSecret Ready reasons. ReasonAccessDenied is shared with SopsTenant.
const (
	ReasonDecrypted      = "Decrypted"
	ReasonSuspended      = "Suspended"
	ReasonTenantNotFound = "TenantNotFound"
	ReasonTenantNotReady = "TenantNotReady"
	ReasonNotRecipient   = "NotRecipient"
	ReasonScopeMismatch  = "ScopeMismatch"
	ReasonDecryptFailed  = "DecryptFailed"
	ReasonConflict       = "Conflict"
	ReasonApplyFailed    = "ApplyFailed"
)

// Labels and annotations.
const (
	// AnnotationSuspend set to "true" on a SopsSecret pauses its reconciliation.
	AnnotationSuspend = "sops.stakater.com/suspend"
	// LabelManagedBy marks Secrets created by the operator.
	LabelManagedBy = "app.kubernetes.io/managed-by"
	// ManagedByValue is the value of LabelManagedBy.
	ManagedByValue = "sops-operator"
	// LabelComponent and LabelInstance mark a tenant's ServiceAccount: component
	// ComponentTenantIdentity, instance the tenant's name.
	LabelComponent          = "app.kubernetes.io/component"
	LabelInstance           = "app.kubernetes.io/instance"
	ComponentTenantIdentity = "tenant-identity"
	// LabelEnabled set to EnabledValue marks a Secret as the operator's: an output Secret it writes, or a
	// tenant key Secret. A tenant admin sets it on a key Secret they bring, for the operator to adopt it.
	// The tenant follows from where the Secret is: a key Secret is <tenant>-sops-keys-<index> in the
	// tenant's namespace, an output Secret has the name of its SopsSecret in the same namespace.
	LabelEnabled = "sops.stakater.com/enabled"
	EnabledValue = "true"
	// ReservedPrefix is the prefix of the operator's own labels and annotations; a SopsSecret's template
	// cannot set them.
	ReservedPrefix = "sops.stakater.com/"
	// FinalizerOutputSecret on a SopsSecret with deletionPolicy Delete lets the operator delete its output
	// Secret before the SopsSecret is gone.
	FinalizerOutputSecret = "sops.stakater.com/output-secret"
	// AnnotationSopsSecret names the SopsSecret an output Secret was created from. It is an
	// annotation because object names can be longer than label values allow (63 characters).
	AnnotationSopsSecret = "sops.stakater.com/sopssecret"
)
