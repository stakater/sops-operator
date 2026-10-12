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
	// AnnotationSopsSecret names the SopsSecret an output Secret was created from. It is an
	// annotation because object names can be longer than label values allow (63 characters).
	AnnotationSopsSecret = "sops.stakater.com/sopssecret"
)
