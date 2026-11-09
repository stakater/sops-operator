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
	// ReasonKeyMismatch: the key Secret does not hold the key recorded in status.publicKey and there is
	// no backup of the recorded key to restore it from.
	ReasonKeyMismatch = "KeyMismatch"
)

// ReasonKeyRestored is the reason of the Warning event recorded when the operator restores the key
// Secret from a key backup.
const ReasonKeyRestored = "KeyRestored"

// Event actions of the tenant key: generation and restore from a backup.
const (
	ActionGenerateKey = "GenerateKey"
	ActionRestoreKey  = "RestoreKey"
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
	// The tenant follows from where the Secret is: a key Secret is <tenant>-sops-keys in the tenant's
	// namespace, an output Secret has the name of its SopsSecret in the same namespace.
	LabelEnabled = "sops.stakater.com/enabled"
	EnabledValue = "true"
	// ReservedPrefix is the prefix of the operator's own labels and annotations; a SopsSecret's template
	// cannot set them.
	ReservedPrefix = "sops.stakater.com/"
	// AnnotationSopsSecret names the SopsSecret an output Secret was created from. It is an
	// annotation because object names can be longer than label values allow (63 characters).
	AnnotationSopsSecret = "sops.stakater.com/sopssecret"
	// LabelKeyBackup set to "true" marks an immutable backup of a tenant key,
	// <tenant>-sops-keys-<YYYYMMDD-HHMMSS>.
	LabelKeyBackup = "sops.stakater.com/key-backup"
	// AnnotationPublicKey on a key backup holds the public key of the key it holds.
	AnnotationPublicKey = "sops.stakater.com/public-key"
)
