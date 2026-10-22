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

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SopsTenantSpec defines a tenant key. The key is the Secret with the tenant's name in the
// tenant's namespace.
type SopsTenantSpec struct {
	// GenerateKey generates a post-quantum age key when the key Secret does not exist.
	// +kubebuilder:default=true
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Generate key",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:booleanSwitch"}
	// +optional
	GenerateKey *bool `json:"generateKey,omitempty"`
	// StartRotation set to true asks for a new tenant key: once every SopsSecret of the tenant is
	// healthy, the operator creates the next key and both keys are accepted. Set it to false, or
	// remove it, to complete the rotation: the next key replaces the current one once every
	// SopsSecret was decrypted with it (DESIGN.md §4.4).
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Start rotation",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:booleanSwitch"}
	// +optional
	StartRotation bool `json:"startRotation,omitempty"`
}

// SopsTenantStatus reports the state of the tenant key.
type SopsTenantStatus struct {
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Observed generation"
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// ServiceAccountName is the tenant identity the operator acts as: the ServiceAccount the cluster
	// admin binds to grant this tenant access.
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="ServiceAccount",xDescriptors={"urn:alm:descriptor:io.kubernetes:ServiceAccount"}
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// KeySecretName is the Secret in the tenant namespace that holds the tenant key and its public key.
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Key Secret",xDescriptors={"urn:alm:descriptor:io.kubernetes:Secret"}
	// +optional
	KeySecretName string `json:"keySecretName,omitempty"`
	// PublicKey is the public key of the current key, for .sops.yaml.
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Public key"
	// +optional
	PublicKey string `json:"publicKey,omitempty"`
	// Rotation is the key rotation in progress.
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Rotation"
	// +optional
	Rotation *TenantRotationStatus `json:"rotation,omitempty"`
	// LastRotation is the last completed key rotation.
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Last rotation"
	// +optional
	LastRotation *LastRotation `json:"lastRotation,omitempty"`
	// UsedBy is the number of SopsSecrets referencing this tenant.
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Used by"
	// +optional
	UsedBy int32 `json:"usedBy,omitempty"`
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Conditions",xDescriptors={"urn:alm:descriptor:io.kubernetes.conditions"}
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// TenantRotationStatus reports a key rotation in progress.
type TenantRotationStatus struct {
	// Phase is InProgress, then Completing.
	// +kubebuilder:validation:Enum=InProgress;Completing
	Phase string `json:"phase"`
	// StartedAt is when the next key was created.
	StartedAt metav1.Time `json:"startedAt"`
	// NextKeySecretName is the Secret holding the next key, <tenant>-sops-keys-next.
	NextKeySecretName string `json:"nextKeySecretName"`
	// NextPublicKey is the public key of the next key, for .sops.yaml.
	NextPublicKey string `json:"nextPublicKey"`
	// Migrated is the number of SopsSecrets decrypted with the next key.
	// +optional
	Migrated int32 `json:"migrated,omitempty"`
	// Pending is the number of SopsSecrets not yet decrypted with the next key.
	// +optional
	Pending int32 `json:"pending,omitempty"`
	// PendingSecrets names up to 50 pending SopsSecrets as <namespace>/<name>, sorted.
	// +kubebuilder:validation:MaxItems=50
	// +optional
	PendingSecrets []string `json:"pendingSecrets,omitempty"`
}

// LastRotation records the last completed key rotation.
type LastRotation struct {
	StartedAt   metav1.Time `json:"startedAt"`
	CompletedAt metav1.Time `json:"completedAt"`
	// PreviousPublicKey is the public key of the key the rotation removed. The CLI removes its
	// entries from files; it can decrypt nothing any more.
	PreviousPublicKey string `json:"previousPublicKey"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:validation:XValidation:rule="size(self.metadata.name) <= 63",message="the name must be at most 63 characters; it is a label value on the tenant's ServiceAccount"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Used By",type=integer,JSONPath=`.status.usedBy`
// +kubebuilder:printcolumn:name="Last Rotated",type=date,JSONPath=`.status.lastRotation.completedAt`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +operator-sdk:csv:customresourcedefinitions:displayName="SOPS Tenant",resources={{Secret,v1,""}}

// SopsTenant is a tenant key used to decrypt SopsSecrets.
type SopsTenant struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec SopsTenantSpec `json:"spec,omitempty"`
	// +optional
	Status SopsTenantStatus `json:"status,omitempty"`
}

// ServiceAccountSuffix is appended to a tenant's name to form its ServiceAccount name.
const ServiceAccountSuffix = "-sops-tenant"

// TenantServiceAccountName returns the name of the ServiceAccount of the tenant named tenant.
func TenantServiceAccountName(tenant string) string {
	return tenant + ServiceAccountSuffix
}

// KeySecretSuffix is appended to a tenant's name to form the name of its key Secret.
const KeySecretSuffix = "-sops-keys"

// TenantKeySecretName returns the name of the key Secret of the tenant named tenant.
func TenantKeySecretName(tenant string) string {
	return tenant + KeySecretSuffix
}

// NextKeySecretSuffix is appended to a tenant's name to form the name of its next key Secret,
// which exists only during a key rotation.
const NextKeySecretSuffix = "-sops-keys-next"

// TenantNextKeySecretName returns the name of the next key Secret of the tenant named tenant.
func TenantNextKeySecretName(tenant string) string {
	return tenant + NextKeySecretSuffix
}

// ShouldGenerateKey reports whether a missing key Secret should be generated.
func (t *SopsTenant) ShouldGenerateKey() bool {
	return t.Spec.GenerateKey == nil || *t.Spec.GenerateKey
}

// +kubebuilder:object:root=true

// SopsTenantList contains a list of SopsTenant.
type SopsTenantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SopsTenant `json:"items"`
}
