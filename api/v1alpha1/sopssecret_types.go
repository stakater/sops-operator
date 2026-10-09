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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// TenantReference names a SopsTenant.
type TenantReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
}

// DeletionPolicy decides what happens to the output Secret when the SopsSecret is deleted.
// +kubebuilder:validation:Enum=Delete;Retain
type DeletionPolicy string

const (
	// DeletionPolicyDelete garbage-collects the output Secret with the SopsSecret.
	DeletionPolicyDelete DeletionPolicy = "Delete"
	// DeletionPolicyRetain keeps the output Secret.
	DeletionPolicyRetain DeletionPolicy = "Retain"
)

// SecretTemplate holds metadata for the output Secret.
type SecretTemplate struct {
	// +optional
	Metadata SecretTemplateMetadata `json:"metadata,omitempty"`
}

// SecretTemplateMetadata holds labels and annotations for the output Secret.
type SecretTemplateMetadata struct {
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// SopsSecretSpec is the encrypted definition of one Secret with the same name and namespace.
// +kubebuilder:validation:XValidation:rule="has(self.data) || has(self.stringData)",message="at least one of data or stringData is required"
// +kubebuilder:validation:XValidation:rule="!has(self.data) || !has(self.stringData) || self.data.all(k, !(k in self.stringData))",message="a key must not appear in both data and stringData"
type SopsSecretSpec struct {
	TenantRef TenantReference `json:"tenantRef"`
	// Scope is the encrypted "<namespace>/<name>" this document may be decrypted into.
	// +kubebuilder:validation:MinLength=1
	Scope string `json:"scope"`
	// +kubebuilder:default=Delete
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
	// +optional
	Template SecretTemplate `json:"template,omitempty"`
	// +kubebuilder:validation:Enum=Opaque;kubernetes.io/tls;kubernetes.io/dockerconfigjson;kubernetes.io/basic-auth;kubernetes.io/ssh-auth
	// +kubebuilder:default=Opaque
	// +optional
	Type corev1.SecretType `json:"type,omitempty"`
	// Data holds encrypted base64 values.
	// +kubebuilder:validation:MaxProperties=256
	// +optional
	Data map[string]string `json:"data,omitempty"`
	// StringData holds encrypted text values.
	// +kubebuilder:validation:MaxProperties=256
	// +optional
	StringData map[string]string `json:"stringData,omitempty"`
}

// SopsAgeRecipient is one age recipient entry of the SOPS metadata.
type SopsAgeRecipient struct {
	// +kubebuilder:validation:MinLength=1
	Recipient string `json:"recipient"`
	// +kubebuilder:validation:MinLength=1
	Enc string `json:"enc"`
}

// SopsMetadata is the metadata block written by `sops encrypt`.
type SopsMetadata struct {
	// +kubebuilder:validation:MinItems=1
	Age []SopsAgeRecipient `json:"age"`
	// +kubebuilder:validation:MinLength=1
	MAC string `json:"mac"`
	// +kubebuilder:validation:MinLength=1
	LastModified string `json:"lastmodified"`
	// +kubebuilder:validation:MinLength=1
	Version string `json:"version"`
	// +kubebuilder:validation:XValidation:rule="self == '^(data|stringData|scope)$'",message="encrypted_regex must be ^(data|stringData|scope)$"
	EncryptedRegex string `json:"encrypted_regex"`
	// +kubebuilder:validation:XValidation:rule="self",message="mac_only_encrypted must be true"
	MACOnlyEncrypted bool `json:"mac_only_encrypted"`
}

// SopsSecretStatus reports the state of the output Secret.
type SopsSecretStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
	// SecretUID is the UID of the Secret this SopsSecret created.
	// +optional
	SecretUID types.UID `json:"secretUID,omitempty"`
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Tenant",type=string,JSONPath=`.spec.tenantRef.name`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SopsSecret is a SOPS-encrypted Secret.
type SopsSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec SopsSecretSpec `json:"spec"`
	Sops SopsMetadata   `json:"sops"`
	// +optional
	Status SopsSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SopsSecretList contains a list of SopsSecret.
type SopsSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SopsSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SopsSecret{}, &SopsSecretList{})
}
