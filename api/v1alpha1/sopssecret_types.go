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
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Tenant name"
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Tenant namespace",xDescriptors={"urn:alm:descriptor:io.kubernetes:Namespace"}
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

// EncryptedValue is a binary age file in base64 (`age -R <recipients> | base64`).
// +kubebuilder:validation:MaxLength=1572864
// +kubebuilder:validation:XValidation:rule="self.startsWith('YWdlLWVuY3J5cHRpb24ub3JnL3Yx')",message="each value must be a binary age file in base64 (age ... | base64)"
type EncryptedValue string

// SopsSecretSpec is the encrypted definition of one Secret with the same name and namespace.
type SopsSecretSpec struct {
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Tenant"
	TenantRef TenantReference `json:"tenantRef"`
	// EncryptedData holds one encrypted value per key of the Secret: a binary age file encrypted for
	// the tenant's public key, in base64. Its plaintext is the line "<namespace>/<name>/<key>"
	// followed by the value.
	// +kubebuilder:validation:MinProperties=1
	// +kubebuilder:validation:MaxProperties=256
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Encrypted data",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:hidden"}
	EncryptedData map[string]EncryptedValue `json:"encryptedData"`
	// +kubebuilder:default=Delete
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Deletion policy",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:select:Delete","urn:alm:descriptor:com.tectonic.ui:select:Retain"}
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Secret metadata",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:advanced"}
	// +optional
	Template SecretTemplate `json:"template,omitempty"`
	// +kubebuilder:validation:Enum=Opaque;kubernetes.io/tls;kubernetes.io/dockerconfigjson;kubernetes.io/basic-auth;kubernetes.io/ssh-auth
	// +kubebuilder:default=Opaque
	// +operator-sdk:csv:customresourcedefinitions:type=spec,displayName="Secret type",xDescriptors={"urn:alm:descriptor:com.tectonic.ui:select:Opaque","urn:alm:descriptor:com.tectonic.ui:select:kubernetes.io/tls","urn:alm:descriptor:com.tectonic.ui:select:kubernetes.io/dockerconfigjson","urn:alm:descriptor:com.tectonic.ui:select:kubernetes.io/basic-auth","urn:alm:descriptor:com.tectonic.ui:select:kubernetes.io/ssh-auth"}
	// +optional
	Type corev1.SecretType `json:"type,omitempty"`
}

// SopsSecretStatus reports the state of the output Secret.
type SopsSecretStatus struct {
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Observed generation"
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Last sync"
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
	// SecretUID is the UID of the Secret this SopsSecret created.
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Secret UID"
	// +optional
	SecretUID types.UID `json:"secretUID,omitempty"`
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Conditions",xDescriptors={"urn:alm:descriptor:io.kubernetes.conditions"}
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
// +operator-sdk:csv:customresourcedefinitions:displayName="SOPS Secret",resources={{Secret,v1,""}}

// SopsSecret is an age-encrypted Secret.
type SopsSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec SopsSecretSpec `json:"spec"`
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
