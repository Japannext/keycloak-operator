/*
Copyright 2024 Japannext.

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

package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KeycloakClientRoleMapping is the Schema for the keycloakclientrolemappings API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="REALM",type="string",JSONPath=".spec.realm"
// +kubebuilder:printcolumn:name="CLIENT",type="string",JSONPath=".spec.client"
// +kubebuilder:printcolumn:name="ROLE",type="string",JSONPath=".spec.role"
// +kubebuilder:printcolumn:name="TYPE",type="string",JSONPath=".spec.subject.kind"
// +kubebuilder:printcolumn:name="SUBJECT",type="string",JSONPath=".spec.subject.name"
// +kubebuilder:printcolumn:name="STATUS",type="string",JSONPath=".status.api.phase",description="The status of the resource"
// +kubebuilder:printcolumn:name="LAST CHANGED",priority=1,type="date",JSONPath=".status.api.lastTransitionTime",description="The last time the resource was changed"
// +kubebuilder:resource:shortName=kcrolemap,categories=keycloak
type KeycloakClientRoleMapping struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeycloakClientRoleMappingSpec   `json:"spec,omitempty"`
	Status KeycloakClientRoleMappingStatus `json:"status,omitempty"`
}

type KeycloakClientRoleMappingSpec struct {
	Endpoint EndpointSelector `json:"endpoint,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	Realm string `json:"realm"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	Client string `json:"client"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	Role string `json:"role"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	Subject Subject `json:"subject"`
}

// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type KeycloakClientRoleMappingStatus struct {
	// The ID of the client owning the role concerned by the mapping
	ClientID string `json:"clientID,omitempty"`
	// The ID of the client role concerned by the mapping
	RoleID string `json:"roleID,omitempty"`
	// The ID of the Subject concerned by the mapping
	SubjectID string `json:"subjectID,omitempty"`
	// Base status
	// +optional
	Api ApiStatus `json:"api,omitempty"`
}

func (i *KeycloakClientRoleMapping) Realm() string              { return i.Spec.Realm }
func (i *KeycloakClientRoleMapping) Endpoint() EndpointSelector { return i.Spec.Endpoint }
func (i *KeycloakClientRoleMapping) ApiStatus() *ApiStatus      { return &i.Status.Api }

// KeycloakClientRoleMappingList contains a list of KeycloakClientRoleMapping
// +kubebuilder:object:root=true
type KeycloakClientRoleMappingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeycloakClientRoleMapping `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeycloakClientRoleMapping{}, &KeycloakClientRoleMappingList{})
}
