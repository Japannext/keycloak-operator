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

	"github.com/japannext/keycloak-operator/gocloak"
)

// KeycloakClientRole is the Schema for the keycloakclientroles API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:shortName=kcrole,categories=keycloak
// +kubebuilder:printcolumn:name="REALM",type="string",JSONPath=".spec.realm"
// +kubebuilder:printcolumn:name="CLIENT",type="string",JSONPath=".spec.client"
// +kubebuilder:printcolumn:name="ROLE",type="string",JSONPath=".spec.config.name"
// +kubebuilder:printcolumn:name="STATUS",type="string",JSONPath=".status.api.phase",description="The status of the resource"
// +kubebuilder:printcolumn:name="LAST CHANGED",priority=1,type="date",JSONPath=".status.api.lastTransitionTime",description="The last time the resource was changed"
// +kubebuilder:printcolumn:name="DESCRIPTION",type="string",priority=1,JSONPath=".spec.config.description",description="The description of the role"
type KeycloakClientRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	ClientName string `json:"clientName,omitempty"`

	Spec   KeycloakClientRoleSpec   `json:"spec,omitempty"`
	Status KeycloakClientRoleStatus `json:"status,omitempty"`
}

// KeycloakClientRoleSpec defines the desired state of KeycloakClientRole
// +kubebuilder:object:generate=true
type KeycloakClientRoleSpec struct {
	Endpoint EndpointSelector `json:"endpoint,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	Realm string `json:"realm"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	Client string       `json:"client"`
	Config gocloak.Role `json:"config"`
}

// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:validation:Optional
type KeycloakClientRoleStatus struct {
	// The ID of the client the role belongs to
	ClientID string `json:"clientID,omitempty"`
	// The ID of the role managed
	RoleID string `json:"roleID,omitempty"`
	// Base status
	// +optional
	Api ApiStatus `json:"api,omitempty"`
}

func (i *KeycloakClientRole) Realm() string              { return i.Spec.Realm }
func (i *KeycloakClientRole) Endpoint() EndpointSelector { return i.Spec.Endpoint }
func (i *KeycloakClientRole) ApiStatus() *ApiStatus      { return &i.Status.Api }

// KeycloakClientRoleList contains a list of KeycloakClientRole
// +kubebuilder:object:root=true
type KeycloakClientRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeycloakClientRole `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeycloakClientRole{}, &KeycloakClientRoleList{})
}
