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

// KeycloakRealmRole is the Schema for the keycloakrealmroles API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:shortName=krrole,categories=keycloak
// +kubebuilder:printcolumn:name="REALM",type="string",JSONPath=".spec.realm"
// +kubebuilder:printcolumn:name="ROLE",type="string",JSONPath=".spec.config.name"
// +kubebuilder:printcolumn:name="STATUS",type="string",JSONPath=".status.api.phase",description="The status of the resource"
// +kubebuilder:printcolumn:name="LAST CHANGED",priority=1,type="date",JSONPath=".status.api.lastTransitionTime",description="The last time the resource was changed"
// +kubebuilder:printcolumn:name="DESCRIPTION",type="string",priority=1,JSONPath=".spec.config.description",description="The description of the role"
type KeycloakRealmRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeycloakRealmRoleSpec   `json:"spec,omitempty"`
	Status KeycloakRealmRoleStatus `json:"status,omitempty"`
}

// KeycloakRealmRoleSpec defines the desired state of KeycloakRealmRole
type KeycloakRealmRoleSpec struct {
	Endpoint EndpointSelector `json:"endpoint,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	Realm  string       `json:"realm"`
	Config gocloak.Role `json:"config"`
}

// KeycloakRealmRoleStatus defines the observed state of KeycloakRealmRole
type KeycloakRealmRoleStatus struct {
	// The ID of the role managed
	RoleID string `json:"roleID,omitempty"`
	// Base status
	// +optional
	Api ApiStatus `json:"api,omitempty"`
}

func (i *KeycloakRealmRole) Realm() string              { return i.Spec.Realm }
func (i *KeycloakRealmRole) Endpoint() EndpointSelector { return i.Spec.Endpoint }
func (i *KeycloakRealmRole) ApiStatus() *ApiStatus      { return &i.Status.Api }

// KeycloakRealmRoleList contains a list of KeycloakRealmRole
// +kubebuilder:object:root=true
type KeycloakRealmRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeycloakRealmRole `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeycloakRealmRole{}, &KeycloakRealmRoleList{})
}
