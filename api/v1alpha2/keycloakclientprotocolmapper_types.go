/*
Copyright 2023.

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

// KeycloakClientProtocolMapper is the Schema for the keycloakclientprotocolmappers API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type KeycloakClientProtocolMapper struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeycloakClientProtocolMapperSpec   `json:"spec,omitempty"`
	Status KeycloakClientProtocolMapperStatus `json:"status,omitempty"`
}

// KeycloakClientProtocolMapperSpec defines the desired state of KeycloakClientProtocolMapper
type KeycloakClientProtocolMapperSpec struct {
	Endpoint EndpointSelector `json:"endpoint,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	Realm string `json:"realm"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	Client string                 `json:"client"`
	Config gocloak.ProtocolMapper `json:"config,omitempty"`
}

// KeycloakClientProtocolMapperStatus defines the observed state of KeycloakClientProtocolMapper
type KeycloakClientProtocolMapperStatus struct {
	// The ID of the client
	ClientID string `json:"clientID,omitempty"`
	// The ID of the protocol mapper managed
	ProtocolMapperID string `json:"protocolMapperID,omitempty"`
	// Base status
	// +optional
	Api ApiStatus `json:"api,omitempty"`
}

func (i *KeycloakClientProtocolMapper) Realm() string              { return i.Spec.Realm }
func (i *KeycloakClientProtocolMapper) Endpoint() EndpointSelector { return i.Spec.Endpoint }
func (i *KeycloakClientProtocolMapper) ApiStatus() *ApiStatus      { return &i.Status.Api }

// KeycloakClientProtocolMapperList contains a list of KeycloakClientProtocolMapper
// +kubebuilder:object:root=true
type KeycloakClientProtocolMapperList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeycloakClientProtocolMapper `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeycloakClientProtocolMapper{}, &KeycloakClientProtocolMapperList{})
}
