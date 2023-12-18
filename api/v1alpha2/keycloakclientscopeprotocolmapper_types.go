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

// KeycloakClientScopeProtocolMapper is the Schema for the keycloakclientscopeprotocolmappers API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:shortName=kcspm,categories=keycloak
// +kubebuilder:printcolumn:name="REALM",type="string",JSONPath=".spec.realm",description="Realm of the client scope"
// +kubebuilder:printcolumn:name="SCOPE",type="string",JSONPath=".spec.clientScope",description="Name of the client scope"
// +kubebuilder:printcolumn:name="STATUS",type="string",JSONPath=".status.api.phase",description="The status of the realm"
// +kubebuilder:printcolumn:name="LAST CHANGED",priority=1,type="date",JSONPath=".status.api.lastTransitionTime",description="The last time the resource was changed"
type KeycloakClientScopeProtocolMapper struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeycloakClientScopeProtocolMapperSpec   `json:"spec,omitempty"`
	Status KeycloakClientScopeProtocolMapperStatus `json:"status,omitempty"`
}

// KeycloakClientScopeProtocolMapperSpec defines the desired state of KeycloakClientScopeProtocolMapper
type KeycloakClientScopeProtocolMapperSpec struct {
	Endpoint EndpointSelector `json:"endpoint,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	Realm string `json:"realm"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	ClientScope string                 `json:"clientScope"`
	Config      gocloak.ProtocolMapper `json:"config,omitempty"`
}

// KeycloakClientScopeProtocolMapperStatus defines the observed state of KeycloakClientScopeProtocolMapper
type KeycloakClientScopeProtocolMapperStatus struct {
	// The ID of the client scope
	ClientScopeID string `json:"clientScopeID,omitempty"`
	// The ID of the protocol mapper managed
	ProtocolMapperID string `json:"protocolMapperID,omitempty"`
	// Base status
	// +optional
	Api ApiStatus `json:"api,omitempty"`
}

func (i *KeycloakClientScopeProtocolMapper) Realm() string              { return i.Spec.Realm }
func (i *KeycloakClientScopeProtocolMapper) Endpoint() EndpointSelector { return i.Spec.Endpoint }
func (i *KeycloakClientScopeProtocolMapper) ApiStatus() *ApiStatus      { return &i.Status.Api }

// KeycloakClientScopeProtocolMapperList contains a list of KeycloakClientScopeProtocolMapper
// +kubebuilder:object:root=true
type KeycloakClientScopeProtocolMapperList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeycloakClientScopeProtocolMapper `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeycloakClientScopeProtocolMapper{}, &KeycloakClientScopeProtocolMapperList{})
}
