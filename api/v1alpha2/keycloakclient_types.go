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

// KeycloakClient is the Schema for the keycloakclients API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:shortName=kc,categories=keycloak
// +kubebuilder:printcolumn:name="CLIENT ID",type="string",JSONPath=".spec.config.clientId",description="Client ID of the keycloak client"
// +kubebuilder:printcolumn:name="PROTOCOL",type="string",JSONPath=".spec.config.protocol",description="Authentication protocol used by the client"
// +kubebuilder:printcolumn:name="STATUS",type="string",JSONPath=".status.api.phase",description="The status of the realm"
// +kubebuilder:printcolumn:name="LAST CHANGED",priority=1,type="date",JSONPath=".status.api.lastTransitionTime",description="The last time the resource was changed"
// +kubebuilder:printcolumn:name="BASE URL",priority=1,type="string",JSONPath=".spec.config.baseUrl",description="Base URL of the service"
type KeycloakClient struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeycloakClientSpec   `json:"spec,omitempty"`
	Status KeycloakClientStatus `json:"status,omitempty"`
}

type KeycloakClientSpec struct {
	Endpoint EndpointSelector `json:"endpoint,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	Realm  string          `json:"realm"`
	Secret SecretGenerator `json:"secret,omitempty"`
	Config gocloak.Client  `json:"config"`
}

// +kubebuilder:object:generate=true
type SecretGenerator struct {
	// Name of the secret to generate
	Name string `json:"name"`
	// Enable secret generation. Only useful when using the `client-secret`
	// client auth method.
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`
}

// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:validation:Optional
type KeycloakClientStatus struct {
	// The ID of the OIDC/SAML client that is created / managed
	ClientID string `json:"clientID,omitempty"`
	// Base status
	// +optional
	Api ApiStatus `json:"api,omitempty"`
}

func (i *KeycloakClient) Realm() string              { return i.Spec.Realm }
func (i *KeycloakClient) Endpoint() EndpointSelector { return i.Spec.Endpoint }
func (i *KeycloakClient) ApiStatus() *ApiStatus      { return &i.Status.Api }

// KeycloakClientList contains a list of KeycloakClient
// +kubebuilder:object:root=true
type KeycloakClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeycloakClient `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeycloakClient{}, &KeycloakClientList{})
}
