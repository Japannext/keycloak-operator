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

// KeycloakClientScope is the Schema for the keycloakclientscopes API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:shortName=kcs,categories=keycloak
// +kubebuilder:printcolumn:name="REALM",type="string",JSONPath=".spec.realm",description="Realm of the client scope"
// +kubebuilder:printcolumn:name="PROTOCOL",type="string",JSONPath=".spec.config.protocol",description="Authentication protocol used by the client"
// +kubebuilder:printcolumn:name="STATUS",type="string",JSONPath=".status.api.phase",description="The status of the realm"
// +kubebuilder:printcolumn:name="LAST CHANGED",priority=1,type="date",JSONPath=".status.api.lastTransitionTime",description="The last time the resource was changed"
type KeycloakClientScope struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeycloakClientScopeSpec   `json:"spec,omitempty"`
	Status KeycloakClientScopeStatus `json:"status,omitempty"`
}

// KeycloakClientScopeSpec defines the desired state of KeycloakClientScope
type KeycloakClientScopeSpec struct {
	Endpoint EndpointSelector `json:"endpoint,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	Realm  string              `json:"realm"`
	Config gocloak.ClientScope `json:"config"`
}

// KeycloakClientScopeStatus defines the observed state of KeycloakClientScope
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:validation:Optional
type KeycloakClientScopeStatus struct {
	// The ID of the client scope deployed
	ClientScopeID string `json:"clientScopeID,omitempty"`
	// Base status
	// +optional
	Api ApiStatus `json:"api,omitempty"`
}

func (i *KeycloakClientScope) Realm() string              { return i.Spec.Realm }
func (i *KeycloakClientScope) Endpoint() EndpointSelector { return i.Spec.Endpoint }
func (i *KeycloakClientScope) ApiStatus() *ApiStatus      { return &i.Status.Api }

// KeycloakClientScopeList contains a list of KeycloakClientScope
// +kubebuilder:object:root=true
type KeycloakClientScopeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeycloakClientScope `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeycloakClientScope{}, &KeycloakClientScopeList{})
}
