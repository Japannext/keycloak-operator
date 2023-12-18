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

// KeycloakRealm is the Schema for the keycloakrealms API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:object:generate=true
// +kubebuilder:storageversion
// +kubebuilder:resource:shortName=kr,categories=keycloak
// +kubebuilder:printcolumn:name="DISPLAY NAME",type="string",JSONPath=".spec.config.displayName",description="Display name of the realm"
// +kubebuilder:printcolumn:name="ENABLED",type="boolean",JSONPath=".spec.config.enabled",description="Whether the realm is enabled"
// +kubebuilder:printcolumn:name="STATUS",type="string",JSONPath=".status.api.phase",description="The status of the realm"
// +kubebuilder:printcolumn:name="LAST TRANSITION",priority=1,type="date",JSONPath=".status.api.lastTransitionTime",description="The last time the resource was changed"
type KeycloakRealm struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeycloakRealmSpec   `json:"spec,omitempty"`
	Status KeycloakRealmStatus `json:"status,omitempty"`
}

// KeycloakRealmSpec defines the desired state of KeycloakRealm
// +kubebuilder:object:generate=true
// +k8s:openapi-gen=true
type KeycloakRealmSpec struct {
	Endpoint EndpointSelector `json:"endpoint,omitempty"`
	// +kubebuilder:validation:Required
	Config gocloak.RealmRepresentation `json:"config"`
}

// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:validation:Optional
type KeycloakRealmStatus struct {
	// The ID of the realm managed
  // +optional
	RealmID string `json:"realmId,omitempty"`

	// Base status
  // +optional
	Api ApiStatus `json:"api,omitempty"`
}

func (i *KeycloakRealm) Realm() string              { return *i.Spec.Config.Realm }
func (i *KeycloakRealm) Endpoint() EndpointSelector { return i.Spec.Endpoint }
func (i *KeycloakRealm) ApiStatus() *ApiStatus      { return &i.Status.Api }

// KeycloakRealmList contains a list of KeycloakRealm
// +kubebuilder:object:root=true
type KeycloakRealmList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeycloakRealm `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeycloakRealm{}, &KeycloakRealmList{})
}
