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
)

// KeycloakClusterEndpoint represent a Keycloak endpoint.
// It is similar to KeycloakEndpoint, but not scoped
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Cluster,shortName=kce,categories=keycloak
// +kubebuilder:printcolumn:name="VERSION",type="string",JSONPath=".status.version",description="The version of the endpoint"
// +kubebuilder:printcolumn:name="STATUS",type="string",JSONPath=".status.phase",description="The status of the endpoint"
// +kubebuilder:printcolumn:name="LAST CONNECTION",priority=1,type="date",JSONPath=".status.lastSuccess",description="The last time the endpoint was connected"
// +kubebuilder:printcolumn:name="URL",type="string",priority=1,JSONPath=".spec.baseUrl",description="The URL of the endpoint"
type KeycloakClusterEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeycloakEndpointSpec   `json:"spec,omitempty"`
	Status KeycloakEndpointStatus `json:"status,omitempty"`
}

func (i *KeycloakClusterEndpoint) EndpointSpec() *KeycloakEndpointSpec     { return &i.Spec }
func (i *KeycloakClusterEndpoint) EndpointStatus() *KeycloakEndpointStatus { return &i.Status }

// KeycloakClusterEndpointList contains a list of KeycloakClusterEndpoint
// +kubebuilder:object:root=true
type KeycloakClusterEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeycloakClusterEndpoint `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeycloakClusterEndpoint{}, &KeycloakClusterEndpointList{})
}
