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

// KeycloakEndpoint is the Schema for the keycloakendpoints API
// +genclient
// +k8s:openapi-gen=true
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="VERSION",type="string",JSONPath=".status.version",description="The version of the endpoint"
// +kubebuilder:printcolumn:name="STATUS",type="string",JSONPath=".status.phase",description="The status of the endpoint"
// +kubebuilder:printcolumn:name="LAST CONNECTION",priority=1,type="date",JSONPath=".status.lastSuccess",description="The last time the endpoint was connected"
// +kubebuilder:printcolumn:name="URL",type="string",priority=1,JSONPath=".spec.baseUrl",description="The URL of the endpoint"
type KeycloakEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeycloakEndpointSpec   `json:"spec,omitempty"`
	Status KeycloakEndpointStatus `json:"status,omitempty"`
}

// KeycloakEndpointSpec defines the desired state of KeycloakEndpoint
// +kubebuilder:object:generate=true
// +k8s:openapi-gen=true
type KeycloakEndpointSpec struct {
	// URL to the keycloak server to manage
	BaseUrl string `json:"baseUrl,omitempty"`

	// Additional prefix of the keycloak API (if needed). Should sometimes
	// be set to `/auth` for some deployments of keycloak.
	// +kubebuilder:default=""
	BasePath string `json:"basePath,omitempty"`

	// Use the value stored in a ConfigMap for the CA certificate
	CaConfigMap *ConfigMapValue `json:"caConfigMap,omitempty"`

	// Ignore TLS CA verification. It's recommended to set `caConfigMap` instead.
	// +kubebuilder:default=false
	TlsInsecureSkipVerify bool `json:"tlsInsecureSkipVerify,omitempty"`

	// Realm to use for admin connections. Defaults to `master`.
	// +kubebuilder:default="master"
	Realm string `json:"realm"`

	// Timeout in seconds for the HTTP connection. Defaults to 10 seconds.
	// +kubebuilder:default=10
	Timeout int `json:"timeout"`

	// The HTTP client rate limit for the operator to keycloak
	//RateLimiter keycloak.RateLimiter `json:"rateLimiter,omitempty"`

	// The name of a secret of type `kubernetes.io/basic-auth` to authenticate to
	// keycloak as admin. The secret need to be in the same namespace as the KeycloakEndpoint.
	// When used in the context of KeycloakClusterEndpoint, a the `namespace` of the secret can
	// be set.
	BasicAuthSecret BasicAuthSecret `json:"basicAuthSecret,omitempty"`

	// A list of rules to complete kubernetes RBAC. If the resource being reconciled matches
	// one of this rule, the action will be executed (allow/reject). If no rule match, the
	// `noMatchBehavior` will be executed. If nothing matches, it will be allowed.
	// If you need to default to forbidden, add a `{action: reject}` as the last rule.
	Rules []Rule `json:"rules,omitempty"`
}

// Reference a user/password data stored in a secret
// +kubebuilder:object:generate=true
type BasicAuthSecret struct {
	// The name of a secret of type `kubernetes.io/basic-auth` to authenticate to
	// keycloak as admin. The secret need to be in the same namespace as the KeycloakEndpoint.
	Name string `json:"name"`

	// Namespace where the secret resides. Only used for KeycloakClusterEndpoint.
	// Has no effect when used with KeycloakEndpoint.
	Namespace string `json:"namespace,omitempty"`
}

// Reference a value stored in a ConfigMap
// +kubebuilder:object:generate=true
type ConfigMapValue struct {
	// Name of the configMap referenced
	Name string `json:"name"`

	// Name of the configMap key to use
	Key string `json:"key"`

	// Namespace where the ConfigMap resides. Used only for KeycloakClusterEndpoint.
	// Has no effect when used with KeycloakEndpoint.
	Namespace string `json:"namespace,omitempty"`
}

type EndpointPhase string

const (
	ENDPOINT_SYNCED  EndpointPhase = "Synced"
	ENDPOINT_PENDING EndpointPhase = "Pending"
	ENDPOINT_ERROR   EndpointPhase = "Error"
)

// KeycloakEndpointStatus defines the observed state of KeycloakEndpoint
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type KeycloakEndpointStatus struct {
	// Whether the CRD could connect to the keycloak endpoint successfully
	Phase   EndpointPhase `json:"phase,omitempty"`
	Version string        `json:"version,omitempty"`
	Message string        `json:"message,omitempty"`
	// +optional
	LastSuccess *metav1.Time `json:"lastSuccess,omitempty"`
}

func (i *KeycloakEndpoint) EndpointSpec() *KeycloakEndpointSpec     { return &i.Spec }
func (i *KeycloakEndpoint) EndpointStatus() *KeycloakEndpointStatus { return &i.Status }

// KeycloakEndpointList contains a list of KeycloakEndpoint
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type KeycloakEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeycloakEndpoint `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeycloakEndpoint{}, &KeycloakEndpointList{})
}
