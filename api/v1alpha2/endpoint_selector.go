package v1alpha2

// Select a KeycloakEndpoint
// +kubebuilder:object:generate=true
type EndpointSelector struct {
	// Kind of the resource representing a Keycloak endpoint
	// +kubebuilder:validation:Enum=KeycloakEndpoint;KeycloakClusterEndpoint
	// +kubebuilder:default=KeycloakEndpoint
	Kind string `json:"kind,omitempty"`
	// Name of the KeycloakEndpoint/KeycloakClusterEndpoint resource
	// +required
	Name string `json:"name,omitempty"`
}
