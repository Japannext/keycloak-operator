package v1alpha2

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
