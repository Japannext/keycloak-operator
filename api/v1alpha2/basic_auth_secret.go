package v1alpha2

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
