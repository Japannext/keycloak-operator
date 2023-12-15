package v1alpha2

// Represent a user or group in keycloak
// +kubebuilder:object:generate=true
type Subject struct {
	// The type of the subject. Either `user` or `group`.
	// +kubebuilder:validation:Enum=user;group
	Kind string `json:"kind"`
	// The name of the user or group
	Name string `json:"name"`
}

type UserRepresentation struct {
	// User ID.
	// +optional
	ID string `json:"id,omitempty"`
	// User Name.
	// +optional
	UserName string `json:"username,omitempty"`
}

type GroupRepresentation struct {
	// Group ID
	// +optional
	ID string `json:"id,omitempty"`
	// Name of the group
	Name string `json:"name"`
}
