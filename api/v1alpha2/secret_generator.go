package v1alpha2

// +kubebuilder:object:generate=true
type SecretGenerator struct {
	// Name of the secret to generate
	Name string `json:"name"`
	// Enable secret generation. Only useful when using the `client-secret`
	// client auth method.
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`
}
