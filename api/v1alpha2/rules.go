package v1alpha2

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// A constraint. Can be match a resource being reconciled.
// +kubebuilder:object:generate=true
type Rule struct {
	// A name to describe and document the rule.
	// +optional
	Name string `json:"name,omitempty"`
	// The authorization action to perform. Valid values: `allow`/`reject`.
	// +kubebuilder:validation:Enum=allow;reject
	Action string `json:"action"`
	// Resources that are allowed to be modified.
	// `*` and an empty array will authorize the rule for every resource
	Resources []string `json:"resources,omitempty"`
	// Namespaces allowed to manage resources
	// `*` and an empty array will authorize the rule for any namespace
	Namespaces []string `json:"namespaces,omitempty"`
	// Realms concerned by the constraint
	// `*` and an empty array will authorize the rule for any realm
	Realms []string `json:"realms,omitempty"`
}

// Check if a list of string contain a substring
// - When `*` is encountered, return a match
// - When the list is empty, return a match
func contains(items []string, target string) bool {
	if len(items) == 0 {
		return true
	}
	for _, item := range items {
		if item == "*" {
			return true
		}
		if item == target {
			return true
		}
	}
	return false
}

// Decides if a rule allows an object
func (c *Rule) Match(i client.Object, realm string) bool {
	if !contains(c.Realms, realm) {
		return false
	}
	if !contains(c.Namespaces, i.GetNamespace()) {
		return false
	}
	kind := i.GetObjectKind().GroupVersionKind().Kind
	if !contains(c.Resources, kind) {
		return false
	}
	return true
}
