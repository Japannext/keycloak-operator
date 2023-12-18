package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Phase string

const (
	SYNCED        Phase = "Synced"
	ERROR         Phase = "Error"
	FORBIDDEN     Phase = "Forbidden"
	NO_ENDPOINT   Phase = "NoEndpoint"
	WAITING       Phase = "Waiting"
	NOT_CONNECTED Phase = "NotConnected"
)

// +kubebuilder:object:generate=true
type ApiStatus struct {
	// Whether the resource is synced, not synced, failed to sync, etc
	Phase Phase `json:"phase,omitempty"`
	// The time the resource was last updated.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`
}
