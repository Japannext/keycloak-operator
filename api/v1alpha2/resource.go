package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"time"
)

type Phase string

const (
	SYNCED    Phase = "Synced"
	ERROR     Phase = "Error"
	PENDING   Phase = "Pending"
	FORBIDDEN Phase = "Forbidden"
)

// +kubebuilder:object:generate=true
type ResourceStatus struct {
	// Whether the resource is synced, not synced, failed to sync, etc
	Phase Phase `json:"phase,omitempty"`
	// The time the resource was last updated.
	// +optional
	LastChanged *metav1.Time `json:"lastChanged,omiempty"`
}

func Now() *metav1.Time {
	return &metav1.Time{Time: time.Now()}
}
