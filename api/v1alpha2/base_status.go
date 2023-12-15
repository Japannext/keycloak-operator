package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A base status shared by all keycloak resources
// +k8s:openapi-gen=true
// +kubebuilder:validation:Optional
type BaseStatus struct {
	Ready bool `json:"ready,omitempty"`
	//
	Phase string `json:"phase,omitempty"`
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
}
