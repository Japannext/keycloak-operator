package utils

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Now() *metav1.Time {
	return &metav1.Time{Time: time.Now()}
}
