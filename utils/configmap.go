package utils

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/japannext/keycloak-operator/api/v1alpha2"
)

// Extract the data from a given ConfigMap
func extractConfigMap(r *BaseReconciler, ctx context.Context, cm *api.ConfigMapValue, ns string) (string, error) {
	// This allow us to use the same object for clusterwide resource and namespaced resources.
	// The clusterwide resource simply set `ns = ""`.
	if ns == "" {
		ns = cm.Namespace
	}

	configMap := &corev1.ConfigMap{}

	err := r.Get(ctx, client.ObjectKey{Namespace: ns, Name: cm.Name}, configMap)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve ConfigMap/%s (ns: '%s')", cm.Name, ns)
	}

	data, ok := configMap.Data[cm.Key]
	if !ok {
		return "", fmt.Errorf("key '%s' not found in ConfigMap/%s (ns: '%s')", cm.Key, cm.Name, ns)
	}

	return data, nil
}

func IsConfigMapEmpty(cm *api.ConfigMapValue) bool {
	return (*cm == api.ConfigMapValue{})
}
