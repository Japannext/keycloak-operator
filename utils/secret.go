package utils

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/japannext/keycloak-operator/api/v1alpha2"
)

// Extract the username and password from a basic-auth secret.
func extractBasicAuthSecret(r *BaseReconciler, ctx context.Context, s api.BasicAuthSecret, ns string) (string, string, error) {
	// This allow us to use the same object for clusterwide resource and namespaced resources.
	// The clusterwide resource simply set `ns = ""`.
	if ns == "" {
		ns = s.Namespace
	}

	secret := &corev1.Secret{}

	err := r.Get(ctx, client.ObjectKey{Namespace: ns, Name: s.Name}, secret)
	if err != nil {
		return "", "", fmt.Errorf("unable to retrieve secret: %w", err)
	}

	username, ok := secret.Data["username"]
	if !ok {
		return "", "", fmt.Errorf("key 'username' not found in secret")
	}
	if len(username) == 0 {
		return "", "", fmt.Errorf("key 'username' is empty")
	}

	password, ok := secret.Data["password"]
	if !ok {
		return "", "", fmt.Errorf("key 'password' not found in secret")
	}
	if len(password) == 0 {
		return "", "", fmt.Errorf("key 'password' is empty")
	}

	return string(username[:]), string(password[:]), nil
}
