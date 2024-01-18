/*
Copyright 2024 Japannext.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/japannext/keycloak-operator/api/v1alpha2"
	"github.com/japannext/keycloak-operator/utils"
)

// KeycloakEndpointReconciler reconciles a KeycloakEndpoint object
type KeycloakClusterEndpointReconciler struct {
	utils.BaseReconciler
}

//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclusterendpoints,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclusterendpoints/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclusterendpoints/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

func (r *KeycloakClusterEndpointReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	i := &api.KeycloakClusterEndpoint{}

	// Resource
	if err := r.Client.Get(ctx, req.NamespacedName, i); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := reconcileEndpoint(&r.BaseReconciler, ctx, i); err != nil {
		return utils.HandleError(err)
	}

	return ctrl.Result{}, nil

}

// SetupWithManager sets up the controller with the Manager.
func (r *KeycloakClusterEndpointReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.KeycloakClusterEndpoint{}).
		Complete(r)
}
