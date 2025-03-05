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

package controller

import (
	"context"
	"fmt"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/japannext/keycloak-operator/api/v1alpha2"
	"github.com/japannext/keycloak-operator/utils"
)

// KeycloakEndpointReconciler reconciles a KeycloakEndpoint object
type KeycloakEndpointReconciler struct {
	utils.BaseReconciler
}

//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakendpoints,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakendpoints/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakendpoints/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

func (r *KeycloakEndpointReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	i := &api.KeycloakClusterEndpoint{}

	// Resource
	if err := r.Client.Get(ctx, req.NamespacedName, i); err != nil {
		return utils.HandleError(err)
	}

	if err := reconcileEndpoint(&r.BaseReconciler, ctx, i); err != nil {
		return utils.HandleError(err)
	}

	return ctrl.Result{}, nil
}

type Endpoint interface {
	client.Object
	EndpointSpec() *api.KeycloakEndpointSpec
	EndpointStatus() *api.KeycloakEndpointStatus
}

func reconcileEndpoint(r *utils.BaseReconciler, ctx context.Context, i Endpoint) error {

	spec := i.EndpointSpec()
	status := i.EndpointStatus()

	if status.Phase == "Connected" && status.LastSuccess.Add(2*time.Minute).After(time.Now()) {
		return nil
	}

	// Endpoint
	gc, token, err := utils.ExtractEndpointFromSpec(r, ctx, *spec, "")
	if err != nil {
		return err
	}

	info, err := gc.GetServerInfo(ctx, token)
	if err != nil {
		msg := fmt.Sprintf("failed to connect to endpoint '%s'", spec.BaseUrl)
		r.Event(i, "Warning", "Connect", fmt.Sprintf("%s: %s", msg, err))
		if status.Phase != "Error" || status.Message != msg {
			patch := client.MergeFrom(i)
			status.Phase = "Error"
			status.Message = msg
			if err := r.Patch(ctx, i, patch); err != nil {
				return fmt.Errorf("failed to patch resource status: %w", err)
			}
			return utils.Reschedule{}
		}
		return err
	}

	if status.Phase != "Connected" {
		r.Event(i, "Normal", "Endpoint", fmt.Sprintf("successfully connected to %s", spec.BaseUrl))
		status.Version = utils.Unwrap(info.SystemInfo.Version)
		status.Phase = "Connected"
		status.LastSuccess = utils.Now()
		if err := r.Status().Update(ctx, i); err != nil {
			return fmt.Errorf("failed to update status: %w", err)
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeycloakEndpointReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.KeycloakEndpoint{}).
		Complete(r)
}
