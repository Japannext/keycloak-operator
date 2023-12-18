/*
Copyright 2023.

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

	"github.com/japannext/keycloak-operator/api/v1alpha2"
	"github.com/japannext/keycloak-operator/gocloak"
	"github.com/japannext/keycloak-operator/utils"
)

// KeycloakLDAPFederationReconciler reconciles a KeycloakLDAPFederation object
type KeycloakLDAPFederationReconciler struct {
	utils.BaseReconciler
}

//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakldapfederations,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakldapfederations/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakldapfederations/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update

func (r *KeycloakLDAPFederationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	i := &v1alpha2.KeycloakLDAPFederation{}

	// Resource
	if err := r.Client.Get(ctx, req.NamespacedName, i); err != nil {
		return utils.HandleError(err)
	}

	if utils.MarkedAsDeleted(i) && utils.NoFinalizer(i) {
		return ctrl.Result{}, nil
	}

	gc, token, err := r.ExtractEndpoint(ctx, i)
	if err != nil {
		return utils.HandleError(err)
	}

	// Sync client
	if err := r.syncComponent(ctx, gc, token, i); err != nil {
		return utils.HandleError(err)
	}

	return ctrl.Result{}, nil
}

func (r *KeycloakLDAPFederationReconciler) syncComponent(ctx context.Context, gc *gocloak.GoCloak, token string, i *v1alpha2.KeycloakLDAPFederation) error {
	realm := i.Spec.Realm
	ns := i.GetNamespace()
	api := r.Api(ctx, i)

	// Fetch
	component, err := gc.FindComponent(ctx, token, realm, v1alpha2.LDAP_STORAGE_MAPPER, "ldap", i.Spec.Config.Name, "")
	serr, notFound := utils.IsNotFound(err)
	if utils.IgnoreNotFound(err) != nil {
		return api.Error("Fetch", "failed to fetch component", err)
	}
	id := utils.Unwrap(component.ID)

	// Deletion
	if utils.MarkedAsDeleted(i) && utils.HasFinalizer(i) {
		if notFound {
			return api.AlreadyDeleted()
		}
		// Deleting...
		err := gc.DeleteComponent(ctx, token, realm, id)
		if _, notFound := utils.IsNotFound(err); notFound {
			return api.AlreadyDeleted()
		}
		if err != nil {
			return api.Error("Delete", "failed to delete resource", err)
		}
		// Deleted
		return api.Deleted()
	}
	// Adding finalizer
	if err := r.AppendFinalizer(ctx, i); err != nil {
		return api.Error("Finalizer", "failed to append finalizer", err)
	}
	// Pending
	if notFound {
		return api.Waiting(serr.Message)
	}

	// Creation
	if id == "" {
		// Creating...
		newComponent, err := i.Spec.Config.ToComponent(ctx, r.Client, ns)
		if err != nil {
			return api.Error("Create", "failed to convert spec to component", err)
		}
		id, err := gc.CreateComponent(ctx, token, realm, *newComponent)
		if err != nil {
			return api.Error("Create", "failed to create resource", err)
		}
		if err := r.CustomPatch(ctx, i, "componentID", id, ""); err != nil {
			return err
		}
		if err := api.SyncLDAP(gc, token, realm, id); err != nil {
			return err
		}
		// Created
		return api.Created()
	}

	// Update ID
	if err := r.CustomPatch(ctx, i, "componentID", id, i.Status.ComponentID); err != nil {
		return err
	}

	// Update
	updatedComponent, err := i.Spec.Config.ToComponent(ctx, r.Client, ns)
	if err != nil {
		return api.Error("Update", "failed to convert spec to component", err)
	}
	changelog := v1alpha2.DiffComponentConfigs(updatedComponent.ComponentConfig, component.ComponentConfig)
	if len(changelog) > 0 {
		// Updating...
		api.EventUpdate(changelog)
		updatedComponent.ID = &id
		if err := gc.UpdateComponent(ctx, token, realm, *updatedComponent); err != nil {
			return api.Error("Update", "failed to update resource", err)
		}
		if err := api.SyncLDAP(gc, token, realm, id); err != nil {
			return err
		}
		// Updated
		return api.Updated()
	}

	// No change
	return api.NoChange()
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeycloakLDAPFederationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha2.KeycloakLDAPFederation{}).
		Complete(r)
}
