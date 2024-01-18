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

	diff "github.com/r3labs/diff/v3"

	"github.com/japannext/keycloak-operator/api/v1alpha2"
	"github.com/japannext/keycloak-operator/gocloak"
	"github.com/japannext/keycloak-operator/utils"
)

// KeycloakClientRoleReconciler reconciles a KeycloakClientRole object
type KeycloakClientRoleReconciler struct {
	utils.BaseReconciler
}

//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclientroles,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclientroles/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclientroles/finalizers,verbs=update

func (r *KeycloakClientRoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	i := &v1alpha2.KeycloakClientRole{}

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
	if err := r.syncClientRole(ctx, gc, token, i); err != nil {
		return utils.HandleError(err)
	}

	return ctrl.Result{}, nil
}

func (r *KeycloakClientRoleReconciler) syncClientRole(ctx context.Context, gc *gocloak.GoCloak, token string, i *v1alpha2.KeycloakClientRole) error {

	realm := i.Spec.Realm
	api := r.Api(ctx, i)

	// Fetch Client
	c, err := gc.FindClient(ctx, token, realm, i.Spec.Client)
	serr, notFound := utils.IsNotFound(err)
	if utils.IgnoreNotFound(err) != nil {
		return api.Error("FetchClient", "failed to fetch resource", err)
	}
	idOfClient := utils.Unwrap(c.ID)
	// Pre-delete edge case
	if utils.MarkedAsDeleted(i) && utils.HasFinalizer(i) && (notFound || idOfClient == "") {
		return api.AlreadyDeleted()
	}
	// Pending
	if notFound {
		return api.Waiting(serr.Message)
	}
	if idOfClient == "" {
		return api.Waiting("client not found")
	}
	// Update ID
	if err := r.CustomPatch(ctx, i, "clientID", idOfClient, i.Status.ClientID); err != nil {
		return err
	}

	// Fetch
	role, err := gc.FindClientRole(ctx, token, realm, idOfClient, *i.Spec.Config.Name)
	serr, notFound = utils.IsNotFound(err)
	if utils.IgnoreNotFound(err) != nil {
		return api.Error("Fetch", "failed to fetch resource", err)
	}
	rid := utils.Unwrap(role.ID)

	// Deletion
	if utils.MarkedAsDeleted(i) && utils.HasFinalizer(i) {
		if notFound || rid == "" {
			return api.AlreadyDeleted()
		}
		// Deleting...
		err := gc.DeleteClientRole(ctx, token, realm, idOfClient, rid)
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
	if rid == "" {
		newRole := i.Spec.Config
		rid, err := gc.CreateClientRole(ctx, token, realm, idOfClient, newRole)
		if err != nil {
			return api.Error("Create", "failed to create resource", err)
		}
		if err := r.CustomPatch(ctx, i, "roleID", rid, ""); err != nil {
			return err
		}
		return api.Created()
	}

	// Update ID
	if err := r.CustomPatch(ctx, i, "roleID", rid, i.Status.RoleID); err != nil {
		return err
	}

	// Update
	changelog, err := diff.Diff(i.Spec.Config, *role)
	if err != nil {
		return api.Error("Update", "failed during diff", err)
	}
	if len(changelog) > 0 {
		api.EventUpdate(changelog)
		updatedRole := i.Spec.Config
		if err := gc.UpdateRole(ctx, token, realm, idOfClient, updatedRole); err != nil {
			return api.Error("Update", "failed to update resource", err)
		}
		return api.Updated()
	}

	return api.NoChange()
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeycloakClientRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha2.KeycloakClientRole{}).
		Complete(r)
}
