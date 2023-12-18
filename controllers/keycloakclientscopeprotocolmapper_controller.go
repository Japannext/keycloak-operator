/*
opyright 2023.

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

// KeycloakClientScopeProtocolMapperReconciler reconciles a KeycloakClientScopeProtocolMapper object
type KeycloakClientScopeProtocolMapperReconciler struct {
	utils.BaseReconciler
}

//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclientscopeprotocolmappers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclientscopeprotocolmappers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclientscopeprotocolmappers/finalizers,verbs=update

func (r *KeycloakClientScopeProtocolMapperReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	i := &v1alpha2.KeycloakClientScopeProtocolMapper{}

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
	if err := r.syncClientScopeProtocolMapper(ctx, gc, token, i); err != nil {
		return utils.HandleError(err)
	}

	return ctrl.Result{}, nil
}

func (r *KeycloakClientScopeProtocolMapperReconciler) syncClientScopeProtocolMapper(ctx context.Context, gc *gocloak.GoCloak, token string, i *v1alpha2.KeycloakClientScopeProtocolMapper) error {

	realm := i.Spec.Realm
	api := r.Api(ctx, i)

	scope, err := gc.FindClientScope(ctx, token, realm, i.Spec.ClientScope)
	serr, notFound := utils.IsNotFound(err)
	if utils.IgnoreNotFound(err) != nil {
		return api.Error("Fetch", "failed to fetch resource", err)
	}
	scopeID := utils.Unwrap(scope.ID)
	// Pre-delete edge case
	if utils.MarkedAsDeleted(i) && utils.HasFinalizer(i) && (notFound || scopeID == "") {
		return api.AlreadyDeleted()
	}
	// Pending
	if notFound {
		return api.Waiting(serr.Message)
	}
	if scopeID == "" {
		return api.Waiting("client scope not found")
	}
	// Update ID
	if err := r.CustomPatch(ctx, i, "clientScopeID", scopeID, i.Status.ClientScopeID); err != nil {
		return err
	}

	// Fetch
	pm, err := gc.FindClientScopeProtocolMapper(ctx, token, realm, scopeID, *i.Spec.Config.Name)
	serr, notFound = utils.IsNotFound(err)
	if utils.IgnoreNotFound(err) != nil {
		return api.Error("Fetch", "failed to fetch resource", err)
	}
	id := utils.Unwrap(pm.ID)

	// Deletion
	if utils.MarkedAsDeleted(i) && utils.HasFinalizer(i) {
		if notFound || id == "" {
			return api.AlreadyDeleted()
		}
		// Deleting...
		err := gc.DeleteClientScopeProtocolMapper(ctx, token, realm, scopeID, id)
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

	if id == "" {
		newProto := i.Spec.Config
		id, err := gc.CreateClientScopeProtocolMapper(ctx, token, realm, scopeID, newProto)
		if err != nil {
			return api.Error("Create", "failed to create resource", err)
		}
		if err := r.CustomPatch(ctx, i, "protocolMapperID", id, i.Status.ProtocolMapperID); err != nil {
			return err
		}
		return api.Created()
	}
	// Update ID
	if err := r.CustomPatch(ctx, i, "protocolMapperID", id, i.Status.ProtocolMapperID); err != nil {
		return err
	}

	// Update
	changelog, err := diff.Diff(i.Spec.Config, *pm)
	if err != nil {
		return api.Error("Update", "failed during diff", err)
	}
	if len(changelog) > 0 {
		api.EventUpdate(changelog)
		updatedProto := i.Spec.Config
		if err := gc.UpdateClientScopeProtocolMapper(ctx, token, realm, scopeID, updatedProto); err != nil {
			return api.Error("Update", "failed to update resource", err)
		}
		return api.Updated()
	}

	return api.NoChange()
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeycloakClientScopeProtocolMapperReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha2.KeycloakClientScopeProtocolMapper{}).
		Complete(r)
}
