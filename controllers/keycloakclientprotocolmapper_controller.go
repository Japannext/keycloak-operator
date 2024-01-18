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

// KeycloakClientProtocolMapperReconciler reconciles a KeycloakClientProtocolMapper object
type KeycloakClientProtocolMapperReconciler struct {
	utils.BaseReconciler
}

//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclientprotocolmappers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclientprotocolmappers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclientprotocolmappers/finalizers,verbs=update

func (r *KeycloakClientProtocolMapperReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	i := &v1alpha2.KeycloakClientProtocolMapper{}

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
	if err := r.syncClientProtocolMapper(ctx, gc, token, i); err != nil {
		return utils.HandleError(err)
	}

	return ctrl.Result{}, nil
}

func (r *KeycloakClientProtocolMapperReconciler) syncClientProtocolMapper(ctx context.Context, gc *gocloak.GoCloak, token string, i *v1alpha2.KeycloakClientProtocolMapper) error {

	realm := i.Spec.Realm
	api := r.Api(ctx, i)

	c, err := gc.FindClient(ctx, token, realm, i.Spec.Client)
	serr, notFound := utils.IsNotFound(err)
	if utils.IgnoreNotFound(err) != nil {
		return api.Error("Fetch", "failed to fetch resource", err)
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
	var protocolMapper *gocloak.ProtocolMapper
	for _, pm := range *c.ProtocolMappers {
		if utils.Unwrap(pm.Name) == utils.Unwrap(i.Spec.Config.Name) {
			protocolMapper = &pm
		}
	}
	id := utils.Unwrap(protocolMapper.ID)

	// Deletion
	if utils.MarkedAsDeleted(i) && utils.HasFinalizer(i) {
		if id == "" {
			return api.AlreadyDeleted()
		}
		// Deleting...
		err := gc.DeleteClientProtocolMapper(ctx, token, realm, idOfClient, id)
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
		id, err := gc.CreateClientProtocolMapper(ctx, token, realm, idOfClient, newProto)
		if err != nil {
			return api.Error("Create", "failed to create resource", err)
		}
		if err := r.CustomPatch(ctx, i, "protocolMapperID", id, ""); err != nil {
			return err
		}
		return api.Created()
	}
	// Update ID
	if err := r.CustomPatch(ctx, i, "protocolMapperID", id, i.Status.ProtocolMapperID); err != nil {
		return err
	}

	// Update
	changelog, err := diff.Diff(i.Spec.Config, *protocolMapper)
	if err != nil {
		return api.Error("Update", "failed during diff", err)
	}
	if len(changelog) > 0 {
		api.EventUpdate(changelog)
		updatedProto := i.Spec.Config
		if err := gc.UpdateClientProtocolMapper(ctx, token, realm, idOfClient, id, updatedProto); err != nil {
			return api.Error("Update", "failed to update resource", err)
		}
		return api.Updated()
	}

	return api.NoChange()
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeycloakClientProtocolMapperReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha2.KeycloakClientProtocolMapper{}).
		Complete(r)
}
