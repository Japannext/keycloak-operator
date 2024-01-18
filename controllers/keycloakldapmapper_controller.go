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

	"github.com/japannext/keycloak-operator/api/v1alpha2"
	"github.com/japannext/keycloak-operator/gocloak"
	"github.com/japannext/keycloak-operator/utils"
)

// KeycloakLDAPMapperReconciler reconciles a KeycloakLDAPMapper object
type KeycloakLDAPMapperReconciler struct {
	utils.BaseReconciler
}

//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakldapmappers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakldapmappers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakldapmappers/finalizers,verbs=update

func (r *KeycloakLDAPMapperReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	i := &v1alpha2.KeycloakLDAPMapper{}

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
	ldap, err := r.syncLdapMapper(ctx, gc, token, i)
	if err != nil {
		return utils.HandleError(err)
	}

	if ldap.Changed {
		if err := r.SyncLDAP(ctx, gc, token, i, ldap); err != nil {
			return utils.HandleError(err)
		}
	}

	return ctrl.Result{}, nil
}

func (r *KeycloakLDAPMapperReconciler) syncLdapMapper(ctx context.Context, gc *gocloak.GoCloak, token string, i *v1alpha2.KeycloakLDAPMapper) (utils.LDAPSync, error) {
	realm := i.Spec.Realm
	api := r.Api(ctx, i)
	ldap := utils.LDAPSync{}
	ldap.Realm = realm

	// Fetch Federation
	fed, err := gc.FindComponent(ctx, token, realm, v1alpha2.USER_STORAGE_PROVIDER, "ldap", i.Spec.Federation, "")
	serr, notFound := utils.IsNotFound(err)
	if utils.IgnoreNotFound(err) != nil {
		return ldap, api.Error("Fetch", "failed to fetch federation", err)
	}
	fid := utils.Unwrap(fed.ID)
	ldap.FederationID = fid
	// Pre-delete edge case
	if utils.MarkedAsDeleted(i) && utils.HasFinalizer(i) && (notFound || fid == "") {
		return ldap, api.AlreadyDeleted()
	}
	// Pending
	if notFound {
		return ldap, api.Waiting(serr.Message)
	}
	if fid == "" {
		return ldap, api.Waiting("ldap federation not found")
	}
	// Update ID
	if err := r.CustomPatch(ctx, i, "federationID", fid, i.Status.FederationID); err != nil {
		return ldap, err
	}

	// Fetch
	component, err := gc.FindComponent(ctx, token, realm, v1alpha2.LDAP_STORAGE_MAPPER, i.Spec.Type, i.Spec.Name, fid)
	serr, notFound = utils.IsNotFound(err)
	if utils.IgnoreNotFound(err) != nil {
		return ldap, api.Error("Fetch", "failed to fetch component", err)
	}
	id := utils.Unwrap(component.ID)

	// Deletion
	if utils.MarkedAsDeleted(i) && utils.HasFinalizer(i) {
		if notFound || id != "" {
			return ldap, api.AlreadyDeleted()
		}
		// Deleting...
		err := gc.DeleteComponent(ctx, token, realm, id)
		if _, notFound := utils.IsNotFound(err); notFound {
			return ldap, api.AlreadyDeleted()
		}
		if err != nil {
			return ldap, api.Error("Delete", "failed to delete resource", err)
		}
		// Deleted
		return ldap, api.Deleted()
	}
	// Adding finalizer
	if err := r.AppendFinalizer(ctx, i); err != nil {
		return ldap, api.Error("Finalizer", "failed to append finalizer", err)
	}
	// Pending
	if notFound {
		return ldap, api.Waiting(serr.Message)
	}

	// Creation
	if id == "" {
		// Creating...
		newComponent, err := i.ToComponent(fid)
		if err != nil {
			return ldap, api.Error("Create", "failed to create resource", err)
		}
		id, err := gc.CreateComponent(ctx, token, realm, *newComponent)
		if err != nil {
			return ldap, api.Error("Create", "failed to create resource", err)
		}
		ldap.Changed = true
		if err := r.CustomPatch(ctx, i, "componentID", id, ""); err != nil {
			return ldap, err
		}
		// Created
		return ldap, api.Created()
	}
	// Update ID
	if err := r.CustomPatch(ctx, i, "componentID", id, i.Status.ComponentID); err != nil {
		return ldap, err
	}

	// Update
	updatedComponent, err := i.ToComponent(fid)
	if err != nil {
		return ldap, api.Error("Update", "failed to update resource", err)
	}
	changelog := v1alpha2.DiffComponentConfigs(updatedComponent.ComponentConfig, component.ComponentConfig)
	if len(changelog) > 0 {
		// Updating...
		api.EventUpdate(changelog)
		updatedComponent.ID = &id
		if err := gc.UpdateComponent(ctx, token, realm, *updatedComponent); err != nil {
			return ldap, api.Error("Update", "failed to update resource", err)
		}
		ldap.Changed = true
		// Updated
		return ldap, api.Updated()
	}

	// No change
	return ldap, api.NoChange()
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeycloakLDAPMapperReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha2.KeycloakLDAPMapper{}).
		Complete(r)
}
