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

	ctrl "sigs.k8s.io/controller-runtime"

	diff "github.com/r3labs/diff/v3"

	"github.com/japannext/keycloak-operator/api/v1alpha2"
	"github.com/japannext/keycloak-operator/gocloak"
	"github.com/japannext/keycloak-operator/utils"
)

// KeycloakRealmReconciler reconciles a KeycloakRealm object
type KeycloakRealmReconciler struct {
	utils.BaseReconciler
}

//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakrealms,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakrealms/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakrealms/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *KeycloakRealmReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	i := &v1alpha2.KeycloakRealm{}

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

	// Sync realm
	if err := r.syncRealm(ctx, gc, token, i); err != nil {
		return utils.HandleError(err)
	}

	return ctrl.Result{}, nil
}

func (r *KeycloakRealmReconciler) syncRealm(ctx context.Context, gc *gocloak.GoCloak, token string, i *v1alpha2.KeycloakRealm) error {

	api := r.Api(ctx, i)

	realmName := utils.Unwrap(i.Spec.Config.Realm)

	// Fetch
	realm, err := gc.GetRealm(ctx, token, realmName)
	_, notFound := utils.IsNotFound(err)
	if utils.IgnoreNotFound(err) != nil {
		return api.Error("Fetch", "failed to fetch resource", err)
	}

	// Deletion
	if utils.MarkedAsDeleted(i) && utils.HasFinalizer(i) {
		if notFound {
			return api.AlreadyDeleted()
		}
		// Deleting
		err := gc.DeleteRealm(ctx, token, realmName)
		if _, notFound := utils.IsNotFound(err); notFound {
			return api.AlreadyDeleted()
		}
		if err != nil {
			return api.Error("Delete", "failed to delete resource", err)
		}
		if err := r.RemoveFinalizer(ctx, i); err != nil {
			return api.Error("Delete", "failed to remove finalizer", err)
		}
		// Deleted
		return api.Deleted()
	}

	// Adding finalizer
	if err := r.AppendFinalizer(ctx, i); err != nil {
		return api.Error("Finalizer", "failed to append finalizer", err)
	}

	// Creation
	if notFound {
		newRealm := i.Spec.Config
		id, err := gc.CreateRealm(ctx, token, newRealm)
		if err != nil {
			return api.Error("Create", "failed to create resource", err)
		}
		if err := r.CustomPatch(ctx, i, "realmId", id, ""); err != nil {
			return err
		}
		return api.Created()
	}

	// Update ID status
	id := utils.Unwrap(realm.ID)
	if err := r.CustomPatch(ctx, i, "realmId", id, i.Status.RealmID); err != nil {
		return err
	}

	// Update
	changelog, err := diff.Diff(i.Spec.Config, *realm)
	if err != nil {
		return api.Error("Update", "failed while doing diff", err)
	}
	if len(changelog) > 0 {
		api.EventUpdate(changelog)
		updatedRealm := i.Spec.Config
		updatedRealm.ID = realm.ID
		if err := gc.UpdateRealm(ctx, token, updatedRealm); err != nil {
			return api.Error("Update", "failed to update resource", err)
		}
		return api.Updated()
	}

	return api.NoChange()
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeycloakRealmReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha2.KeycloakRealm{}).
		Complete(r)
}
