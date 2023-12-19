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

// KeycloakClientRoleMappingReconciler reconciles a KeycloakClientRoleMapping object
type KeycloakClientRoleMappingReconciler struct {
	utils.BaseReconciler
}

//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclientrolemappings,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclientrolemappings/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclientrolemappings/finalizers,verbs=update

func (r *KeycloakClientRoleMappingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	i := &v1alpha2.KeycloakClientRoleMapping{}

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
	if err := r.syncClientRoleMapping(ctx, gc, token, i); err != nil {
		return utils.HandleError(err)
	}

	return ctrl.Result{}, nil
}

func (r *KeycloakClientRoleMappingReconciler) syncClientRoleMapping(ctx context.Context, gc *gocloak.GoCloak, token string, i *v1alpha2.KeycloakClientRoleMapping) error {

	realm := i.Spec.Realm
	clientID := i.Spec.Client
	subject := i.Spec.Subject
	api := r.Api(ctx, i)

	// Fetch Client
	c, err := gc.FindClient(ctx, token, realm, clientID)
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

	// Fetch Client Role
	role, err := gc.FindClientRole(ctx, token, realm, idOfClient, i.Spec.Role)
	serr, notFound = utils.IsNotFound(err)
	if utils.IgnoreNotFound(err) != nil {
		return api.Error("FetchClientRole", "failed to fetch resource", err)
	}
	rid := utils.Unwrap(role.ID)
	// Pre-delete edge case
	if utils.MarkedAsDeleted(i) && utils.HasFinalizer(i) && (notFound || rid == "") {
		return api.AlreadyDeleted()
	}
	// Pending
	if notFound {
		return api.Waiting(serr.Message)
	}
	if rid == "" {
		return api.Waiting("client role not found")
	}
	// Update ID
	if err := r.CustomPatch(ctx, i, "roleID", rid, i.Status.RoleID); err != nil {
		return err
	}

	// Fetch Subject
	sid, err := utils.GetSubjectID(ctx, gc, token, realm, idOfClient, i.Spec.Subject)
	serr, notFound = utils.IsNotFound(err)
	if utils.IgnoreNotFound(err) != nil {
		return api.Error("FetchSubject", "failed to fetch subject", err)
	}
	// Pre-delete edge case
	if utils.MarkedAsDeleted(i) && utils.HasFinalizer(i) && (notFound || sid == "") {
		return api.AlreadyDeleted()
	}
	// Pending
	if notFound {
		return api.Waiting(serr.Message)
	}
	if sid == "" {
		return api.Waiting("subject id not found")
	}
	// Update ID
	if err := r.CustomPatch(ctx, i, "subjectID", sid, i.Status.SubjectID); err != nil {
		return err
	}

	// Roles
	roles, err := utils.GetSubjectRoles(ctx, gc, token, realm, idOfClient, sid, i.Spec.Subject)
	serr, notFound = utils.IsNotFound(err)
	if utils.IgnoreNotFound(err) != nil {
		return api.Error("FetchSubjectRoles", "failed to fetch subject roles", err)
	}
	exist := roleExists(roles, utils.Unwrap(role.Name))

	// Deletion
	if utils.MarkedAsDeleted(i) && utils.HasFinalizer(i) {
		if notFound || !exist {
			return api.AlreadyDeleted()
		}
		// Deleting...
		err := utils.DeleteRoleFromSubject(ctx, gc, token, realm, idOfClient, sid, subject, *role)
		if _, notFound := utils.IsNotFound(err); notFound {
			return api.AlreadyDeleted()
		}
		if err != nil {
			return api.Error("Delete", "failed to delete resource", err)
		}
		return api.Deleted()
	}
	// Adding finalizer
	if err := r.AppendFinalizer(ctx, i); err != nil {
		return api.Error("Finalizer", "failed to append finalizer", err)
	}
	if notFound {
		return api.Waiting(serr.Message)
	}

	// Creation
	if !exist {
		// Creating...
		if err := utils.AddRoleToSubject(ctx, gc, token, realm, idOfClient, sid, subject, *role); err != nil {
			return api.Error("Create", "failed to create resource", err)
		}
		return api.Created()
	}

	// No change
	return api.NoChange()
}

func roleExists(roles []*gocloak.Role, name string) bool {
	for _, r := range roles {
		if *r.Name == name {
			return true
		}
	}
	return false
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeycloakClientRoleMappingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha2.KeycloakClientRoleMapping{}).
		Complete(r)
}
