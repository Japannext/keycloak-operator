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
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	diff "github.com/r3labs/diff/v3"

	"github.com/japannext/keycloak-operator/api/v1alpha2"
	"github.com/japannext/keycloak-operator/gocloak"
	"github.com/japannext/keycloak-operator/utils"
)

const secretDescription = `Secret used for an OpenID connect client to authenticate to the Identity Provider.
Consists of a 'client_id' and a 'client_secret'.`

// KeycloakClientReconciler reconciles a KeycloakClient object
type KeycloakClientReconciler struct {
	utils.BaseReconciler
}

// func (r *KeycloakClientReconciler) GetClient() client.Client          { return r.Client }
// func (r *KeycloakClientReconciler) GetRecorder() record.EventRecorder { return r.Recorder }

//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclients,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclients/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=keycloak.japannext.co.jp,resources=keycloakclients/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch

func (r *KeycloakClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	i := &v1alpha2.KeycloakClient{}

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
	if err := r.syncClient(ctx, gc, token, i); err != nil {
		return utils.HandleError(err)
	}

	// Sync secret
	if err := r.syncSecret(ctx, gc, token, i); err != nil {
		return utils.HandleError(err)
	}

	return ctrl.Result{}, nil
}

func (r *KeycloakClientReconciler) syncClient(ctx context.Context, gc *gocloak.GoCloak, token string, i *v1alpha2.KeycloakClient) error {

	realm := i.Spec.Realm
	clientID := utils.Unwrap(i.Spec.Config.ClientID)

	api := r.Api(ctx, i)

	// Fetch
	c, err := gc.FindClient(ctx, token, realm, clientID)
	serr, notFound := utils.IsNotFound(err)
	if utils.IgnoreNotFound(err) != nil {
		return api.Error("Fetch", "failed to fetch resource", err)
	}
	idOfClient := utils.Unwrap(c.ID)

	// Deletion
	if utils.MarkedAsDeleted(i) && utils.HasFinalizer(i) {
		if notFound || idOfClient == "" {
			return api.AlreadyDeleted()
		}
		// Deleting...
		err := gc.DeleteClient(ctx, token, i.Spec.Realm, idOfClient)
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
	if notFound {
		return api.Waiting(serr.Message)
	}

	// Creation
	if idOfClient == "" {
		newClient := i.Spec.Config
		idOfClient, err := gc.CreateClient(ctx, token, i.Spec.Realm, newClient)
		if err != nil {
			return api.Error("Create", "failed to create resource", err)
		}
		if err := r.CustomPatch(ctx, i, "clientID", idOfClient, ""); err != nil {
			return err
		}
		i.Status.ClientID = idOfClient
		return api.Created()
	}

	// Update ID
	if err := r.CustomPatch(ctx, i, "clientID", idOfClient, i.Status.ClientID); err != nil {
		return err
	}
	// Done to pass the value to syncSecret
	i.Status.ClientID = idOfClient

	// Update
	changelog, err := diff.Diff(i.Spec.Config, *c)
	if err != nil {
		return api.Error("Update", "failed during diff", err)
	}
	if len(changelog) > 0 {
		api.EventUpdate(changelog)
		updatedClient := i.Spec.Config
		updatedClient.ID = &idOfClient
		if err := gc.UpdateClient(ctx, token, i.Spec.Realm, updatedClient); err != nil {
			return api.Error("Update", "failed to update resource", err)
		}
		return api.Updated()
	}

	return api.NoChange()
}

func (r *KeycloakClientReconciler) syncSecret(ctx context.Context, gc *gocloak.GoCloak, token string, i *v1alpha2.KeycloakClient) error {

	// Skipping if being deleted
	if utils.MarkedAsDeleted(i) && utils.HasFinalizer(i) {
		return nil
	}

	realm := i.Spec.Realm
	idOfClient := i.Status.ClientID
	api := r.Api(ctx, i)

	// Fetch keycloak client secret
	clientSecret, err := gc.FetchClientSecret(ctx, token, realm, idOfClient)
	serr, notFound := utils.IsNotFound(err)
	if utils.IgnoreNotFound(err) != nil {
		return api.Error("SecretFetch", "failed to retrieve keycloak client secret", err)
	}

	if notFound {
		return api.Waiting(serr.Message)
	}

	// Fetch secret (if exists)
	secret := &corev1.Secret{}
	err = r.Client.Get(ctx, client.ObjectKey{Name: i.Spec.Secret.Name, Namespace: i.GetNamespace()}, secret)
	// Not found
	if apierrors.IsNotFound(err) {
		secret = newSecret(i, clientSecret)
		controllerutil.SetOwnerReference(i, secret, r.Scheme)
		// Creating...
		if err := r.Client.Create(ctx, secret); err != nil {
			return api.Error("SecretCreate", "failed to create secret", err)
		}

		// Created
		r.Event(i, "Normal", "SecretCreate", "successfully created secret")
		return nil
	}
	if err != nil {
		return api.Error("SecretFetch", "failed to fetch secret", err)
	}

	// Owner reference
	if err := r.AppendOwnerReferences(ctx, secret, i); err != nil {
		return err
	}

	// Update secret if necessary
	changelog := diffSecret(i, secret, clientSecret)
	if len(changelog) > 0 {
		secret.ObjectMeta.Annotations["keycloak.japannext.co.jp/lastChanged"] = time.Now().Format(time.RFC3339)
		if err := r.Client.Update(ctx, secret); err != nil {
			return api.Error("SecretUpdate", "failed to update secret", err)
		}

		r.Event(i, "Normal", "SecretUpdate", "successfully updated secret")
		return nil
	}

	// No change
	return nil
}

func newSecret(i *v1alpha2.KeycloakClient, clientSecret string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      i.Spec.Secret.Name,
			Namespace: i.GetNamespace(),
			Labels:    make(map[string]string),
			Annotations: map[string]string{
				"a8r.io/description":                   secretDescription,
				"keycloak.japannext.co.jp/client":      *i.Spec.Config.ClientID,
				"keycloak.japannext.co.jp/realm":       i.Spec.Realm,
				"keycloak.japannext.co.jp/lastChanged": time.Now().Format(time.RFC3339),
			},
		},
		Type: "keycloak.japannext.co.jp/client-secret",
		Data: map[string][]byte{
			"client_id":     []byte(*i.Spec.Config.ClientID),
			"client_secret": []byte(clientSecret),
		},
	}
}

// Compare a secret to the desired state described in the KeycloakClient
func diffSecret(i *v1alpha2.KeycloakClient, secret *corev1.Secret, clientSecret string) diff.Changelog {
	changes := []diff.Change{}

	b, ok := secret.Data["client_id"]
	x := string(b)
	y := utils.Unwrap(i.Spec.Config.ClientID)
	if !ok {
		changes = append(changes, diff.Change{Type: diff.CREATE, Path: []string{"data", "client_id"}, To: y})
	}
	if x != y {
		changes = append(changes, diff.Change{Type: diff.UPDATE, Path: []string{"data", "client_id"}, From: x, To: y})
	}
	secret.Data["client_id"] = []byte(y)

	b, ok = secret.Data["client_secret"]
	x = string(b)
	y = clientSecret
	if !ok {
		changes = append(changes, diff.Change{Type: diff.CREATE, Path: []string{"data", "client_secret"}, To: "<redacted>"})
	}
	if x != y {
		changes = append(changes, diff.Change{Type: diff.UPDATE, Path: []string{"data", "client_secret"}, From: "<redacted>", To: "<redacted>"})
	}
	secret.Data["client_secret"] = []byte(clientSecret)

	realm, ok := secret.ObjectMeta.Annotations["keycloak.japannext.co.jp/realm"]
	if !ok {
		changes = append(changes, diff.Change{Type: diff.CREATE, Path: []string{"metadata", "annotations", "keycloak.japannext.co.jp/realm"}, To: i.Spec.Realm})
	}
	if realm != i.Spec.Realm {
		changes = append(changes, diff.Change{Type: diff.UPDATE, Path: []string{"metadata", "annotations", "keycloak.japannext.co.jp/realm"}, From: realm, To: i.Spec.Realm})
	}
	metav1.SetMetaDataAnnotation(&secret.ObjectMeta, "keycloak.japannext.co.jp/realm", i.Spec.Realm)

	return changes
}

// SetupWithManager sets up the controller with the Manager.
func (r *KeycloakClientReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha2.KeycloakClient{}).
		Complete(r)
}
