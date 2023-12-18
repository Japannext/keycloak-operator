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

package v1alpha2

import (
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// log is for logging in this package.
var keycloakclientlog = logf.Log.WithName("keycloakclient-resource")

func (r *KeycloakClient) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

//+kubebuilder:webhook:path=/mutate-keycloak-japannext-co-jp-v1alpha2-keycloakclient,mutating=true,failurePolicy=fail,sideEffects=None,groups=keycloak.japannext.co.jp,resources=keycloakclients,verbs=create;update,versions=v1alpha2,name=mkeycloakclient.kb.io,admissionReviewVersions=v1

var _ webhook.Defaulter = &KeycloakClient{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *KeycloakClient) Default() {
	keycloakclientlog.Info("default", "name", r.Name)

	if Unwrap(r.Spec.Config.ClientID) == "" {
		r.Spec.Config.ClientID = Ptr(r.ObjectMeta.Name)
	}

	// Default name is clientID name
	if Unwrap(r.Spec.Config.Name) == "" {
		r.Spec.Config.Name = r.Spec.Config.ClientID
	}

	if len(Unwrap(r.Spec.Config.Access)) == 0 {
		r.Spec.Config.Access = Ptr(map[string]bool{"view": true, "configure": true, "manage": true})
	}

	if r.Spec.Config.AuthenticationFlowBindingOverrides == nil {
		r.Spec.Config.AuthenticationFlowBindingOverrides = Ptr(map[string]string{})
	}

	if r.Spec.Config.RedirectURIs == nil {
		r.Spec.Config.RedirectURIs = Ptr([]string{})
	}
	if r.Spec.Config.DefaultClientScopes == nil {
		r.Spec.Config.DefaultClientScopes = Ptr([]string{})
	}
	if r.Spec.Config.WebOrigins == nil {
		r.Spec.Config.WebOrigins = Ptr([]string{})
	}

	// Automatically fill-in the secret name by default.
	// Not using secret generation is the exception rather than the rule, so let's
	// make the defaults automatic.
	if r.Spec.Secret.Name == "" && r.Spec.Secret.Enabled {
		r.Spec.Secret.Name = fmt.Sprintf("%s-oidc-secret", r.ObjectMeta.Name)
	}

}
