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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"time"
)

// log is for logging in this package.
var keycloakldapfederationlog = logf.Log.WithName("keycloakldapfederation-resource")

func (r *KeycloakLDAPFederation) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

//+kubebuilder:webhook:path=/mutate-keycloak-japannext-co-jp-v1alpha2-keycloakldapfederation,mutating=true,failurePolicy=fail,sideEffects=None,groups=keycloak.japannext.co.jp,resources=keycloakldapfederations,verbs=create;update,versions=v1alpha2,name=mkeycloakldapfederation.kb.io,admissionReviewVersions=v1

var _ webhook.Defaulter = &KeycloakLDAPFederation{}

const _10sec int64 = 10000000000
const _1h int64 = 3600000000000
const _24h int64 = 86400000000000

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *KeycloakLDAPFederation) Default() {

	if r.Spec.Config.ChangedSyncPeriod == nil {
		r.Spec.Config.ChangedSyncPeriod = &metav1.Duration{Duration: time.Duration(_1h)}
	}
	if r.Spec.Config.ConnectionTimeout == nil {
		r.Spec.Config.ConnectionTimeout = &metav1.Duration{Duration: time.Duration(_10sec)}
	}
	if r.Spec.Config.FullSyncPeriod == nil {
		r.Spec.Config.FullSyncPeriod = &metav1.Duration{Duration: time.Duration(_24h)}
	}

}
