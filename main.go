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

package main

import (
	"flag"
	"os"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"go.uber.org/zap/zapcore"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	keycloakv1alpha2 "github.com/japannext/keycloak-operator/api/v1alpha2"
	"github.com/japannext/keycloak-operator/controllers"
	"github.com/japannext/keycloak-operator/utils"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(keycloakv1alpha2.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var syncPeriod time.Duration

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.DurationVar(&syncPeriod, "sync-period", time.Duration(int64(15*60*1000*1000*1000)), "The duration between forced sync. "+
		"Supported format: <number><ns|us|ms|s|m|h>. Defaults to 15min.")

	opts := zap.Options{
		Development: true,
		Level:       zapcore.Level(-5),
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	options := ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		SyncPeriod:             &syncPeriod,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "d4804880.japannext.co.jp",
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), options)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&controllers.KeycloakEndpointReconciler{
		BaseReconciler: utils.NewReconciler(mgr),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeycloakEndpoint")
		os.Exit(1)
	}
	if err = (&controllers.KeycloakClusterEndpointReconciler{
		BaseReconciler: utils.NewReconciler(mgr),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeycloakClusterEndpoint")
		os.Exit(1)
	}
	if err = (&controllers.KeycloakRealmReconciler{
		BaseReconciler: utils.NewReconciler(mgr),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeycloakRealm")
		os.Exit(1)
	}
	if err = (&keycloakv1alpha2.KeycloakRealm{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "KeycloakRealm")
		os.Exit(1)
	}
	if err = (&controllers.KeycloakClientReconciler{
		BaseReconciler: utils.NewReconciler(mgr),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeycloakClient")
		os.Exit(1)
	}
	if err = (&keycloakv1alpha2.KeycloakClient{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "KeycloakClient")
		os.Exit(1)
	}
	if err = (&controllers.KeycloakClientRoleReconciler{
		BaseReconciler: utils.NewReconciler(mgr),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeycloakClientRole")
		os.Exit(1)
	}
	if err = (&keycloakv1alpha2.KeycloakClientRole{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "KeycloakClientRole")
		os.Exit(1)
	}
	if err = (&controllers.KeycloakClientRoleMappingReconciler{
		BaseReconciler: utils.NewReconciler(mgr),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeycloakClientRoleMapping")
		os.Exit(1)
	}

	if err = (&controllers.KeycloakLDAPFederationReconciler{
		BaseReconciler: utils.NewReconciler(mgr),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeycloakLDAPFederation")
		os.Exit(1)
	}
	if err = (&keycloakv1alpha2.KeycloakLDAPFederation{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "KeycloakLDAPFederation")
		os.Exit(1)
	}
	if err = (&controllers.KeycloakLDAPMapperReconciler{
		BaseReconciler: utils.NewReconciler(mgr),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeycloakLDAPMapper")
		os.Exit(1)
	}
	if err = (&controllers.KeycloakClientScopeReconciler{
		BaseReconciler: utils.NewReconciler(mgr),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeycloakClientScope")
		os.Exit(1)
	}
	if err = (&controllers.KeycloakClientScopeProtocolMapperReconciler{
		BaseReconciler: utils.NewReconciler(mgr),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeycloakClientScopeProtocolMapper")
		os.Exit(1)
	}
	if err = (&controllers.KeycloakClientProtocolMapperReconciler{
		BaseReconciler: utils.NewReconciler(mgr),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeycloakClientProtocolMapper")
		os.Exit(1)
	}
	if err = (&controllers.KeycloakRealmRoleReconciler{
		BaseReconciler: utils.NewReconciler(mgr),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeycloakRealmRole")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
