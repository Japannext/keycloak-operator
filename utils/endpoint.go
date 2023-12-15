package utils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	api "github.com/japannext/keycloak-operator/api/v1alpha2"
	"github.com/japannext/keycloak-operator/gocloak"
)

// spec, err := ExtractEndpointSpec(ctx, r.Client, i.Spec.Endpoint, ns)
// IsForbidden(spec.Rules)
// gc, err := ExtractEndpointFromSpec(spec)
func extractEndpointSpec(r *BaseReconciler, ctx context.Context, e api.EndpointSelector, ns string) (api.KeycloakEndpointSpec, error) {
	if e.Kind == "KeycloakEndpoint" {
		i := &api.KeycloakEndpoint{}
		err := r.Get(ctx, client.ObjectKey{Namespace: ns, Name: e.Name}, i)
		return i.Spec, err

	} else if e.Kind == "KeycloakClusterEndpoint" {
		i := &api.KeycloakClusterEndpoint{}
		err := r.Get(ctx, client.ObjectKey{Name: e.Name}, i)
		return i.Spec, err

	} else {
		return api.KeycloakEndpointSpec{}, fmt.Errorf("Unsupported kind '%s'", e.Kind)
	}
}

func ExtractEndpointFromSpec(r *BaseReconciler, ctx context.Context, spec api.KeycloakEndpointSpec, ns string) (*gocloak.GoCloak, string, error) {

	username, password, err := extractBasicAuthSecret(r, ctx, spec.BasicAuthSecret, ns)
	if err != nil {
		return &gocloak.GoCloak{}, "", err
	}

	gc := gocloak.NewClient(spec.BaseUrl + spec.BasePath)
	resty := gc.RestyClient()

	tlsConfig := &tls.Config{}
	if spec.TlsInsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}
	if spec.CaConfigMap.Name != "" {
		pem, err := extractConfigMap(r, ctx, spec.CaConfigMap, ns)
		if err != nil {
			return &gocloak.GoCloak{}, "", err
		}
		certs := x509.NewCertPool()
		if ok := certs.AppendCertsFromPEM([]byte(pem)); !ok {
			return &gocloak.GoCloak{}, "", fmt.Errorf("Not a valid PEM certificate in configmap/%s, at key '%s'", spec.CaConfigMap.Name, spec.CaConfigMap.Key)
		}
		tlsConfig.RootCAs = certs
	}
	resty.SetTLSClientConfig(tlsConfig)

	token, err := gc.LoginAdmin(ctx, username, password, spec.Realm)
	if err != nil {
		return &gocloak.GoCloak{}, "", err
	}

	return gc, token.AccessToken, nil
}

// Extract the endpoint, but deal with several kind of errors
func (r *BaseReconciler) ExtractEndpoint(ctx context.Context, i Object) (*gocloak.GoCloak, string, error) {
	log := log.FromContext(ctx)
	base := i.BaseStatus()
	ns := i.GetNamespace()
	realm := i.Realm()
	e := i.Endpoint()
	spec, err := extractEndpointSpec(r, ctx, e, ns)
	if err != nil {
		err = fmt.Errorf("could not find endpoint %s/%s: %w", getKind(i), i.GetName(), err)
		r.Event(i, "Warning", "Endpoint", err.Error())
		patch := client.StrategicMergeFrom(i)
		base.Phase = "NoEndpoint"
		base.Ready = false
		if err := r.Status().Patch(ctx, i, patch); err != nil {
			return nil, "", fmt.Errorf("failed to patch status: %w", err)
		}
		return nil, "", err
	}
	if len(spec.Rules) > 0 {
		if forbidden, ruleName := isForbidden(spec.Rules, i, realm); forbidden {
			if MarkedAsDeleted(i) && HasFinalizer(i) {
				log.Info("Forbidden resource deleted silently")
				return nil, "", NoReschedule{}
			}
			msg := fmt.Sprintf("Rule '%s': namespace '%s' is forbidden to manage '%s' on realm '%s'", ruleName, ns, getKind(i), realm)
			r.Event(i, "Warning", "Authz", msg)
			patch := client.StrategicMergeFrom(i)
			base.Phase = "Forbidden"
			base.Ready = false
			if err := r.Status().Patch(ctx, i, patch); err != nil {
				return nil, "", fmt.Errorf("failed to patch status: %w", err)
			}
			return nil, "", fmt.Errorf(msg)
		}
	}
	if e.Kind == "KeycloakClusterEndpoint" {
		ns = spec.BasicAuthSecret.Namespace
	}
	gc, token, err := ExtractEndpointFromSpec(r, ctx, spec, ns)
	if err != nil {
		err = fmt.Errorf("failed to connect to '%s': %w", spec.BaseUrl, err)
		r.Event(i, "Warning", "Endpoint", err.Error())
		patch := client.StrategicMergeFrom(i)
		base.Phase = "Disconnected"
		base.Ready = false
		if err := r.Status().Patch(ctx, i, patch); err != nil {
			return nil, "", fmt.Errorf("failed to patch status: %w", err)
		}
		return nil, "", Reschedule{}
	}

	return gc, token, nil
}
