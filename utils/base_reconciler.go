package utils

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/japannext/keycloak-operator/api/v1alpha2"
)

type Object interface {
	client.Object
	BaseStatus() *api.BaseStatus
	Endpoint() api.EndpointSelector
	Realm() string
}

type Reconciler interface {
	BaseReconciler
}

type BaseReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	record.EventRecorder
}

func NewReconciler(mgr ctrl.Manager) BaseReconciler {
	return BaseReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		EventRecorder: mgr.GetEventRecorderFor("keycloak-operator"),
	}
}

func (r *BaseReconciler) Api(ctx context.Context, i Object) *ApiHelper {
	return &ApiHelper{
		BaseReconciler: r,
		Context:        ctx,
		Object:         i,
	}
}

// Get the kind of a kubernetes object
func getKind(i Object) string {
	return i.GetObjectKind().GroupVersionKind().Kind
}
