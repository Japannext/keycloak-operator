package utils

import (
	"errors"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/japannext/keycloak-operator/gocloak"
)

type Reschedule struct {
	RequeueAfter time.Duration
}

func (r Reschedule) Error() string {
	return "reschedule"
}

// A wrapper for errors that should not retrigger the reconciler.
type NoReschedule struct{}

func (nr NoReschedule) Error() string {
	return "no-reschedule"
}

func IsNoReschedule(err error) bool {
	return errors.Is(err, NoReschedule{})
}

func HandleError(err error) (ctrl.Result, error) {
	var reschedule *Reschedule
	if errors.As(err, &reschedule) {
		return ctrl.Result{RequeueAfter: reschedule.RequeueAfter}, nil
	}
	if errors.Is(err, NoReschedule{}) {
		return ctrl.Result{}, nil
	}
	if apierrors.IsNotFound(err) {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, err
}

func IsNotFound(err error) (*gocloak.APIError, bool) {
	if err != nil {
		if serr, ok := err.(*gocloak.APIError); ok && serr.Code == 404 {
			return serr, true
		}
	}
	return nil, false
}

func IgnoreNotFound(err error) error {
	if _, notFound := IsNotFound(err); notFound {
		return nil
	}
	return err
}
