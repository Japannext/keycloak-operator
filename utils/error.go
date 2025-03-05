package utils

import (
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/japannext/keycloak-operator/gocloak"
)

type ReschedulableError struct {
	RequeueAfter time.Duration
	Err          error
}

func (r ReschedulableError) Error() string {
	return fmt.Sprintf("Rescheduling %s later: %s", r.RequeueAfter, r.Err.Error())
}
func (r ReschedulableError) Is(err error) bool {
	_, ok := err.(*ReschedulableError)
	return ok
}
func RescheduleAfter(requeueAfter time.Duration, err error) ReschedulableError {
	return ReschedulableError{
		RequeueAfter: requeueAfter,
		Err:          err,
	}
}
func Reschedule(err error) ReschedulableError {
	return ReschedulableError{
		Err: err,
	}
}

// A wrapper for errors that should not retrigger the reconciler.
type UnReschedulableError struct {
	Err error
}

func (nr UnReschedulableError) Error() string {
	return fmt.Sprintf("will not reschedule: %s", nr.Err.Error())
}
func (nr UnReschedulableError) Is(err error) bool {
	_, ok := err.(*UnReschedulableError)
	return ok
}
func DoNotReschedule(err error) UnReschedulableError {
	return UnReschedulableError{Err: err}
}

func HandleError(err error) (ctrl.Result, error) {
	var rerr ReschedulableError
	if errors.As(err, &rerr) {
		return ctrl.Result{RequeueAfter: rerr.RequeueAfter}, nil
	}
	if errors.Is(err, &UnReschedulableError{}) {
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
