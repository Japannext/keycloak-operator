package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/japannext/keycloak-operator/api/v1alpha2"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// A api to manage log/event/status related to keycloak API
// resources.
type ApiHelper struct {
	*BaseReconciler
	Context context.Context
	Object  Object
}

const (
	createdMsg        = "successfully created resource"
	updatedMsg        = "successfully updated resource"
	deletedMsg        = "successfully deleted resource"
	alreadyDeletedMsg = "resource was already deleted"
)

func (api *ApiHelper) Created() error {
	log.FromContext(api.Context).Info(createdMsg)
	api.Event(api.Object, "Normal", "Create", createdMsg)
	if err := api.Status().Patch(api.Context, api.Object, makePatch(v1alpha2.SYNCED)); err != nil {
		return fmt.Errorf("failed to patch resource status (create): %w", err)
	}
	return nil
}

func (api *ApiHelper) Updated() error {
	log.FromContext(api.Context).Info(updatedMsg)
	api.Event(api.Object, "Normal", "Update", updatedMsg)
	if err := api.Status().Patch(api.Context, api.Object, makePatch(v1alpha2.SYNCED)); err != nil {
		return fmt.Errorf("failed to patch resource status (update): %w", err)
	}
	return nil
}

func (api *ApiHelper) Deleted() error {
	log.FromContext(api.Context).Info(deletedMsg)
	return api.RemoveFinalizer(api.Context, api.Object)
}

func (api *ApiHelper) AlreadyDeleted() error {
	log.FromContext(api.Context).Info(alreadyDeletedMsg)
	return api.RemoveFinalizer(api.Context, api.Object)
}

func (api *ApiHelper) NoChange() error {
	status := api.Object.ApiStatus()
	if status.Phase != v1alpha2.SYNCED {
		if err := api.Status().Patch(api.Context, api.Object, makePatch(v1alpha2.SYNCED)); err != nil {
			return fmt.Errorf("failed to patch resource status (no-change): %w", err)
		}
	}
	return nil
}

func (api *ApiHelper) Waiting(text string) error {
	msg := fmt.Sprintf("resource waiting due to dependency: %s", text)
	log.FromContext(api.Context).V(2).Info(msg)
	api.Event(api.Object, "Normal", "Waiting", msg)
	status := api.Object.ApiStatus()
	if status.Phase != v1alpha2.WAITING {
		if err := api.Status().Patch(api.Context, api.Object, makePatch(v1alpha2.WAITING)); err != nil {
			return fmt.Errorf("failed to patch resource status (waiting): %w", err)
		}
	}
	return Reschedule{RequeueAfter: 1 * time.Minute}
}

func (api *ApiHelper) Error(action, text string, err error) error {
	msg := fmt.Sprintf("%s: %s", text, err)
	log.FromContext(api.Context).Error(err, text)
	api.Event(api.Object, "Warning", action, msg)
	status := api.Object.ApiStatus()
	if status.Phase != v1alpha2.ERROR {
		if err := api.Status().Patch(api.Context, api.Object, makePatch(v1alpha2.SYNCED)); err != nil {
			return fmt.Errorf("failed to patch resource status (error): %w", err)
		}
	}
	return err
}
