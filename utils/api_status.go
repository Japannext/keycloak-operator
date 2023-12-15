package utils

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// A helper to manage log/event/status related to keycloak API
// resources.
type ApiHelper struct {
	*BaseReconciler
	Context context.Context
	Object  Object
}

func getCondition(conditions []metav1.Condition, name string) (bool, *metav1.Condition) {
	for _, condition := range conditions {
		if condition.Type == name {
			return true, &condition
		}
	}
	return false, nil
}

const (
	keycloakApi       = "KeycloakApi"
	createdMsg        = "successfully created resource"
	updatedMsg        = "successfully updated resource"
	deletedMsg        = "successfully deleted resource"
	alreadyDeletedMsg = "resource was already deleted"
)

func (api *ApiHelper) Created() error {
	log.FromContext(api.Context).Info(createdMsg)
	api.Event(api.Object, "Normal", "Create", createdMsg)
	conditions := api.Object.BaseStatus().Conditions
	found, condition := getCondition(conditions, keycloakApi)
	if !found {
		conditions = append(conditions, metav1.Condition{})
		condition = &conditions[len(conditions)-1]
	}
	condition.Type = keycloakApi
	condition.Reason = "Created"
	condition.LastTransitionTime = *Now()
	condition.Message = createdMsg
	condition.Status = metav1.ConditionTrue

	return nil
}

func (api *ApiHelper) Updated() error {
	log.FromContext(api.Context).Info(updatedMsg)
	api.Event(api.Object, "Normal", "Update", updatedMsg)
	conditions := api.Object.BaseStatus().Conditions
	found, condition := getCondition(conditions, keycloakApi)
	if !found {
		conditions = append(conditions, metav1.Condition{})
		condition = &conditions[len(conditions)-1]
	}
	condition.Type = keycloakApi
	condition.Reason = "Updated"
	condition.LastTransitionTime = *Now()
	condition.Message = updatedMsg
	condition.Status = metav1.ConditionTrue

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
	conditions := api.Object.BaseStatus().Conditions
	found, condition := getCondition(conditions, keycloakApi)
	if !found {
		conditions = append(conditions, metav1.Condition{})
		condition = &conditions[len(conditions)-1]
	}
	switch condition.Reason {
	case "Created", "Updated":
		// pass
	default:
		condition.Type = keycloakApi
		condition.Reason = "Synced"
		condition.LastTransitionTime = *Now()
		condition.Message = "resource is in-sync"
		condition.Status = metav1.ConditionTrue
	}
	return nil
}

func (api *ApiHelper) Waiting(text string) error {
	msg := fmt.Sprintf("resource waiting due to dependency: %s", text)
	log.FromContext(api.Context).V(2).Info(msg)
	api.Event(api.Object, "Normal", "Waiting", msg)
	conditions := api.Object.BaseStatus().Conditions
	found, condition := getCondition(conditions, keycloakApi)
	if !found {
		conditions = append(conditions, metav1.Condition{})
		condition = &conditions[len(conditions)-1]
	}
	if condition.Reason != "Waiting" || condition.Message != msg {
		condition.Type = keycloakApi
		condition.Reason = "Waiting"
		condition.LastTransitionTime = *Now()
		condition.Message = msg
		condition.Status = metav1.ConditionFalse
	}
	return Reschedule{}
}

func (api *ApiHelper) Error(action, text string, err error) error {
	msg := fmt.Sprintf("%s: %s", text, err)
	log.FromContext(api.Context).Error(err, text)
	api.Event(api.Object, "Warning", action, msg)
	conditions := api.Object.BaseStatus().Conditions
	found, condition := getCondition(conditions, keycloakApi)
	if found {
		conditions = append(conditions, metav1.Condition{})
		condition = &conditions[len(conditions)-1]
	}
	if condition.Reason != "Error" || condition.Message != msg {
		condition.Type = keycloakApi
		condition.Reason = "Error"
		condition.LastTransitionTime = *Now()
		condition.Message = msg
		condition.Status = metav1.ConditionFalse
	}
	return err
}
