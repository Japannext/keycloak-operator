package utils

import (
	"context"
	"fmt"

	api "github.com/japannext/keycloak-operator/api/v1alpha2"
	gocloak "github.com/japannext/keycloak-operator/gocloak"
)

func AddRoleToSubject(ctx context.Context, gc *gocloak.GoCloak, token, realm, idOfClient, sid string, subject api.Subject, role gocloak.Role) error {
	newRoles := []gocloak.Role{role}
	if subject.Kind == "user" {
		return gc.AddClientRolesToUser(ctx, token, realm, idOfClient, sid, newRoles)
	} else if subject.Kind == "group" {
		return gc.AddClientRolesToGroup(ctx, token, realm, idOfClient, sid, newRoles)
	}
	return fmt.Errorf("unknown kind '%s'", subject.Kind)
}

func DeleteRoleFromSubject(ctx context.Context, gc *gocloak.GoCloak, token, realm, idOfClient, sid string, subject api.Subject, role gocloak.Role) error {
	oldRoles := []gocloak.Role{role}
	if subject.Kind == "user" {
		return gc.DeleteClientRolesFromUser(ctx, token, realm, idOfClient, sid, oldRoles)
	} else if subject.Kind == "group" {
		return gc.DeleteClientRoleFromGroup(ctx, token, realm, idOfClient, sid, oldRoles)
	}
	return fmt.Errorf("unknown kind '%s'", subject.Kind)
}

func GetSubjectID(ctx context.Context, gc *gocloak.GoCloak, token, realm, idOfClient string, subject api.Subject) (string, error) {
	if subject.Kind == "user" {
		users, err := gc.GetUsers(ctx, token, realm, gocloak.GetUsersParams{Username: &subject.Name})
		if err != nil {
			return "", err
		}
		if len(users) == 0 {
			return "", nil
		}
		sid := Unwrap(users[0].ID)
		return sid, nil

	} else if subject.Kind == "group" {
		groups, err := gc.GetGroups(ctx, token, realm, gocloak.GetGroupsParams{Search: &subject.Name})
		if err != nil {
			return "", err
		}
		if len(groups) == 0 {
			return "", nil
		}
		sid := Unwrap(groups[0].ID)
		return sid, nil

	}
	return "", fmt.Errorf("unsupported kind %s", subject.Kind)
}

func GetSubjectRoles(ctx context.Context, gc *gocloak.GoCloak, token, realm, idOfClient, sid string, subject api.Subject) ([]*gocloak.Role, error) {

	if subject.Kind == "user" {
		return gc.GetClientRolesByUserID(ctx, token, realm, idOfClient, sid)

	} else if subject.Kind == "group" {
		return gc.GetClientRolesByGroupID(ctx, token, realm, idOfClient, sid)

	}
	return []*gocloak.Role{}, fmt.Errorf("unsupported kind %s", subject.Kind)
}
