package utils

import (
	"github.com/japannext/keycloak-operator/gocloak"
)

func (api *ApiHelper) SyncLDAP(gc *gocloak.GoCloak, token, realm, id string) error {
	_, err := gc.SyncUserFederation(api.Context, token, realm, id, gocloak.FULL_SYNC)
	if err != nil {
		return api.Error("LDAPSync", "failed to sync user federation", err)
	}
	api.Event(api.Object, "Normal", "LDAPSync", "Successfully synced LDAP federation")
	return nil
}
