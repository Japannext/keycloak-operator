package utils

import (
	"context"

	"github.com/japannext/keycloak-operator/gocloak"
)

type LDAPSync struct {
	Changed      bool
	Realm        string
	FederationID string
}

func (r *BaseReconciler) SyncLDAP(ctx context.Context, gc *gocloak.GoCloak, token string, i Object, ldap LDAPSync) error {
	_, err := gc.SyncUserFederation(ctx, token, ldap.Realm, ldap.FederationID, gocloak.FULL_SYNC)
	if err != nil {
		return r.Api(ctx, i).Error("LDAPSync", "failed to sync user federation", err)
	}
	r.Event(i, "Normal", "LDAPSync", "Successfully synced LDAP federation")
	return nil
}
