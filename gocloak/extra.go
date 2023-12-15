package gocloak

import (
	"context"
	"fmt"
)

func getValue(component map[string][]string, k string) string {
	v, ok := component[k]
	if !ok {
		return ""
	}
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func (gc *GoCloak) TestLDAPConnection(ctx context.Context, token, realm, componentId string, component map[string][]string) error {

	action := map[string]string{
		"action":            "testConnection",
		"authType":          getValue(component, "authType"),
		"bindCredential":    "*********",
		"bindDn":            getValue(component, "bindDn"),
		"componentId":       componentId,
		"connectionTimeout": getValue(component, "connectionTimeout"),
		"connectionUrl":     getValue(component, "connectionUrl"),
		"startTls":          getValue(component, "startTls"),
		"useTruststoreSpi":  getValue(component, "useTruststoreSpi"),
	}

	url := gc.getRealmURL(realm, gc.Config.openIDConnect, "testLDAPConnection")
	resp, err := gc.GetRequestWithBearerAuth(ctx, token).SetBody(action).Post(url)
	if err != nil {
		return err
	}
	switch resp.StatusCode() {
	case 204:
		return nil
	default:
		return fmt.Errorf("")
	}
}

func (gc *GoCloak) TestLDAPAuthentication(ctx context.Context, token, realm, componentId string, component map[string][]string) error {

	action := map[string]string{
		"action":            "testAuthentication",
		"authType":          getValue(component, "authType"),
		"bindCredential":    "*********",
		"bindDn":            getValue(component, "bindDn"),
		"componentId":       componentId,
		"connectionTimeout": getValue(component, "connectionTimeout"),
		"connectionUrl":     getValue(component, "connectionUrl"),
		"startTls":          getValue(component, "startTls"),
		"useTruststoreSpi":  getValue(component, "useTruststoreSpi"),
	}

	url := gc.getRealmURL(realm, gc.Config.openIDConnect, "testLDAPConnection")
	resp, err := gc.GetRequestWithBearerAuth(ctx, token).SetBody(action).Post(url)
	if err != nil {
		return err
	}
	switch resp.StatusCode() {
	case 204:
		return nil
	default:
		return fmt.Errorf("")
	}
}

type LDAPSyncResult struct {
	Ignored bool   `json:"ignored"`
	Added   int    `json:"added"`
	Updated int    `json:"updated"`
	Removed int    `json:"removed"`
	Failed  int    `json:"failed"`
	Status  string `json:"status"`
}

type SyncType string

const (
	FULL_SYNC     SyncType = "triggerFullSync"
	CHANGED_USERS SyncType = "triggerChangedUsersSync"
)

func (gc *GoCloak) SyncUserFederation(ctx context.Context, token, realm, componentId string, action SyncType) (*LDAPSyncResult, error) {
	url := gc.getAdminRealmURL(realm, "user-storage", componentId, "sync")
	url += fmt.Sprintf("?action=%s", action)
	result := &LDAPSyncResult{}
	resp, err := gc.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Post(url)
	if err != nil {
		return &LDAPSyncResult{}, err
	}
	code := resp.StatusCode()
	if code == 200 {
		return result, nil
	}
	return result, fmt.Errorf("Unexpected status code: %d", code)
}
