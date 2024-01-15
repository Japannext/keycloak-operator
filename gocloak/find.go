package gocloak

import (
	"context"
)

func (gc *GoCloak) FindClient(ctx context.Context, token, realm, clientID string) (*Client, error) {
	items, err := gc.GetClients(ctx, token, realm, GetClientsParams{ClientID: &clientID})
	if err != nil {
		return &Client{}, err
	}
	for _, c := range items {
		if *c.ClientID == clientID {
			return c, nil
		}
	}
	return &Client{}, nil
}

func (gc *GoCloak) FindClientRole(ctx context.Context, token string, realm, idOfClient, roleName string) (*Role, error) {
	items, err := gc.GetClientRoles(ctx, token, realm, idOfClient, GetRoleParams{Search: &roleName})
	if err != nil {
		return &Role{}, nil
	}
	for _, role := range items {
		if *role.Name == roleName {
			return role, nil
		}
	}
	return &Role{}, nil
}

func (gc *GoCloak) FetchClientSecret(ctx context.Context, token, realm, idOfClient string) (string, error) {
	creds, err := gc.GetClientSecret(ctx, token, realm, idOfClient)
	if err != nil {
		return "", err
	}
	if creds.Value == nil {
		return "", nil
	}
	return *creds.Value, nil
}

func (gc *GoCloak) FindComponent(ctx context.Context, token, realm, providerType, providerId, name, parentId string) (*Component, error) {
	params := GetComponentsParams{Name: &name, ProviderType: &providerType}
	if parentId != "" {
		params.ParentID = &parentId
	}
	items, err := gc.GetComponentsWithParams(ctx, token, realm, params)
	if err != nil {
		return &Component{}, err
	}

	for _, item := range items {
		if *item.Name == name && *item.ProviderID == providerId {
			return item, nil
		}
	}
	return &Component{}, nil
}

func (gc *GoCloak) FindClientScope(ctx context.Context, token, realm, name string) (*ClientScope, error) {
	scopes, err := gc.GetClientScopes(ctx, token, realm)
	if err != nil {
		return &ClientScope{}, err
	}
	for _, scope := range scopes {
		if *scope.Name == name {
			return scope, nil
		}
	}
	return &ClientScope{}, nil
}

func (gc *GoCloak) FindClientProtocolMapper(ctx context.Context, token, realm string, c *Client, name string) (*ProtocolMapper, error) {
	items := *c.ProtocolMappers
	for _, pm := range items {
		if *pm.Name == name {
			return &pm, nil
		}
	}
	return &ProtocolMapper{}, nil
}

func (gc *GoCloak) FindClientScopeProtocolMapper(ctx context.Context, token, realm, scopeID, name string) (*ProtocolMapper, error) {
	items, err := gc.GetClientScopeProtocolMappers(ctx, token, realm, scopeID)
	if err != nil {
		return &ProtocolMapper{}, err
	}
	for _, pm := range items {
		if *pm.Name == name {
			return pm, nil
		}
	}
	return &ProtocolMapper{}, nil
}
