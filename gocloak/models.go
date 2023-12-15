package gocloak

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// GetQueryParams converts the struct to map[string]string
// The fields tags must have `json:"<name>,string,omitempty"` format for all types, except strings
// The string fields must have: `json:"<name>,omitempty"`. The `json:"<name>,string,omitempty"` tag for string field
// will add additional double quotes.
// "string" tag allows to convert the non-string fields of a structure to map[string]string.
// "omitempty" allows to skip the fields with default values.
func GetQueryParams(s interface{}) (map[string]string, error) {
	// if obj, ok := s.(GetGroupsParams); ok {
	// 	obj.OnMarshal()
	// 	s = obj
	// }
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var res map[string]string
	err = json.Unmarshal(b, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// StringOrArray represents a value that can either be a string or an array of strings
type StringOrArray []string

// UnmarshalJSON unmarshals a string or an array object from a JSON array or a JSON string
func (s *StringOrArray) UnmarshalJSON(data []byte) error {
	if len(data) > 1 && data[0] == '[' {
		var obj []string
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		*s = StringOrArray(obj)
		return nil
	}

	var obj string
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*s = StringOrArray([]string{obj})
	return nil
}

// MarshalJSON converts the array of strings to a JSON array or JSON string if there is only one item in the array
func (s *StringOrArray) MarshalJSON() ([]byte, error) {
	if len(*s) == 1 {
		return json.Marshal([]string(*s)[0])
	}
	return json.Marshal([]string(*s))
}

// EnforcedString can be used when the expected value is string but Keycloak in some cases gives you mixed types
type EnforcedString string

// UnmarshalJSON modify data as string before json unmarshal
func (s *EnforcedString) UnmarshalJSON(data []byte) error {
	if data[0] != '"' {
		// Escape unescaped quotes
		data = bytes.ReplaceAll(data, []byte(`"`), []byte(`\"`))
		data = bytes.ReplaceAll(data, []byte(`\\"`), []byte(`\"`))

		// Wrap data in quotes
		data = append([]byte(`"`), data...)
		data = append(data, []byte(`"`)...)
	}

	var val string
	err := json.Unmarshal(data, &val)
	*s = EnforcedString(val)
	return err
}

// MarshalJSON return json marshal
func (s *EnforcedString) MarshalJSON() ([]byte, error) {
	return json.Marshal(*s)
}

// APIErrType is a field containing more specific API error types
// that may be checked by the receiver.
type APIErrType string

const (
	// APIErrTypeUnknown is for API errors that are not strongly
	// typed.
	APIErrTypeUnknown APIErrType = "unknown"

	// APIErrTypeInvalidGrant corresponds with Keycloak's
	// OAuthErrorException due to "invalid_grant".
	APIErrTypeInvalidGrant = "oauth: invalid grant"
)

// ParseAPIErrType is a convenience method for returning strongly
// typed API errors.
func ParseAPIErrType(err error) APIErrType {
	if err == nil {
		return APIErrTypeUnknown
	}
	switch {
	case strings.Contains(err.Error(), "invalid_grant"):
		return APIErrTypeInvalidGrant
	default:
		return APIErrTypeUnknown
	}
}

// APIError holds message and statusCode for api errors
type APIError struct {
	Code    int        `json:"code"`
	Message string     `json:"message"`
	Type    APIErrType `json:"type"`
}

// Error stringifies the APIError
func (apiError APIError) Error() string {
	return apiError.Message
}

// CertResponseKey is returned by the certs endpoint.
// JSON Web Key structure is described here:
// https://self-issued.info/docs/draft-ietf-jose-json-web-key.html#JWKContents
type CertResponseKey struct {
	Kid     *string   `json:"kid,omitempty"`
	Kty     *string   `json:"kty,omitempty"`
	Alg     *string   `json:"alg,omitempty"`
	Use     *string   `json:"use,omitempty"`
	N       *string   `json:"n,omitempty"`
	E       *string   `json:"e,omitempty"`
	X       *string   `json:"x,omitempty"`
	Y       *string   `json:"y,omitempty"`
	Crv     *string   `json:"crv,omitempty"`
	KeyOps  *[]string `json:"key_ops,omitempty"`
	X5u     *string   `json:"x5u,omitempty"`
	X5c     *[]string `json:"x5c,omitempty"`
	X5t     *string   `json:"x5t,omitempty"`
	X5tS256 *string   `json:"x5t#S256,omitempty"`
}

// CertResponse is returned by the certs endpoint
type CertResponse struct {
	Keys *[]CertResponseKey `json:"keys,omitempty"`
}

// IssuerResponse is returned by the issuer endpoint
type IssuerResponse struct {
	Realm           *string `json:"realm,omitempty"`
	PublicKey       *string `json:"public_key,omitempty"`
	TokenService    *string `json:"token-service,omitempty"`
	AccountService  *string `json:"account-service,omitempty"`
	TokensNotBefore *int    `json:"tokens-not-before,omitempty"`
}

// ResourcePermission represents a permission granted to a resource
type ResourcePermission struct {
	RSID           *string   `json:"rsid,omitempty"`
	ResourceID     *string   `json:"resource_id,omitempty"`
	RSName         *string   `json:"rsname,omitempty"`
	Scopes         *[]string `json:"scopes,omitempty"`
	ResourceScopes *[]string `json:"resource_scopes,omitempty"`
}

// PermissionResource represents a resources asscoiated with a permission
type PermissionResource struct {
	ResourceID   *string `json:"_id,omitempty"`
	ResourceName *string `json:"name,omitempty"`
}

// PermissionScope represents scopes associated with a permission
type PermissionScope struct {
	ScopeID   *string `json:"id,omitempty"`
	ScopeName *string `json:"name,omitempty"`
}

// IntroSpectTokenResult is returned when a token was checked
type IntroSpectTokenResult struct {
	Permissions *[]ResourcePermission `json:"permissions,omitempty"`
	Exp         *int                  `json:"exp,omitempty"`
	Nbf         *int                  `json:"nbf,omitempty"`
	Iat         *int                  `json:"iat,omitempty"`
	Aud         *StringOrArray        `json:"aud,omitempty"`
	Active      *bool                 `json:"active,omitempty"`
	AuthTime    *int                  `json:"auth_time,omitempty"`
	Jti         *string               `json:"jti,omitempty"`
	Type        *string               `json:"typ,omitempty"`
}

// User represents the Keycloak User Structure
type User struct {
	ID                         *string                     `json:"id,omitempty"`
	CreatedTimestamp           *int64                      `json:"createdTimestamp,omitempty"`
	Username                   *string                     `json:"username,omitempty"`
	Enabled                    *bool                       `json:"enabled,omitempty"`
	Totp                       *bool                       `json:"totp,omitempty"`
	EmailVerified              *bool                       `json:"emailVerified,omitempty"`
	FirstName                  *string                     `json:"firstName,omitempty"`
	LastName                   *string                     `json:"lastName,omitempty"`
	Email                      *string                     `json:"email,omitempty"`
	FederationLink             *string                     `json:"federationLink,omitempty"`
	Attributes                 *map[string][]string        `json:"attributes,omitempty"`
	DisableableCredentialTypes *[]interface{}              `json:"disableableCredentialTypes,omitempty"`
	RequiredActions            *[]string                   `json:"requiredActions,omitempty"`
	Access                     *map[string]bool            `json:"access,omitempty"`
	ClientRoles                *map[string][]string        `json:"clientRoles,omitempty"`
	RealmRoles                 *[]string                   `json:"realmRoles,omitempty"`
	Groups                     *[]string                   `json:"groups,omitempty"`
	ServiceAccountClientID     *string                     `json:"serviceAccountClientId,omitempty"`
	Credentials                *[]CredentialRepresentation `json:"credentials,omitempty"`
}

// SetPasswordRequest sets a new password
type SetPasswordRequest struct {
	Type      *string `json:"type,omitempty"`
	Temporary *bool   `json:"temporary,omitempty"`
	Password  *string `json:"value,omitempty"`
}

// Component is a component
type Component struct {
	ID              *string              `json:"id,omitempty"`
	Name            *string              `json:"name,omitempty"`
	ProviderID      *string              `json:"providerId,omitempty"`
	ProviderType    *string              `json:"providerType,omitempty"`
	ParentID        *string              `json:"parentId,omitempty"`
	ComponentConfig *map[string][]string `json:"config,omitempty"`
	SubType         *string              `json:"subType,omitempty"`
}

// KeyStoreConfig holds the keyStoreConfig
type KeyStoreConfig struct {
	ActiveKeys *ActiveKeys `json:"active,omitempty"`
	Key        *[]Key      `json:"keys,omitempty"`
}

// ActiveKeys holds the active keys
type ActiveKeys struct {
	HS256 *string `json:"HS256,omitempty"`
	RS256 *string `json:"RS256,omitempty"`
	AES   *string `json:"AES,omitempty"`
}

// Key is a key
type Key struct {
	ProviderID       *string `json:"providerId,omitempty"`
	ProviderPriority *int    `json:"providerPriority,omitempty"`
	Kid              *string `json:"kid,omitempty"`
	Status           *string `json:"status,omitempty"`
	Type             *string `json:"type,omitempty"`
	Algorithm        *string `json:"algorithm,omitempty"`
	PublicKey        *string `json:"publicKey,omitempty"`
	Certificate      *string `json:"certificate,omitempty"`
}

// Attributes holds Attributes
type Attributes struct {
	LDAPENTRYDN *[]string `json:"LDAP_ENTRY_DN,omitempty"`
	LDAPID      *[]string `json:"LDAP_ID,omitempty"`
}

// Access represents access
type Access struct {
	ManageGroupMembership *bool `json:"manageGroupMembership,omitempty"`
	View                  *bool `json:"view,omitempty"`
	MapRoles              *bool `json:"mapRoles,omitempty"`
	Impersonate           *bool `json:"impersonate,omitempty"`
	Manage                *bool `json:"manage,omitempty"`
}

// UserGroup is a UserGroup
type UserGroup struct {
	ID   *string `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
	Path *string `json:"path,omitempty"`
}

// GetUsersParams represents the optional parameters for getting users
type GetUsersParams struct {
	BriefRepresentation *bool   `json:"briefRepresentation,string,omitempty"`
	Email               *string `json:"email,omitempty"`
	EmailVerified       *bool   `json:"emailVerified,string,omitempty"`
	Enabled             *bool   `json:"enabled,string,omitempty"`
	Exact               *bool   `json:"exact,string,omitempty"`
	First               *int    `json:"first,string,omitempty"`
	FirstName           *string `json:"firstName,omitempty"`
	IDPAlias            *string `json:"idpAlias,omitempty"`
	IDPUserID           *string `json:"idpUserId,omitempty"`
	LastName            *string `json:"lastName,omitempty"`
	Max                 *int    `json:"max,string,omitempty"`
	Q                   *string `json:"q,omitempty"`
	Search              *string `json:"search,omitempty"`
	Username            *string `json:"username,omitempty"`
}

// GetComponentsParams represents the optional parameters for getting components
type GetComponentsParams struct {
	Name         *string `json:"name,omitempty"`
	ProviderType *string `json:"provider,omitempty"`
	ParentID     *string `json:"parent,omitempty"`
}

// ExecuteActionsEmail represents parameters for executing action emails
type ExecuteActionsEmail struct {
	UserID      *string   `json:"-"`
	ClientID    *string   `json:"client_id,omitempty"`
	Lifespan    *int      `json:"lifespan,string,omitempty"`
	RedirectURI *string   `json:"redirect_uri,omitempty"`
	Actions     *[]string `json:"-"`
}

// SendVerificationMailParams is being used to send verification params
type SendVerificationMailParams struct {
	ClientID    *string
	RedirectURI *string
}

// Group is a Group
type Group struct {
	ID          *string              `json:"id,omitempty"`
	Name        *string              `json:"name,omitempty"`
	Path        *string              `json:"path,omitempty"`
	SubGroups   *[]Group             `json:"subGroups,omitempty"`
	Attributes  *map[string][]string `json:"attributes,omitempty"`
	Access      *map[string]bool     `json:"access,omitempty"`
	ClientRoles *map[string][]string `json:"clientRoles,omitempty"`
	RealmRoles  *[]string            `json:"realmRoles,omitempty"`
}

// GroupsCount represents the groups count response from keycloak
type GroupsCount struct {
	Count int `json:"count,omitempty"`
}

// GetGroupsParams represents the optional parameters for getting groups
type GetGroupsParams struct {
	BriefRepresentation *bool   `json:"briefRepresentation,string,omitempty"`
	Exact               *bool   `json:"exact,string,omitempty"`
	First               *int    `json:"first,string,omitempty"`
	Full                *bool   `json:"full,string,omitempty"`
	Max                 *int    `json:"max,string,omitempty"`
	Q                   *string `json:"q,omitempty"`
	Search              *string `json:"search,omitempty"`
}

// MarshalJSON is a custom json marshaling function to automatically set the Full and BriefRepresentation properties
// for backward compatibility
func (obj GetGroupsParams) MarshalJSON() ([]byte, error) {
	type Alias GetGroupsParams
	a := (Alias)(obj)
	if a.BriefRepresentation != nil {
		a.Full = BoolP(!*a.BriefRepresentation)
	} else if a.Full != nil {
		a.BriefRepresentation = BoolP(!*a.Full)
	}
	return json.Marshal(a)
}

// CompositesRepresentation represents the composite roles of a role
// +kubebuilder:object:generate=true
type CompositesRepresentation struct {
	Client *map[string][]string `json:"client,omitempty"`
	Realm  *[]string            `json:"realm,omitempty"`
}

// Role is a role
// +kubebuilder:object:generate=true
type Role struct {
	// +optional
	ID *string `json:"id,omitempty" diff:"-"`
	// +required
	Name *string `json:"name,omitempty" diff:"name"`
	// +optional
	ScopeParamRequired *bool `json:"scopeParamRequired,omitempty" diff:"scopeParamRequired"`
	// +kubebuilder:default=false
	Composite *bool `json:"composite,omitempty" diff:"composite"`
	// +optional
	Composites *CompositesRepresentation `json:"composites,omitempty" diff:"composites"`
	// +optional
	ClientRole *bool `json:"clientRole,omitempty" diff:"clientRole"`
	// +optional
	ContainerID *string `json:"containerId,omitempty" diff:"-"`
	// +kubebuilder:default=""
	Description *string `json:"description,omitempty" diff:"description"`
	// +optional
	Attributes *map[string][]string `json:"attributes,omitempty" diff:"-"`
}

// GetRoleParams represents the optional parameters for getting roles
type GetRoleParams struct {
	First               *int    `json:"first,string,omitempty"`
	Max                 *int    `json:"max,string,omitempty"`
	Search              *string `json:"search,omitempty"`
	BriefRepresentation *bool   `json:"briefRepresentation,string,omitempty"`
}

// ClientMappingsRepresentation is a client role mappings
type ClientMappingsRepresentation struct {
	ID       *string `json:"id,omitempty"`
	Client   *string `json:"client,omitempty"`
	Mappings *[]Role `json:"mappings,omitempty"`
}

// MappingsRepresentation is a representation of role mappings
type MappingsRepresentation struct {
	ClientMappings map[string]*ClientMappingsRepresentation `json:"clientMappings,omitempty"`
	RealmMappings  *[]Role                                  `json:"realmMappings,omitempty"`
}

// ClientScope is a ClientScope
// +kubebuilder:object:generate=true
type ClientScope struct {
	// +optional
	ID *string `json:"id,omitempty" diff:"-"`
	// +required
	Name *string `json:"name,omitempty" diff:"name"`
	// +kubebuilder:default=""
	Description *string `json:"description,omitempty" diff:"description"`
	// +kubebuilder:validation:Enum=openid-connect;saml
	// +kubebuilder:default="openid-connect"
	Protocol              *string                `json:"protocol,omitempty" diff:"protocol"`
	ClientScopeAttributes *ClientScopeAttributes `json:"attributes,omitempty" diff:"attributes"`
	ProtocolMappers       *[]ProtocolMapper      `json:"protocolMappers,omitempty" diff:"-"`
}

// ClientScopeAttributes are attributes of client scopes
// +kubebuilder:object:generate=true
type ClientScopeAttributes struct {
	ConsentScreenText      *string `json:"consent.screen.text,omitempty" diff:"consent.screen.text"`
	DisplayOnConsentScreen *string `json:"display.on.consent.screen,omitempty" diff:"display.on.consent.screen"`
	IncludeInTokenScope    *string `json:"include.in.token.scope,omitempty" diff:"include.in.token.scope"`
}

// ProtocolMapper representation
// +kubebuilder:object:generate=true
type ProtocolMapper struct {
	// +optional
	Config *map[string]string `json:"config,omitempty" diff:"config"`
	// +optional
	ID *string `json:"id,omitempty" diff:"-"`
	// +required
	Name *string `json:"name,omitempty" diff:"name"`
	// +required
	Protocol *string `json:"protocol,omitempty" diff:"protocol"`
	// +kubebuilder:validation:Enum=oidc-acr-mapper;oidc-address-mapper;oidc-allowed-origins-mapper;oidc-audience-mapper;oidc-audience-resolve-mapper;oidc-claims-param-token-mapper;oidc-full-name-mapper;oidc-group-membership-mapper;oidc-hardcoded-claim-mapper;oidc-hardcoded-role-mapper;oidc-role-name-mapper;oidc-sha256-pairwise-sub-mapper;oidc-usermodel-attribute-mapper;oidc-usermodel-client-role-mapper;oidc-usermodel-property-mapper;oidc-usermodel-realm-role-mapper;oidc-usersessionmodel-note-mapper
	// +required
	ProtocolMapper *string `json:"protocolMapper,omitempty" diff:"protocolMapper"`
	// +kubebuilder:default=false
	ConsentRequired *bool `json:"consentRequired,omitempty" diff:"consentRequired"`
}

// Client is a ClientRepresentation
// +kubebuilder:object:generate=true
type Client struct {
	// Access options.
	// +optional
	Access *map[string]bool `json:"access,omitempty" diff:"access"`
	// Application Admin URL.
	// +kubebuilder:default=""
	AdminURL *string `json:"adminUrl,omitempty" diff:"adminUrl"`
	// Client Attributes.
	// +optional
	Attributes *map[string]string `json:"attributes,omitempty" diff:"-"`
	// Authentication Flow Binding Overrides.
	// +optional
	AuthenticationFlowBindingOverrides *map[string]string `json:"authenticationFlowBindingOverrides,omitempty" diff:"authenticationFlowBindingOverrides"`
	// True if fine-grained authorization support is enabled for this client.
	// +optional
	AuthorizationServicesEnabled *bool `json:"authorizationServicesEnabled,omitempty" diff:"authorizationServicesEnabled"`
	// Authorization settings for this resource server.
	// +optional
	AuthorizationSettings *ResourceServerRepresentation `json:"authorizationSettings,omitempty" diff:"authorizationSettings"`
	// // +kubebuilder:default=""
	BaseURL *string `json:"baseUrl,omitempty" diff:"baseUrl"`
	// +kubebuilder:default=false
	BearerOnly *bool `json:"bearerOnly,omitempty" diff:"bearerOnly"`
	// +kubebuilder:default=client-secret
	ClientAuthenticatorType *string `json:"clientAuthenticatorType,omitempty" diff:"clientAuthenticatorType"`
	// +optional
	ClientID *string `json:"clientId,omitempty" diff:"clientId"`
	// +kubebuilder:default=false
	ConsentRequired *bool `json:"consentRequired,omitempty" diff:"consentRequired"`
	// +optional
	DefaultClientScopes *[]string `json:"defaultClientScopes,omitempty" diff:"defaultClientScopes"`
	// +kubebuilder:default=""
	Description *string `json:"description,omitempty" diff:"description"`
	// +kubebuilder:default=false
	DirectAccessGrantsEnabled *bool `json:"directAccessGrantsEnabled,omitempty" diff:"directAccessGrantsEnabled"`
	// +kubebuilder:default=true
	Enabled *bool `json:"enabled,omitempty" diff:"enabled"`
	// +kubebuilder:default=false
	FrontChannelLogout *bool `json:"frontchannelLogout,omitempty" diff:"frontchannelLogout"`
	// +kubebuilder:default=true
	FullScopeAllowed *bool `json:"fullScopeAllowed,omitempty" diff:"fullScopeAllowed"`
	// +optional
	ID *string `json:"id,omitempty" diff:"-"`
	// +kubebuilder:default=false
	ImplicitFlowEnabled *bool `json:"implicitFlowEnabled,omitempty" diff:"implicitFlowEnabled"`
	// +required
	Name *string `json:"name,omitempty" diff:"name"`
	// +kubebuilder:default=-1
	NodeReRegistrationTimeout *int32 `json:"nodeReRegistrationTimeout,omitempty" diff:"nodeReRegistrationTimeout"`
	// +kubebuilder:default=0
	NotBefore *int32 `json:"notBefore,omitempty" diff:"notBefore"`
	// +kubebuilder:default={"address", "phone", "offline_access", "microprofile-jwt"}
	OptionalClientScopes *[]string `json:"optionalClientScopes,omitempty" diff:"optionalClientScopes"`
	Origin               *string   `json:"origin,omitempty" diff:"origin"`
	// +kubebuilder:default="openid-connect"
	Protocol        *string           `json:"protocol,omitempty" diff:"protocol"`
	ProtocolMappers *[]ProtocolMapper `json:"protocolMappers,omitempty" diff:"protocolMappers"`
	// +kubebuilder:default=false
	PublicClient *bool `json:"publicClient,omitempty" diff:"publicClient"`
	// +optional
	RedirectURIs            *[]string       `json:"redirectUris,omitempty" diff:"redirectUris"`
	RegisteredNodes         *map[string]int `json:"registeredNodes,omitempty" diff:"registeredNodes"`
	RegistrationAccessToken *string         `json:"registrationAccessToken,omitempty" diff:"registrationAccessToken"`
	// +kubebuilder:default=""
	RootURL *string `json:"rootUrl,omitempty" diff:"rootUrl"`
	// +optional
	Secret *string `json:"secret,omitempty" diff:"-"`
	// +kubebuilder:default=false
	ServiceAccountsEnabled *bool `json:"serviceAccountsEnabled,omitempty" diff:"serviceAccountsEnabled"`
	// +kubebuilder:default=true
	StandardFlowEnabled *bool `json:"standardFlowEnabled,omitempty" diff:"standardFlowEnabled"`
	// +kubebuilder:default=false
	SurrogateAuthRequired *bool `json:"surrogateAuthRequired,omitempty" diff:"surrogateAuthRequired"`
	// +optional
	WebOrigins *[]string `json:"webOrigins,omitempty" diff:"webOrigins"`
}

// ResourceServerRepresentation represents the resources of a Server
// +kubebuilder:object:generate=true
type ResourceServerRepresentation struct {
	AllowRemoteResourceManagement *bool                   `json:"allowRemoteResourceManagement,omitempty" diff:"allowRemoteResourceManagement"`
	ClientID                      *string                 `json:"clientId,omitempty" diff:"clientId"`
	ID                            *string                 `json:"id,omitempty" diff:"-"`
	Name                          *string                 `json:"name,omitempty" diff:"name"`
	Policies                      *[]PolicyRepresentation `json:"policies,omitempty" diff:"policies"`
	// +kubebuilder:validation:Enum=ENFORCING;PERMISSIVE;DISABLED
	PolicyEnforcementMode *string                   `json:"policyEnforcementMode,omitempty" diff:"policyEnforcementMode"`
	Resources             *[]ResourceRepresentation `json:"resources,omitempty" diff:"resources"`
	Scopes                *[]ScopeRepresentation    `json:"scopes,omitempty" diff:"scopes"`
	// +kubebuilder:validation:Enum=AFFIRMATIVE;UNANIMOUS;CONSENSUS
	DecisionStrategy *string `json:"decisionStrategy,omitempty" diff:"decisionStrategy"`
}

// AdapterConfiguration represents adapter configuration of a client
type AdapterConfiguration struct {
	Realm            *string     `json:"realm"`
	AuthServerURL    *string     `json:"auth-server-url"`
	SSLRequired      *string     `json:"ssl-required"`
	Resource         *string     `json:"resource"`
	Credentials      interface{} `json:"credentials"`
	ConfidentialPort *int        `json:"confidential-port"`
}

// PolicyEnforcementMode is an enum type for PolicyEnforcementMode of ResourceServerRepresentation
type PolicyEnforcementMode string

// PolicyEnforcementMode values
var (
	ENFORCING  = PolicyEnforcementModeP("ENFORCING")
	PERMISSIVE = PolicyEnforcementModeP("PERMISSIVE")
	DISABLED   = PolicyEnforcementModeP("DISABLED")
)

// Logic is an enum type for policy logic
type Logic string

// Logic values
var (
	POSITIVE = LogicP("POSITIVE")
	NEGATIVE = LogicP("NEGATIVE")
)

// DecisionStrategy is an enum type for DecisionStrategy of PolicyRepresentation
type DecisionStrategy string

// DecisionStrategy values
var (
	AFFIRMATIVE = DecisionStrategyP("AFFIRMATIVE")
	UNANIMOUS   = DecisionStrategyP("UNANIMOUS")
	CONSENSUS   = DecisionStrategyP("CONSENSUS")
)

// PolicyRepresentation is a representation of a Policy
// +kubebuilder:object:generate=true
type PolicyRepresentation struct {
	Config *map[string]string `json:"config,omitempty" diff:"config"`
	// +kubebuilder:validation:Enum=AFFIRMATIVE;UNANIMOUS;CONSENSUS
	DecisionStrategy *string `json:"decisionStrategy,omitempty" diff:"decisionStrategy"`
	Description      *string `json:"description,omitempty" diff:"description"`
	ID               *string `json:"id,omitempty" diff:"-"`
	// +kubebuilder:validation:Enum=POSITIVE;NEGATIVE
	Logic     *string   `json:"logic,omitempty" diff:"logic"`
	Name      *string   `json:"name,omitempty" diff:"name"`
	Owner     *string   `json:"owner,omitempty" diff:"owner"`
	Policies  *[]string `json:"policies,omitempty" diff:"policies"`
	Resources *[]string `json:"resources,omitempty" diff:"resources"`
	Scopes    *[]string `json:"scopes,omitempty" diff:"scopes"`
	Type      *string   `json:"type,omitempty" diff:"type"`
	/*
		RolePolicyRepresentation
		JSPolicyRepresentation
		ClientPolicyRepresentation
		TimePolicyRepresentation
		UserPolicyRepresentation
		AggregatedPolicyRepresentation
		GroupPolicyRepresentation
	*/
}

// RolePolicyRepresentation represents role based policies
// +kubebuilder:object:generate=true
type RolePolicyRepresentation struct {
	Roles *[]RoleDefinition `json:"roles,omitempty" diff:"roles"`
}

// JSPolicyRepresentation represents js based policies
// +kubebuilder:object:generate=true
type JSPolicyRepresentation struct {
	Code *string `json:"code,omitempty" diff:"code"`
}

// ClientPolicyRepresentation represents client based policies
// +kubebuilder:object:generate=true
type ClientPolicyRepresentation struct {
	Clients *[]string `json:"clients,omitempty" diff:"clients"`
}

// TimePolicyRepresentation represents time based policies
// +kubebuilder:object:generate=true
type TimePolicyRepresentation struct {
	NotBefore    *string `json:"notBefore,omitempty" diff:"notBefore"`
	NotOnOrAfter *string `json:"notOnOrAfter,omitempty" diff:"notOnOrAfter"`
	DayMonth     *string `json:"dayMonth,omitempty" diff:"dayMonth"`
	DayMonthEnd  *string `json:"dayMonthEnd,omitempty" diff:"dayMonthEnd"`
	Month        *string `json:"month,omitempty" diff:"month"`
	MonthEnd     *string `json:"monthEnd,omitempty" diff:"monthEnd"`
	Year         *string `json:"year,omitempty" diff:"year"`
	YearEnd      *string `json:"yearEnd,omitempty" diff:"yearEnd"`
	Hour         *string `json:"hour,omitempty" diff:"hour"`
	HourEnd      *string `json:"hourEnd,omitempty" diff:"hourEnd"`
	Minute       *string `json:"minute,omitempty" diff:"minute"`
	MinuteEnd    *string `json:"minuteEnd,omitempty" diff:"minuteEnd"`
}

// UserPolicyRepresentation represents user based policies
// +kubebuilder:object:generate=true
type UserPolicyRepresentation struct {
	Users *[]string `json:"users,omitempty" diff:"users"`
}

// AggregatedPolicyRepresentation represents aggregated policies
// +kubebuilder:object:generate=true
type AggregatedPolicyRepresentation struct {
	Policies *[]string `json:"policies,omitempty" diff:"policies"`
}

// GroupPolicyRepresentation represents group based policies
// +kubebuilder:object:generate=true
type GroupPolicyRepresentation struct {
	Groups      *[]GroupDefinition `json:"groups,omitempty" diff:"groups"`
	GroupsClaim *string            `json:"groupsClaim,omitempty" diff:"groupsClaim"`
}

// GroupDefinition represents a group in a GroupPolicyRepresentation
// +kubebuilder:object:generate=true
type GroupDefinition struct {
	ID             *string `json:"id,omitempty" diff:"-"`
	Path           *string `json:"path,omitempty" diff:"path"`
	ExtendChildren *bool   `json:"extendChildren,omitempty" diff:"extendChildren"`
}

// ResourceRepresentation is a representation of a Resource
// +kubebuilder:object:generate=true
type ResourceRepresentation struct {
	ID                 *string                      `json:"_id,omitempty" diff:"-"`
	Attributes         *map[string][]string         `json:"attributes,omitempty" diff:"-"`
	DisplayName        *string                      `json:"displayName,omitempty" diff:"displayName"`
	IconURI            *string                      `json:"icon_uri,omitempty" diff:"icon_uri"`
	Name               *string                      `json:"name,omitempty" diff:"name"`
	Owner              *ResourceOwnerRepresentation `json:"owner,omitempty" diff:"owner"`
	OwnerManagedAccess *bool                        `json:"ownerManagedAccess,omitempty" diff:"ownerManagedAccess"`
	ResourceScopes     *[]ScopeRepresentation       `json:"resource_scopes,omitempty" diff:"resource_scopes"`
	Type               *string                      `json:"type,omitempty" diff:"type"`
	URIs               *[]string                    `json:"uris,omitempty" diff:"uris"`
}

// ResourceOwnerRepresentation represents a resource's owner
// +kubebuilder:object:generate=true
type ResourceOwnerRepresentation struct {
	ID   *string `json:"id,omitempty" diff:"-"`
	Name *string `json:"name,omitempty" diff:"name"`
}

// ScopeRepresentation is a represents a Scope
// +kubebuilder:object:generate=true
type ScopeRepresentation struct {
	DisplayName *string                 `json:"displayName,omitempty" diff:"displayName"`
	IconURI     *string                 `json:"iconUri,omitempty" diff:"iconUri"`
	ID          *string                 `json:"id,omitempty" diff:"-"`
	Name        *string                 `json:"name,omitempty" diff:"name"`
	Policies    *[]PolicyRepresentation `json:"policies,omitempty" diff:"policies"`
	// Resources   *[]ResourceRepresentation `json:"resources,omitempty" diff:"resources"`
}

// RoleDefinition represents a role in a RolePolicyRepresentation
// +kubebuilder:object:generate=true
type RoleDefinition struct {
	ID       *string `json:"id,omitempty" diff:"-"`
	Private  *bool   `json:"private,omitempty" diff:"private"`
	Required *bool   `json:"required,omitempty" diff:"required"`
}

// GetClientsParams represents the query parameters
type GetClientsParams struct {
	ClientID             *string `json:"clientId,omitempty"`
	ViewableOnly         *bool   `json:"viewableOnly,string,omitempty"`
	First                *int    `json:"first,string,omitempty"`
	Max                  *int    `json:"max,string,omitempty"`
	Search               *bool   `json:"search,string,omitempty"`
	SearchableAttributes *string `json:"q,omitempty"`
}

// UserInfoAddress is representation of the address sub-filed of UserInfo
// https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
type UserInfoAddress struct {
	Formatted     *string `json:"formatted,omitempty"`
	StreetAddress *string `json:"street_address,omitempty"`
	Locality      *string `json:"locality,omitempty"`
	Region        *string `json:"region,omitempty"`
	PostalCode    *string `json:"postal_code,omitempty"`
	Country       *string `json:"country,omitempty"`
}

// UserInfo is returned by the userinfo endpoint
// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
type UserInfo struct {
	Sub                 *string          `json:"sub,omitempty"`
	Name                *string          `json:"name,omitempty"`
	GivenName           *string          `json:"given_name,omitempty"`
	FamilyName          *string          `json:"family_name,omitempty"`
	MiddleName          *string          `json:"middle_name,omitempty"`
	Nickname            *string          `json:"nickname,omitempty"`
	PreferredUsername   *string          `json:"preferred_username,omitempty"`
	Profile             *string          `json:"profile,omitempty"`
	Picture             *string          `json:"picture,omitempty"`
	Website             *string          `json:"website,omitempty"`
	Email               *string          `json:"email,omitempty"`
	EmailVerified       *bool            `json:"email_verified,omitempty"`
	Gender              *string          `json:"gender,omitempty"`
	ZoneInfo            *string          `json:"zoneinfo,omitempty"`
	Locale              *string          `json:"locale,omitempty"`
	PhoneNumber         *string          `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool            `json:"phone_number_verified,omitempty"`
	Address             *UserInfoAddress `json:"address,omitempty"`
	UpdatedAt           *int             `json:"updated_at,omitempty"`
}

// RolesRepresentation represents the roles of a realm
type RolesRepresentation struct {
	Client *map[string][]Role `json:"client,omitempty"`
	Realm  *[]Role            `json:"realm,omitempty"`
}

// RealmRepresentation represents a realm
// +kubebuilder:object:generate=true
type RealmRepresentation struct {
	// +kubebuilder:default=60
	AccessCodeLifespan *int `json:"accessCodeLifespan,omitempty" diff:"accessCodeLifespan"`
	// +kubebuilder:default=1800
	AccessCodeLifespanLogin *int `json:"accessCodeLifespanLogin,omitempty" diff:"accessCodeLifespanLogin"`
	// +kubebuilder:default=300
	AccessCodeLifespanUserAction *int `json:"accessCodeLifespanUserAction,omitempty" diff:"accessCodeLifespanUserAction"`
	// +kubebuilder:default=300
	AccessTokenLifespan *int `json:"accessTokenLifespan,omitempty" diff:"accessTokenLifespan"`
	// +kubebuilder:default=900
	AccessTokenLifespanForImplicitFlow *int `json:"accessTokenLifespanForImplicitFlow,omitempty" diff:"accessTokenLifespanForImplicitFlow"`
	// +optional
	AccountTheme *string `json:"accountTheme,omitempty" diff:"accountTheme"`
	// +kubebuilder:default=43200
	ActionTokenGeneratedByAdminLifespan *int `json:"actionTokenGeneratedByAdminLifespan,omitempty" diff:"actionTokenGeneratedByAdminLifespan"`
	// +kubebuilder:default=300
	ActionTokenGeneratedByUserLifespan *int `json:"actionTokenGeneratedByUserLifespan,omitempty" diff:"actionTokenGeneratedByUserLifespan"`
	// +kubebuilder:default=false
	AdminEventsDetailsEnabled *bool `json:"adminEventsDetailsEnabled,omitempty" diff:"adminEventsDetailsEnabled"`
	// +kubebuilder:default=false
	AdminEventsEnabled *bool `json:"adminEventsEnabled,omitempty" diff:"adminEventsEnabled"`
	// +optional
	AdminTheme *string `json:"adminTheme,omitempty" diff:"adminTheme"`
	// +kubebuilder:default={}
	Attributes *map[string]string `json:"attributes,omitempty" diff:"-"`
	// +kubebuilder:default="browser"
	BrowserFlow *string `json:"browserFlow,omitempty" diff:"browserFlow"`
	// +kubebuilder:default={}
	BrowserSecurityHeaders *map[string]string `json:"browserSecurityHeaders,omitempty" diff:"-"`
	// +kubebuilder:default=false
	BruteForceProtected *bool `json:"bruteForceProtected,omitempty" diff:"bruteForceProtected"`
	// +kubebuilder:default="clients"
	ClientAuthenticationFlow *string `json:"clientAuthenticationFlow,omitempty" diff:"clientAuthenticationFlow"`
	// +optional
	DefaultDefaultClientScopes *[]string `json:"defaultDefaultClientScopes,omitempty" diff:"defaultDefaultClientScopes"`
	// +optional
	DefaultGroups *[]string `json:"defaultGroups,omitempty" diff:"defaultGroups"`
	// +kubebuilder:default=""
	DefaultLocale *string `json:"defaultLocale,omitempty" diff:"defaultLocale"`
	// +optional
	DefaultOptionalClientScopes *[]string `json:"defaultOptionalClientScopes,omitempty" diff:"defaultOptionalClientScopes"`
	// +optional
	DefaultRole *Role `json:"defaultRole,omitempty" diff:"-"`
	// +optional
	DefaultRoles *[]string `json:"defaultRoles,omitempty" diff:"defaultRoles"`
	// +kubebuilder:default=""
	DefaultSignatureAlgorithm *string `json:"defaultSignatureAlgorithm,omitempty" diff:"defaultSignatureAlgorithm"`
	// +kubebuilder:default="direct grant"
	DirectGrantFlow *string `json:"directGrantFlow,omitempty" diff:"directGrantFlow"`
	// +kubebuilder:default=""
	DisplayName *string `json:"displayName,omitempty" diff:"displayName"`
	// +kubebuilder:default=""
	DisplayNameHTML *string `json:"displayNameHtml,omitempty" diff:"displayNameHtml"`
	// +kubebuilder:default="docker auth"
	DockerAuthenticationFlow *string `json:"dockerAuthenticationFlow,omitempty" diff:"dockerAuthenticationFlow"`
	// +kubebuilder:default=false
	DuplicateEmailsAllowed *bool `json:"duplicateEmailsAllowed,omitempty" diff:"duplicateEmailsAllowed"`
	// +kubebuilder:default=false
	EditUsernameAllowed *bool `json:"editUsernameAllowed,omitempty" diff:"editUsernameAllowed"`
	// +optional
	EmailTheme *string `json:"emailTheme,omitempty" diff:"emailTheme"`
	// +kubebuilder:default=true
	Enabled *bool `json:"enabled,omitempty" diff:"enabled"`
	// +kubebuilder:default={}
	EnabledEventTypes *[]string `json:"enabledEventTypes,omitempty" diff:"enabledEventTypes"`
	// +kubebuilder:default=false
	EventsEnabled *bool `json:"eventsEnabled,omitempty" diff:"eventsEnabled"`
	// +optional
	EventsExpiration *int64 `json:"eventsExpiration,omitempty" diff:"eventsExpiration"`
	// +kubebuilder:default={"jboss-logging"}
	EventsListeners *[]string `json:"eventsListeners,omitempty" diff:"eventsListeners"`
	// +kubebuilder:default=30
	FailureFactor *int `json:"failureFactor,omitempty" diff:"failureFactor"`
	// +optional
	ID *string `json:"id,omitempty" diff:"-"`
	// +kubebuilder:default=false
	InternationalizationEnabled *bool `json:"internationalizationEnabled,omitempty" diff:"internationalizationEnabled"`
	// +optional
	KeycloakVersion *string `json:"keycloakVersion,omitempty" diff:"keycloakVersion"`
	// +optional
	LoginTheme *string `json:"loginTheme,omitempty" diff:"loginTheme"`
	// +kubebuilder:default=true
	LoginWithEmailAllowed *bool `json:"loginWithEmailAllowed,omitempty" diff:"loginWithEmailAllowed"`
	// +kubebuilder:default=43200
	MaxDeltaTimeSeconds *int `json:"maxDeltaTimeSeconds,omitempty" diff:"maxDeltaTimeSeconds"`
	// +kubebuilder:default=900
	MaxFailureWaitSeconds *int `json:"maxFailureWaitSeconds,omitempty" diff:"maxFailureWaitSeconds"`
	// +kubebuilder:default=60
	MinimumQuickLoginWaitSeconds *int `json:"minimumQuickLoginWaitSeconds,omitempty" diff:"minimumQuickLoginWaitSeconds"`
	// +kubebuilder:default=0
	NotBefore *int `json:"notBefore,omitempty" diff:"notBefore"`
	// +kubebuilder:default=2582000
	OfflineSessionIdleTimeout *int `json:"offlineSessionIdleTimeout,omitempty" diff:"offlineSessionIdleTimeout"`
	// +kubebuilder:default=5184000
	OfflineSessionMaxLifespan *int `json:"offlineSessionMaxLifespan,omitempty" diff:"offlineSessionMaxLifespan"`
	// +kubebuilder:default=false
	OfflineSessionMaxLifespanEnabled *bool `json:"offlineSessionMaxLifespanEnabled,omitempty" diff:"offlineSessionMaxLifespanEnabled"`
	// +kubebuilder:default="HmacSHA1"
	OtpPolicyAlgorithm *string `json:"otpPolicyAlgorithm,omitempty" diff:"otpPolicyAlgorithm"`
	// +kubebuilder:default=6
	OtpPolicyDigits *int `json:"otpPolicyDigits,omitempty" diff:"otpPolicyDigits"`
	// +kubebuilder:default=0
	OtpPolicyInitialCounter *int `json:"otpPolicyInitialCounter,omitempty" diff:"otpPolicyInitialCounter"`
	// +kubebuilder:default=1
	OtpPolicyLookAheadWindow *int `json:"otpPolicyLookAheadWindow,omitempty" diff:"otpPolicyLookAheadWindow"`
	// +kubebuilder:default=30
	OtpPolicyPeriod *int `json:"otpPolicyPeriod,omitempty" diff:"otpPolicyPeriod"`
	// +kubebuilder:default="totp"
	OtpPolicyType *string `json:"otpPolicyType,omitempty" diff:"otpPolicyType"`
	// +kubebuilder:default={"FreeOTP", "Google Authenticator"}
	OtpSupportedApplications *[]string `json:"otpSupportedApplications,omitempty" diff:"otpSupportedApplications"`
	// +optional
	PasswordPolicy *string `json:"passwordPolicy,omitempty" diff:"passwordPolicy"`
	// +kubebuilder:default=false
	PermanentLockout *bool `json:"permanentLockout,omitempty" diff:"permanentLockout"`
	// +kubebuilder:default=1000
	QuickLoginCheckMilliSeconds *int64 `json:"quickLoginCheckMilliSeconds,omitempty" diff:"quickLoginCheckMilliSeconds"`
	// +required
	Realm *string `json:"realm,omitempty" diff:"realm"`
	// +kubebuilder:default=0
	RefreshTokenMaxReuse *int `json:"refreshTokenMaxReuse,omitempty" diff:"refreshTokenMaxReuse"`
	// +kubebuilder:default=false
	RegistrationAllowed *bool `json:"registrationAllowed,omitempty" diff:"registrationAllowed"`
	// +kubebuilder:default=false
	RegistrationEmailAsUsername *bool `json:"registrationEmailAsUsername,omitempty" diff:"registrationEmailAsUsername"`
	// +kubebuilder:default="registration"
	RegistrationFlow *string `json:"registrationFlow,omitempty" diff:"registrationFlow"`
	// +kubebuilder:default=false
	RememberMe *bool `json:"rememberMe,omitempty" diff:"rememberMe"`
	// +kubebuilder:default="reset credentials"
	ResetCredentialsFlow *string `json:"resetCredentialsFlow,omitempty" diff:"resetCredentialsFlow"`
	// +kubebuilder:default=false
	ResetPasswordAllowed *bool `json:"resetPasswordAllowed,omitempty" diff:"resetPasswordAllowed"`
	// +kubebuilder:default=false
	RevokeRefreshToken *bool `json:"revokeRefreshToken,omitempty" diff:"revokeRefreshToken"`
	// +optional
	SMTPServer *map[string]string `json:"smtpServer,omitempty" diff:"smtpServer"`
	// +kubebuilder:default="external"
	SslRequired *string `json:"sslRequired,omitempty" diff:"sslRequired"`
	// +kubebuilder:default=1800
	SsoSessionIdleTimeout *int `json:"ssoSessionIdleTimeout,omitempty" diff:"ssoSessionIdleTimeout"`
	// +kubebuilder:default=0
	SsoSessionIdleTimeoutRememberMe *int `json:"ssoSessionIdleTimeoutRememberMe,omitempty" diff:"ssoSessionIdleTimeoutRememberMe"`
	// +kubebuilder:default=43200
	SsoSessionMaxLifespan *int `json:"ssoSessionMaxLifespan,omitempty" diff:"ssoSessionMaxLifespan"`
	// +kubebuilder:default=0
	SsoSessionMaxLifespanRememberMe *int `json:"ssoSessionMaxLifespanRememberMe,omitempty" diff:"ssoSessionMaxLifespanRememberMe"`
	// +optional
	SupportedLocales *[]string `json:"supportedLocales,omitempty" diff:"supportedLocales"`
	// +kubebuilder:default=false
	UserManagedAccessAllowed *bool `json:"userManagedAccessAllowed,omitempty" diff:"userManagedAccessAllowed"`
	// +kubebuilder:default=false
	VerifyEmail *bool `json:"verifyEmail,omitempty" diff:"verifyEmail"`
	// +kubebuilder:default=60
	WaitIncrementSeconds *int `json:"waitIncrementSeconds,omitempty" diff:"waitIncrementSeconds"`
	// +optional
	WebAuthnPolicyAcceptableAaguids *[]string `json:"webAuthnPolicyAcceptableAaguids,omitempty" diff:"webAuthnPolicyAcceptableAaguids"`
	// +kubebuilder:default="not specified"
	WebAuthnPolicyAttestationConveyancePreference *string `json:"webAuthnPolicyAttestationConveyancePreference,omitempty" diff:"webAuthnPolicyAttestationConveyancePreference"`
	// +kubebuilder:default="not specified"
	WebAuthnPolicyAuthenticatorAttachment *string `json:"webAuthnPolicyAuthenticatorAttachment,omitempty" diff:"webAuthnPolicyAuthenticatorAttachment"`
	// +kubebuilder:default=false
	WebAuthnPolicyAvoidSameAuthenticatorRegister *bool `json:"webAuthnPolicyAvoidSameAuthenticatorRegister,omitempty" diff:"webAuthnPolicyAvoidSameAuthenticatorRegister"`
	// +kubebuilder:default=0
	WebAuthnPolicyCreateTimeout *int `json:"webAuthnPolicyCreateTimeout,omitempty" diff:"webAuthnPolicyCreateTimeout"`
	// +optional
	WebAuthnPolicyPasswordlessAcceptableAaguids *[]string `json:"webAuthnPolicyPasswordlessAcceptableAaguids,omitempty" diff:"webAuthnPolicyPasswordlessAcceptableAaguids"`
	// +kubebuilder:default="not specified"
	WebAuthnPolicyPasswordlessAttestationConveyancePreference *string `json:"webAuthnPolicyPasswordlessAttestationConveyancePreference,omitempty" diff:"webAuthnPolicyPasswordlessAttestationConveyancePreference"`
	// +kubebuilder:default="not specified"
	WebAuthnPolicyPasswordlessAuthenticatorAttachment *string `json:"webAuthnPolicyPasswordlessAuthenticatorAttachment,omitempty" diff:"webAuthnPolicyPasswordlessAuthenticatorAttachment"`
	// +kubebuilder:default=false
	WebAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister *bool `json:"webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister,omitempty" diff:"webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister"`
	// +kubebuilder:default=0
	WebAuthnPolicyPasswordlessCreateTimeout *int `json:"webAuthnPolicyPasswordlessCreateTimeout,omitempty" diff:"webAuthnPolicyPasswordlessCreateTimeout"`
	// +kubebuilder:default="not specified"
	WebAuthnPolicyPasswordlessRequireResidentKey *string `json:"webAuthnPolicyPasswordlessRequireResidentKey,omitempty" diff:"webAuthnPolicyPasswordlessRequireResidentKey"`
	// +kubebuilder:default="keycloak"
	WebAuthnPolicyPasswordlessRpEntityName *string `json:"webAuthnPolicyPasswordlessRpEntityName,omitempty" diff:"webAuthnPolicyPasswordlessRpEntityName"`
	// +kubebuilder:default=""
	WebAuthnPolicyPasswordlessRpID *string `json:"webAuthnPolicyPasswordlessRpId,omitempty" diff:"webAuthnPolicyPasswordlessRpId"`
	// +kubebuilder:default={"ES256"}
	WebAuthnPolicyPasswordlessSignatureAlgorithms *[]string `json:"webAuthnPolicyPasswordlessSignatureAlgorithms,omitempty" diff:"webAuthnPolicyPasswordlessSignatureAlgorithms"`
	// +kubebuilder:default="not specified"
	WebAuthnPolicyPasswordlessUserVerificationRequirement *string `json:"webAuthnPolicyPasswordlessUserVerificationRequirement,omitempty" diff:"webAuthnPolicyPasswordlessUserVerificationRequirement"`
	// +kubebuilder:default="not specified"
	WebAuthnPolicyRequireResidentKey *string `json:"webAuthnPolicyRequireResidentKey,omitempty" diff:"webAuthnPolicyRequireResidentKey"`
	// +kubebuilder:default="keycloak"
	WebAuthnPolicyRpEntityName *string `json:"webAuthnPolicyRpEntityName,omitempty" diff:"webAuthnPolicyRpEntityName"`
	// +kubebuilder:default=""
	WebAuthnPolicyRpID *string `json:"webAuthnPolicyRpId,omitempty" diff:"webAuthnPolicyRpId"`
	// +kubebuilder:default={"ES256"}
	WebAuthnPolicySignatureAlgorithms *[]string `json:"webAuthnPolicySignatureAlgorithms,omitempty" diff:"webAuthnPolicySignatureAlgorithms"`
	// +kubebuilder:default="not specified"
	WebAuthnPolicyUserVerificationRequirement *string `json:"webAuthnPolicyUserVerificationRequirement,omitempty" diff:"webAuthnPolicyUserVerificationRequirement"`
}

// AuthenticationFlowRepresentation represents an authentication flow of a realm
type AuthenticationFlowRepresentation struct {
	Alias                    *string                                  `json:"alias,omitempty"`
	AuthenticationExecutions *[]AuthenticationExecutionRepresentation `json:"authenticationExecutions,omitempty"`
	BuiltIn                  *bool                                    `json:"builtIn,omitempty"`
	Description              *string                                  `json:"description,omitempty"`
	ID                       *string                                  `json:"id,omitempty"`
	ProviderID               *string                                  `json:"providerId,omitempty"`
	TopLevel                 *bool                                    `json:"topLevel,omitempty"`
}

// AuthenticationExecutionRepresentation represents the authentication execution of an AuthenticationFlowRepresentation
type AuthenticationExecutionRepresentation struct {
	Authenticator       *string `json:"authenticator,omitempty"`
	AuthenticatorConfig *string `json:"authenticatorConfig,omitempty"`
	AuthenticatorFlow   *bool   `json:"authenticatorFlow,omitempty"`
	AutheticatorFlow    *bool   `json:"autheticatorFlow,omitempty"`
	FlowAlias           *string `json:"flowAlias,omitempty"`
	Priority            *int    `json:"priority,omitempty"`
	Requirement         *string `json:"requirement,omitempty"`
	UserSetupAllowed    *bool   `json:"userSetupAllowed,omitempty"`
}

// CreateAuthenticationExecutionRepresentation contains the provider to be used for a new authentication representation
type CreateAuthenticationExecutionRepresentation struct {
	Provider *string `json:"provider,omitempty"`
}

// CreateAuthenticationExecutionFlowRepresentation contains the provider to be used for a new authentication representation
type CreateAuthenticationExecutionFlowRepresentation struct {
	Alias       *string `json:"alias,omitempty"`
	Description *string `json:"description,omitempty"`
	Provider    *string `json:"provider,omitempty"`
	Type        *string `json:"type,omitempty"`
}

// ModifyAuthenticationExecutionRepresentation is the payload for updating an execution representation
type ModifyAuthenticationExecutionRepresentation struct {
	ID                   *string   `json:"id,omitempty"`
	ProviderID           *string   `json:"providerId,omitempty"`
	AuthenticationConfig *string   `json:"authenticationConfig,omitempty"`
	AuthenticationFlow   *bool     `json:"authenticationFlow,omitempty"`
	Requirement          *string   `json:"requirement,omitempty"`
	FlowID               *string   `json:"flowId"`
	DisplayName          *string   `json:"displayName,omitempty"`
	Alias                *string   `json:"alias,omitempty"`
	RequirementChoices   *[]string `json:"requirementChoices,omitempty"`
	Configurable         *bool     `json:"configurable,omitempty"`
	Level                *int      `json:"level,omitempty"`
	Index                *int      `json:"index,omitempty"`
	Description          *string   `json:"description"`
}

// MultiValuedHashMap represents something
type MultiValuedHashMap struct {
	Empty      *bool    `json:"empty,omitempty"`
	LoadFactor *float32 `json:"loadFactor,omitempty"`
	Threshold  *int32   `json:"threshold,omitempty"`
}

// AuthorizationParameters represents the options to obtain get an authorization
type AuthorizationParameters struct {
	ResponseType *string `json:"code,omitempty"`
	ClientID     *string `json:"client_id,omitempty"`
	Scope        *string `json:"scope,omitempty"`
	RedirectURI  *string `json:"redirect_uri,omitempty"`
	State        *string `json:"state,omitempty"`
	Nonce        *string `json:"nonce,omitempty"`
	IDTokenHint  *string `json:"id_token_hint,omitempty"`
}

// FormData returns a map of options to be used in SetFormData function
func (p *AuthorizationParameters) FormData() map[string]string {
	m, _ := json.Marshal(p)
	var res map[string]string
	_ = json.Unmarshal(m, &res)
	return res
}

// AuthorizationResponse represents the response to an authorization request.
type AuthorizationResponse struct {
}

// TokenOptions represents the options to obtain a token
type TokenOptions struct {
	ClientID            *string   `json:"client_id,omitempty"`
	ClientSecret        *string   `json:"-"`
	GrantType           *string   `json:"grant_type,omitempty"`
	RefreshToken        *string   `json:"refresh_token,omitempty"`
	Scopes              *[]string `json:"-"`
	Scope               *string   `json:"scope,omitempty"`
	ResponseTypes       *[]string `json:"-"`
	ResponseType        *string   `json:"response_type,omitempty"`
	Permission          *string   `json:"permission,omitempty"`
	Username            *string   `json:"username,omitempty"`
	Password            *string   `json:"password,omitempty"`
	Totp                *string   `json:"totp,omitempty"`
	Code                *string   `json:"code,omitempty"`
	RedirectURI         *string   `json:"redirect_uri,omitempty"`
	ClientAssertionType *string   `json:"client_assertion_type,omitempty"`
	ClientAssertion     *string   `json:"client_assertion,omitempty"`
	SubjectToken        *string   `json:"subject_token,omitempty"`
	RequestedSubject    *string   `json:"requested_subject,omitempty"`
	Audience            *string   `json:"audience,omitempty"`
	RequestedTokenType  *string   `json:"requested_token_type,omitempty"`
}

// FormData returns a map of options to be used in SetFormData function
func (t *TokenOptions) FormData() map[string]string {
	if !NilOrEmptySlice(t.Scopes) {
		t.Scope = StringP(strings.Join(*t.Scopes, " "))
	}
	if !NilOrEmptySlice(t.ResponseTypes) {
		t.ResponseType = StringP(strings.Join(*t.ResponseTypes, " "))
	}
	if NilOrEmpty(t.ResponseType) {
		t.ResponseType = StringP("token")
	}
	m, _ := json.Marshal(t)
	var res map[string]string
	_ = json.Unmarshal(m, &res)
	return res
}

// RequestingPartyTokenOptions represents the options to obtain a requesting party token
type RequestingPartyTokenOptions struct {
	GrantType                   *string   `json:"grant_type,omitempty"`
	Ticket                      *string   `json:"ticket,omitempty"`
	ClaimToken                  *string   `json:"claim_token,omitempty"`
	ClaimTokenFormat            *string   `json:"claim_token_format,omitempty"`
	RPT                         *string   `json:"rpt,omitempty"`
	Permissions                 *[]string `json:"-"`
	Audience                    *string   `json:"audience,omitempty"`
	ResponseIncludeResourceName *bool     `json:"response_include_resource_name,string,omitempty"`
	ResponsePermissionsLimit    *uint32   `json:"response_permissions_limit,omitempty"`
	SubmitRequest               *bool     `json:"submit_request,string,omitempty"`
	ResponseMode                *string   `json:"response_mode,omitempty"`
	SubjectToken                *string   `json:"subject_token,omitempty"`
}

// FormData returns a map of options to be used in SetFormData function
func (t *RequestingPartyTokenOptions) FormData() map[string]string {
	if NilOrEmpty(t.GrantType) { // required grant type for RPT
		t.GrantType = StringP("urn:ietf:params:oauth:grant-type:uma-ticket")
	}
	if t.ResponseIncludeResourceName == nil { // defaults to true if no value set
		t.ResponseIncludeResourceName = BoolP(true)
	}

	m, _ := json.Marshal(t)
	var res map[string]string
	_ = json.Unmarshal(m, &res)
	return res
}

// RequestingPartyPermission is returned by request party token with response type set to "permissions"
type RequestingPartyPermission struct {
	Claims       *map[string]string `json:"claims,omitempty"`
	ResourceID   *string            `json:"rsid,omitempty"`
	ResourceName *string            `json:"rsname,omitempty"`
	Scopes       *[]string          `json:"scopes,omitempty"`
}

// RequestingPartyPermissionDecision is returned by request party token with response type set to "decision"
type RequestingPartyPermissionDecision struct {
	Result *bool `json:"result,omitempty"`
}

// UserSessionRepresentation represents a list of user's sessions
type UserSessionRepresentation struct {
	Clients    *map[string]string `json:"clients,omitempty"`
	ID         *string            `json:"id,omitempty"`
	IPAddress  *string            `json:"ipAddress,omitempty"`
	LastAccess *int64             `json:"lastAccess,omitempty"`
	Start      *int64             `json:"start,omitempty"`
	UserID     *string            `json:"userId,omitempty"`
	Username   *string            `json:"username,omitempty"`
}

// SystemInfoRepresentation represents a system info
type SystemInfoRepresentation struct {
	FileEncoding   *string `json:"fileEncoding,omitempty"`
	JavaHome       *string `json:"javaHome,omitempty"`
	JavaRuntime    *string `json:"javaRuntime,omitempty"`
	JavaVendor     *string `json:"javaVendor,omitempty"`
	JavaVersion    *string `json:"javaVersion,omitempty"`
	JavaVM         *string `json:"javaVm,omitempty"`
	JavaVMVersion  *string `json:"javaVmVersion,omitempty"`
	OSArchitecture *string `json:"osArchitecture,omitempty"`
	OSName         *string `json:"osName,omitempty"`
	OSVersion      *string `json:"osVersion,omitempty"`
	ServerTime     *string `json:"serverTime,omitempty"`
	Uptime         *string `json:"uptime,omitempty"`
	UptimeMillis   *int    `json:"uptimeMillis,omitempty"`
	UserDir        *string `json:"userDir,omitempty"`
	UserLocale     *string `json:"userLocale,omitempty"`
	UserName       *string `json:"userName,omitempty"`
	UserTimezone   *string `json:"userTimezone,omitempty"`
	Version        *string `json:"version,omitempty"`
}

// MemoryInfoRepresentation represents a memory info
type MemoryInfoRepresentation struct {
	Free           *int    `json:"free,omitempty"`
	FreeFormated   *string `json:"freeFormated,omitempty"`
	FreePercentage *int    `json:"freePercentage,omitempty"`
	Total          *int    `json:"total,omitempty"`
	TotalFormated  *string `json:"totalFormated,omitempty"`
	Used           *int    `json:"used,omitempty"`
	UsedFormated   *string `json:"usedFormated,omitempty"`
}

// PasswordPolicy represents the configuration for a supported password policy
type PasswordPolicy struct {
	ConfigType        string `json:"configType,omitempty"`
	DefaultValue      string `json:"defaultValue,omitempty"`
	DisplayName       string `json:"displayName,omitempty"`
	ID                string `json:"id,omitempty"`
	MultipleSupported bool   `json:"multipleSupported,omitempty"`
}

// ProtocolMapperTypeProperty represents a property of a ProtocolMapperType
type ProtocolMapperTypeProperty struct {
	Name         string         `json:"name,omitempty"`
	Label        string         `json:"label,omitempty"`
	HelpText     string         `json:"helpText,omitempty"`
	Type         string         `json:"type,omitempty"`
	Options      []string       `json:"options,omitempty"`
	DefaultValue EnforcedString `json:"defaultValue,omitempty"`
	Secret       bool           `json:"secret,omitempty"`
	ReadOnly     bool           `json:"readOnly,omitempty"`
}

// ProtocolMapperType represents a type of protocol mapper
type ProtocolMapperType struct {
	ID         string                       `json:"id,omitempty"`
	Name       string                       `json:"name,omitempty"`
	Category   string                       `json:"category,omitempty"`
	HelpText   string                       `json:"helpText,omitempty"`
	Priority   int                          `json:"priority,omitempty"`
	Properties []ProtocolMapperTypeProperty `json:"properties,omitempty"`
}

// ProtocolMapperTypes holds the currently available ProtocolMapperType-s grouped by protocol
type ProtocolMapperTypes struct {
	DockerV2      []ProtocolMapperType `json:"docker-v2,omitempty"`
	SAML          []ProtocolMapperType `json:"saml,omitempty"`
	OpenIDConnect []ProtocolMapperType `json:"openid-connect,omitempty"`
}

// BuiltinProtocolMappers holds the currently available built-in blueprints of ProtocolMapper-s grouped by protocol
type BuiltinProtocolMappers struct {
	SAML          []ProtocolMapper `json:"saml,omitempty"`
	OpenIDConnect []ProtocolMapper `json:"openid-connect,omitempty"`
}

// ServerInfoRepresentation represents a server info
type ServerInfoRepresentation struct {
	SystemInfo             *SystemInfoRepresentation `json:"systemInfo,omitempty"`
	MemoryInfo             *MemoryInfoRepresentation `json:"memoryInfo,omitempty"`
	PasswordPolicies       []*PasswordPolicy         `json:"passwordPolicies,omitempty"`
	ProtocolMapperTypes    *ProtocolMapperTypes      `json:"protocolMapperTypes,omitempty"`
	BuiltinProtocolMappers *BuiltinProtocolMappers   `json:"builtinProtocolMappers,omitempty"`
	Themes                 *Themes                   `json:"themes,omitempty"`
}

// ThemeRepresentation contains the theme name and locales
type ThemeRepresentation struct {
	Name    string   `json:"name,omitempty"`
	Locales []string `json:"locales,omitempty"`
}

// Themes contains the available keycloak themes with locales
type Themes struct {
	Accounts []ThemeRepresentation `json:"account,omitempty"`
	Admin    []ThemeRepresentation `json:"admin,omitempty"`
	Common   []ThemeRepresentation `json:"common,omitempty"`
	Email    []ThemeRepresentation `json:"email,omitempty"`
	Login    []ThemeRepresentation `json:"login,omitempty"`
	Welcome  []ThemeRepresentation `json:"welcome,omitempty"`
}

// FederatedIdentityRepresentation represents an user federated identity
type FederatedIdentityRepresentation struct {
	IdentityProvider *string `json:"identityProvider,omitempty"`
	UserID           *string `json:"userId,omitempty"`
	UserName         *string `json:"userName,omitempty"`
}

// IdentityProviderRepresentation represents an identity provider
type IdentityProviderRepresentation struct {
	AddReadTokenRoleOnCreate  *bool              `json:"addReadTokenRoleOnCreate,omitempty"`
	Alias                     *string            `json:"alias,omitempty"`
	Config                    *map[string]string `json:"config,omitempty"`
	DisplayName               *string            `json:"displayName,omitempty"`
	Enabled                   *bool              `json:"enabled,omitempty"`
	FirstBrokerLoginFlowAlias *string            `json:"firstBrokerLoginFlowAlias,omitempty"`
	InternalID                *string            `json:"internalId,omitempty"`
	LinkOnly                  *bool              `json:"linkOnly,omitempty"`
	PostBrokerLoginFlowAlias  *string            `json:"postBrokerLoginFlowAlias,omitempty"`
	ProviderID                *string            `json:"providerId,omitempty"`
	StoreToken                *bool              `json:"storeToken,omitempty"`
	TrustEmail                *bool              `json:"trustEmail,omitempty"`
}

// IdentityProviderMapper represents the body of a call to add a mapper to
// an identity provider
type IdentityProviderMapper struct {
	ID                     *string            `json:"id,omitempty"`
	Name                   *string            `json:"name,omitempty"`
	IdentityProviderMapper *string            `json:"identityProviderMapper,omitempty"`
	IdentityProviderAlias  *string            `json:"identityProviderAlias,omitempty"`
	Config                 *map[string]string `json:"config"`
}

// GetResourceParams represents the optional parameters for getting resources
type GetResourceParams struct {
	Deep        *bool   `json:"deep,string,omitempty"`
	First       *int    `json:"first,string,omitempty"`
	Max         *int    `json:"max,string,omitempty"`
	Name        *string `json:"name,omitempty"`
	Owner       *string `json:"owner,omitempty"`
	Type        *string `json:"type,omitempty"`
	URI         *string `json:"uri,omitempty"`
	Scope       *string `json:"scope,omitempty"`
	MatchingURI *bool   `json:"matchingUri,string,omitempty"`
	ExactName   *bool   `json:"exactName,string,omitempty"`
}

// GetScopeParams represents the optional parameters for getting scopes
type GetScopeParams struct {
	Deep  *bool   `json:"deep,string,omitempty"`
	First *int    `json:"first,string,omitempty"`
	Max   *int    `json:"max,string,omitempty"`
	Name  *string `json:"name,omitempty"`
}

// GetPolicyParams represents the optional parameters for getting policies
// TODO: more policy params?
type GetPolicyParams struct {
	First      *int    `json:"first,string,omitempty"`
	Max        *int    `json:"max,string,omitempty"`
	Name       *string `json:"name,omitempty"`
	Permission *bool   `json:"permission,string,omitempty"`
	Type       *string `json:"type,omitempty"`
}

// GetPermissionParams represents the optional parameters for getting permissions
type GetPermissionParams struct {
	First    *int    `json:"first,string,omitempty"`
	Max      *int    `json:"max,string,omitempty"`
	Name     *string `json:"name,omitempty"`
	Resource *string `json:"resource,omitempty"`
	Scope    *string `json:"scope,omitempty"`
	Type     *string `json:"type,omitempty"`
}

// GetUsersByRoleParams represents the optional parameters for getting users by role
type GetUsersByRoleParams struct {
	First *int `json:"first,string,omitempty"`
	Max   *int `json:"max,string,omitempty"`
}

// PermissionRepresentation is a representation of a RequestingPartyPermission
type PermissionRepresentation struct {
	DecisionStrategy *string   `json:"decisionStrategy,omitempty"`
	Description      *string   `json:"description,omitempty"`
	ID               *string   `json:"id,omitempty"`
	Logic            *string   `json:"logic,omitempty"`
	Name             *string   `json:"name,omitempty"`
	Policies         *[]string `json:"policies,omitempty"`
	Resources        *[]string `json:"resources,omitempty"`
	ResourceType     *string   `json:"resourceType,omitempty"`
	Scopes           *[]string `json:"scopes,omitempty"`
	Type             *string   `json:"type,omitempty"`
}

// CreatePermissionTicketParams represents the optional parameters for getting a permission ticket
type CreatePermissionTicketParams struct {
	ResourceID     *string              `json:"resource_id,omitempty"`
	ResourceScopes *[]string            `json:"resource_scopes,omitempty"`
	Claims         *map[string][]string `json:"claims,omitempty"`
}

// PermissionTicketDescriptionRepresentation represents the parameters returned along with a permission ticket
type PermissionTicketDescriptionRepresentation struct {
	ID                     *string               `json:"id,omitempty"`
	CreatedTimeStamp       *int64                `json:"createdTimestamp,omitempty"`
	UserName               *string               `json:"username,omitempty"`
	Enabled                *bool                 `json:"enabled,omitempty"`
	TOTP                   *bool                 `json:"totp,omitempty"`
	EmailVerified          *bool                 `json:"emailVerified,omitempty"`
	FirstName              *string               `json:"firstName,omitempty"`
	LastName               *string               `json:"lastName,omitempty"`
	Email                  *string               `json:"email,omitempty"`
	DisableCredentialTypes *[]string             `json:"disableCredentialTypes,omitempty"`
	RequiredActions        *[]string             `json:"requiredActions,omitempty"`
	NotBefore              *int64                `json:"notBefore,omitempty"`
	Access                 *AccessRepresentation `json:"access,omitempty"`
}

// AccessRepresentation represents the access parameters returned in the permission ticket description
type AccessRepresentation struct {
	ManageGroupMembership *bool `json:"manageGroupMembership,omitempty"`
	View                  *bool `json:"view,omitempty"`
	MapRoles              *bool `json:"mapRoles,omitempty"`
	Impersonate           *bool `json:"impersonate,omitempty"`
	Manage                *bool `json:"manage,omitempty"`
}

// PermissionTicketResponseRepresentation represents the keycloak response containing the permission ticket
type PermissionTicketResponseRepresentation struct {
	Ticket *string `json:"ticket,omitempty"`
}

// PermissionTicketRepresentation represents the permission ticket contents
type PermissionTicketRepresentation struct {
	AZP         *string                                     `json:"azp,omitempty"`
	Claims      *map[string][]string                        `json:"claims,omitempty"`
	Permissions *[]PermissionTicketPermissionRepresentation `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}

// PermissionTicketPermissionRepresentation represents the individual permissions in a permission ticket
type PermissionTicketPermissionRepresentation struct {
	Scopes *[]string `json:"scopes,omitempty"`
	RSID   *string   `json:"rsid,omitempty"`
}

// PermissionGrantParams represents the permission which the resource owner is granting to a specific user
type PermissionGrantParams struct {
	ResourceID  *string `json:"resource,omitempty"`
	RequesterID *string `json:"requester,omitempty"`
	Granted     *bool   `json:"granted,omitempty"`
	ScopeName   *string `json:"scopeName,omitempty"`
	TicketID    *string `json:"id,omitempty"`
}

// PermissionGrantResponseRepresentation represents the reply from Keycloack after granting permission
type PermissionGrantResponseRepresentation struct {
	ID          *string `json:"id,omitempty"`
	Owner       *string `json:"owner,omitempty"`
	ResourceID  *string `json:"resource,omitempty"`
	Scope       *string `json:"scope,omitempty"`
	Granted     *bool   `json:"granted,omitempty"`
	RequesterID *string `json:"requester,omitempty"`
}

// GetUserPermissionParams represents the optional parameters for getting user permissions
type GetUserPermissionParams struct {
	ScopeID     *string `json:"scopeId,omitempty"`
	ResourceID  *string `json:"resourceId,omitempty"`
	Owner       *string `json:"owner,omitempty"`
	Requester   *string `json:"requester,omitempty"`
	Granted     *bool   `json:"granted,omitempty"`
	ReturnNames *string `json:"returnNames,omitempty"`
	First       *int    `json:"first,string,omitempty"`
	Max         *int    `json:"max,string,omitempty"`
}

// ResourcePolicyRepresentation is a representation of a Policy applied to a resource
type ResourcePolicyRepresentation struct {
	Name             *string   `json:"name,omitempty"`
	Description      *string   `json:"description,omitempty"`
	Scopes           *[]string `json:"scopes,omitempty"`
	Roles            *[]string `json:"roles,omitempty"`
	Groups           *[]string `json:"groups,omitempty"`
	Clients          *[]string `json:"clients,omitempty"`
	ID               *string   `json:"id,omitempty"`
	Logic            *string   `json:"logic,omitempty"`
	DecisionStrategy *string   `json:"decisionStrategy,omitempty"`
	Owner            *string   `json:"owner,omitempty"`
	Type             *string   `json:"type,omitempty"`
	Users            *[]string `json:"users,omitempty"`
}

// PolicyScopeRepresentation is a representation of a scopes of specific policy
type PolicyScopeRepresentation struct {
	ID   *string `json:"id,omitempty"`
	Name *string `json:"name,omitempty"`
}

// PolicyResourceRepresentation is a representation of a resource of specific policy
type PolicyResourceRepresentation struct {
	ID   *string `json:"_id,omitempty"`
	Name *string `json:"name,omitempty"`
}

// GetResourcePoliciesParams is a representation of the query params for getting policies
type GetResourcePoliciesParams struct {
	ResourceID *string `json:"resource,omitempty"`
	Name       *string `json:"name,omitempty"`
	Scope      *string `json:"scope,omitempty"`
	First      *int    `json:"first,string,omitempty"`
	Max        *int    `json:"max,string,omitempty"`
}

// GetEventsParams represents the optional parameters for getting events
type GetEventsParams struct {
	Client    *string  `json:"client,omitempty"`
	DateFrom  *string  `json:"dateFrom,omitempty"`
	DateTo    *string  `json:"dateTo,omitempty"`
	First     *int32   `json:"first,string,omitempty"`
	IPAddress *string  `json:"ipAddress,omitempty"`
	Max       *int32   `json:"max,string,omitempty"`
	Type      []string `json:"type,omitempty"`
	UserID    *string  `json:"user,omitempty"`
}

// EventRepresentation is a representation of a Event
type EventRepresentation struct {
	Time      int64             `json:"time,omitempty"`
	Type      *string           `json:"type,omitempty"`
	RealmID   *string           `json:"realmId,omitempty"`
	ClientID  *string           `json:"clientId,omitempty"`
	UserID    *string           `json:"userId,omitempty"`
	SessionID *string           `json:"sessionId,omitempty"`
	IPAddress *string           `json:"ipAddress,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
}

// CredentialRepresentation is a representations of the credentials
// v7: https://www.keycloak.org/docs-api/7.0/rest-api/index.html#_credentialrepresentation
// v8: https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_credentialrepresentation
type CredentialRepresentation struct {
	// Common part
	CreatedDate *int64  `json:"createdDate,omitempty"`
	Temporary   *bool   `json:"temporary,omitempty"`
	Type        *string `json:"type,omitempty"`
	Value       *string `json:"value,omitempty"`

	// <= v7
	Algorithm         *string             `json:"algorithm,omitempty"`
	Config            *MultiValuedHashMap `json:"config,omitempty"`
	Counter           *int32              `json:"counter,omitempty"`
	Device            *string             `json:"device,omitempty"`
	Digits            *int32              `json:"digits,omitempty"`
	HashIterations    *int32              `json:"hashIterations,omitempty"`
	HashedSaltedValue *string             `json:"hashedSaltedValue,omitempty"`
	Period            *int32              `json:"period,omitempty"`
	Salt              *string             `json:"salt,omitempty"`

	// >= v8
	CredentialData *string `json:"credentialData,omitempty"`
	ID             *string `json:"id,omitempty"`
	Priority       *int32  `json:"priority,omitempty"`
	SecretData     *string `json:"secretData,omitempty"`
	UserLabel      *string `json:"userLabel,omitempty"`
}

// BruteForceStatus is a representation of realm user regarding brute force attack
type BruteForceStatus struct {
	NumFailures   *int    `json:"numFailures,omitempty"`
	Disabled      *bool   `json:"disabled,omitempty"`
	LastIPFailure *string `json:"lastIPFailure,omitempty"`
	LastFailure   *int    `json:"lastFailure,omitempty"`
}

// RequiredActionProviderRepresentation is a representation of required actions
// v15: https://www.keycloak.org/docs-api/15.0/rest-api/index.html#_requiredactionproviderrepresentation
type RequiredActionProviderRepresentation struct {
	Alias         *string            `json:"alias,omitempty"`
	Config        *map[string]string `json:"config,omitempty"`
	DefaultAction *bool              `json:"defaultAction,omitempty"`
	Enabled       *bool              `json:"enabled,omitempty"`
	Name          *string            `json:"name,omitempty"`
	Priority      *int32             `json:"priority,omitempty"`
	ProviderID    *string            `json:"providerId,omitempty"`
}

// ManagementPermissionRepresentation is a representation of management permissions
// v18: https://www.keycloak.org/docs-api/18.0/rest-api/#_managementpermissionreference
type ManagementPermissionRepresentation struct {
	Enabled          *bool              `json:"enabled,omitempty"`
	Resource         *string            `json:"resource,omitempty"`
	ScopePermissions *map[string]string `json:"scopePermissions,omitempty"`
}

// GetClientUserSessionsParams represents the optional parameters for getting user sessions associated with the client
type GetClientUserSessionsParams struct {
	First *int `json:"first,string,omitempty"`
	Max   *int `json:"max,string,omitempty"`
}

// prettyStringStruct returns struct formatted into pretty string
func prettyStringStruct(t interface{}) string {
	json, err := json.MarshalIndent(t, "", "\t")
	if err != nil {
		return ""
	}

	return string(json)
}

// Stringer implementations for all struct types
func (v *CertResponseKey) String() string                           { return prettyStringStruct(v) }
func (v *CertResponse) String() string                              { return prettyStringStruct(v) }
func (v *IssuerResponse) String() string                            { return prettyStringStruct(v) }
func (v *ResourcePermission) String() string                        { return prettyStringStruct(v) }
func (v *PermissionResource) String() string                        { return prettyStringStruct(v) }
func (v *PermissionScope) String() string                           { return prettyStringStruct(v) }
func (v *IntroSpectTokenResult) String() string                     { return prettyStringStruct(v) }
func (v *User) String() string                                      { return prettyStringStruct(v) }
func (v *SetPasswordRequest) String() string                        { return prettyStringStruct(v) }
func (v *Component) String() string                                 { return prettyStringStruct(v) }
func (v *KeyStoreConfig) String() string                            { return prettyStringStruct(v) }
func (v *ActiveKeys) String() string                                { return prettyStringStruct(v) }
func (v *Key) String() string                                       { return prettyStringStruct(v) }
func (v *Attributes) String() string                                { return prettyStringStruct(v) }
func (v *Access) String() string                                    { return prettyStringStruct(v) }
func (v *UserGroup) String() string                                 { return prettyStringStruct(v) }
func (v *GetUsersParams) String() string                            { return prettyStringStruct(v) }
func (v *GetComponentsParams) String() string                       { return prettyStringStruct(v) }
func (v *ExecuteActionsEmail) String() string                       { return prettyStringStruct(v) }
func (v *Group) String() string                                     { return prettyStringStruct(v) }
func (v *GroupsCount) String() string                               { return prettyStringStruct(v) }
func (obj *GetGroupsParams) String() string                         { return prettyStringStruct(obj) }
func (v *CompositesRepresentation) String() string                  { return prettyStringStruct(v) }
func (v *Role) String() string                                      { return prettyStringStruct(v) }
func (v *GetRoleParams) String() string                             { return prettyStringStruct(v) }
func (v *ClientMappingsRepresentation) String() string              { return prettyStringStruct(v) }
func (v *MappingsRepresentation) String() string                    { return prettyStringStruct(v) }
func (v *ClientScope) String() string                               { return prettyStringStruct(v) }
func (v *ClientScopeAttributes) String() string                     { return prettyStringStruct(v) }
func (v *ProtocolMapper) String() string                            { return prettyStringStruct(v) }
func (v *Client) String() string                                    { return prettyStringStruct(v) }
func (v *ResourceServerRepresentation) String() string              { return prettyStringStruct(v) }
func (v *RoleDefinition) String() string                            { return prettyStringStruct(v) }
func (v *PolicyRepresentation) String() string                      { return prettyStringStruct(v) }
func (v *RolePolicyRepresentation) String() string                  { return prettyStringStruct(v) }
func (v *JSPolicyRepresentation) String() string                    { return prettyStringStruct(v) }
func (v *ClientPolicyRepresentation) String() string                { return prettyStringStruct(v) }
func (v *TimePolicyRepresentation) String() string                  { return prettyStringStruct(v) }
func (v *UserPolicyRepresentation) String() string                  { return prettyStringStruct(v) }
func (v *AggregatedPolicyRepresentation) String() string            { return prettyStringStruct(v) }
func (v *GroupPolicyRepresentation) String() string                 { return prettyStringStruct(v) }
func (v *GroupDefinition) String() string                           { return prettyStringStruct(v) }
func (v *ResourceRepresentation) String() string                    { return prettyStringStruct(v) }
func (v *ResourceOwnerRepresentation) String() string               { return prettyStringStruct(v) }
func (v *ScopeRepresentation) String() string                       { return prettyStringStruct(v) }
func (v *GetClientsParams) String() string                          { return prettyStringStruct(v) }
func (v *UserInfoAddress) String() string                           { return prettyStringStruct(v) }
func (v *UserInfo) String() string                                  { return prettyStringStruct(v) }
func (v *RolesRepresentation) String() string                       { return prettyStringStruct(v) }
func (v *RealmRepresentation) String() string                       { return prettyStringStruct(v) }
func (v *MultiValuedHashMap) String() string                        { return prettyStringStruct(v) }
func (t *TokenOptions) String() string                              { return prettyStringStruct(t) }
func (t *RequestingPartyTokenOptions) String() string               { return prettyStringStruct(t) }
func (v *RequestingPartyPermission) String() string                 { return prettyStringStruct(v) }
func (v *UserSessionRepresentation) String() string                 { return prettyStringStruct(v) }
func (v *SystemInfoRepresentation) String() string                  { return prettyStringStruct(v) }
func (v *MemoryInfoRepresentation) String() string                  { return prettyStringStruct(v) }
func (v *ServerInfoRepresentation) String() string                  { return prettyStringStruct(v) }
func (v *FederatedIdentityRepresentation) String() string           { return prettyStringStruct(v) }
func (v *IdentityProviderRepresentation) String() string            { return prettyStringStruct(v) }
func (v *GetResourceParams) String() string                         { return prettyStringStruct(v) }
func (v *GetScopeParams) String() string                            { return prettyStringStruct(v) }
func (v *GetPolicyParams) String() string                           { return prettyStringStruct(v) }
func (v *GetPermissionParams) String() string                       { return prettyStringStruct(v) }
func (v *GetUsersByRoleParams) String() string                      { return prettyStringStruct(v) }
func (v *PermissionRepresentation) String() string                  { return prettyStringStruct(v) }
func (v *CreatePermissionTicketParams) String() string              { return prettyStringStruct(v) }
func (v *PermissionTicketDescriptionRepresentation) String() string { return prettyStringStruct(v) }
func (v *AccessRepresentation) String() string                      { return prettyStringStruct(v) }
func (v *PermissionTicketResponseRepresentation) String() string    { return prettyStringStruct(v) }
func (v *PermissionTicketRepresentation) String() string            { return prettyStringStruct(v) }
func (v *PermissionTicketPermissionRepresentation) String() string  { return prettyStringStruct(v) }
func (v *PermissionGrantParams) String() string                     { return prettyStringStruct(v) }
func (v *PermissionGrantResponseRepresentation) String() string     { return prettyStringStruct(v) }
func (v *GetUserPermissionParams) String() string                   { return prettyStringStruct(v) }
func (v *ResourcePolicyRepresentation) String() string              { return prettyStringStruct(v) }
func (v *GetResourcePoliciesParams) String() string                 { return prettyStringStruct(v) }
func (v *CredentialRepresentation) String() string                  { return prettyStringStruct(v) }
func (v *RequiredActionProviderRepresentation) String() string      { return prettyStringStruct(v) }
func (v *BruteForceStatus) String() string                          { return prettyStringStruct(v) }
func (v *GetClientUserSessionsParams) String() string               { return prettyStringStruct(v) }
