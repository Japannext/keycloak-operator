/*
Copyright 2024 Japannext.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha2

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/japannext/keycloak-operator/gocloak"
)

// KeycloakLDAPFederation is the Schema for the keycloakldapfederations API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:shortName=kldap,categories=keycloak
// +kubebuilder:printcolumn:name="STATUS",type="string",JSONPath=".status.api.phase"
// +kubebuilder:printcolumn:name="LAST CHANGED",priority=1,type="date",JSONPath=".status.api.lastTransitionTime",description="The last time the resource was changed"
type KeycloakLDAPFederation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeycloakLDAPFederationSpec   `json:"spec,omitempty"`
	Status KeycloakLDAPFederationStatus `json:"status,omitempty"`
}

// KeycloakLDAPFederationSpec defines the desired state of KeycloakLDAPFederation
type KeycloakLDAPFederationSpec struct {
	Endpoint EndpointSelector `json:"endpoint,omitempty"`
	Realm    string           `json:"realm"`
	Config   *LdapFederation  `json:"config,omitempty"`
}

// +kubebuilder:object:generate=true
type LdapFederation struct {
	// Enable/disable HTTP authentication of users with SPNEGO/Kerberos tokens. The data about authenticated users
	// will be provisioned from this LDAP server.
	// +kubebuilder:default=false
	AllowKerberosAuthentication bool `json:"allowKerberosAuthentication"`
	// Count of LDAP users to be imported from LDAP to Keycloak within a single transaction
	// +kubebuilder:default=1000
	BatchSizeForSync int `json:"batchSizeForSync"`
	// Name of a kubernetes secret holding the `bind_dn` and `bind_password` necessary to connect
	// +kubebuilder:default=""
	BindCredentialsSecret string `json:"bindCredentialsSecret,omitempty"`
	// Cache Policy for this storage provider. 'DEFAULT' is whatever the default settings are for the global cache.
	// 'EVICT_DAILY' is a time of day every day that the cache will be invalidated. 'EVICT_WEEKLY' is a day of the week
	// and time the cache will be invalidated. 'MAX_LIFESPAN' is the time in milliseconds that will be the lifespan of a
	// cache entry.
	// +kubebuilder:validation:Enum=DEFAULT;EVICT_DAILY;EVICT_WEEKLY;MAX_LIFESPAN
	// +kubebuilder:default="DEFAULT"
	CachePolicy string `json:"cachePolicy,omitempty"`
	// Day of the week the entry will become invalid
	// +kubebuilder:validation:Enum=monday;tuesday;wednesday;thursday;friday;saturday;sunday
	// +kubebuilder:default="sunday"
	EvictionDay string `json:"evictionDay,omitempty"`
	// Hour of the day the entry will become invalid (when selecting 'EVICT_DAILY' or 'EVICT_WEEKLY' cachePolicy)
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=23
	// +kubebuilder:default=0
	EvictionHour int `json:"evictionHour,omitempty"`
	// Minute of the hour the entry will become invalid (when selecting 'EVICT_DAILY' or 'EVICT_WEEKLY' cachePolicy)
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=59
	// +kubebuilder:default=0
	EvictionMinute int `json:"evictionMinute,omitempty"`
	// Max lifespan of cache entry in milliseconds (when selecting 'MAX_LIFESPAN' cachePolicy)
	// +kubebuilder:default=86400000
	MaxLifespan int `json:"maxLifespan,omitempty"`
	// Period for synchronization of changed or newly created LDAP users in seconds
	ChangedSyncPeriod *metav1.Duration `json:"changedSyncPeriod,omitempty"`
	// Determines if Keycloak should use connection pooling for accessing LDAP server.
	// +kubebuilder:default=false
	ConnectionPooling bool `json:"connectionPooling"`
	// If enabled, incoming and outgoing LDAP ASN.1 BER packets will be dumped to the error output stream.
	// Be careful when enabling this option in production as it will expose all data sent to and from the LDAP server.
	// +kubebuilder:default=false
	ConnectionTrace bool `json:"connectionTrace,omitempty"`
	// Connection URL to your LDAP server
	// +required
	ConnectionUrl string `json:"connectionUrl"`
	// LDAP connection timeout in milliseconds
	ConnectionTimeout *metav1.Duration `json:"connectionTimeout,omitempty"`
	// READ_ONLY is a read-only LDAP store. WRITABLE means data will be synced back to LDAP on demand.
	// UNSYNCED means user data will be imported, but not synced back to LDAP.
	// +kubebuilder:validation:Enum=READ_ONLY;WRITABLE;UNSYNCED
	// +kubebuilder:default="READ_ONLY"
	EditMode string `json:"editMode,omitempty"`
	// Enable or disable the LDAP federation
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`
	// Period for full synchronization in seconds
	FullSyncPeriod *metav1.Duration `json:"fullSyncPeriod,omitempty"`
	// If true, LDAP users will be imported into the Keycloak DB and synced by the configured sync policies.
	// +kubebuilder:default=true
	ImportEnabled bool `json:"importEnabled"`
	// Whether the LDAP server supports pagination
	// +kubebuilder:default=false
	Pagination bool `json:"pagination"`
	// +kubebuilder:default=0
	Priority int `json:"priority"`
	// Name of the LDAP attribute, which is used as RDN (top attribute) of typical user DN. Usually it's the same as the Username LDAP attribute,
	// however it is not required. For example for Active directory, it is common to use 'cn' as RDN attribute when username attribute might be 'sAMAccountName'.
	// +kubebuilder:default=cn
	RdnLDAPAttribute string `json:"rdnLDAPAttribute,omitempty"`
	// Name of the LDAP federation
	// +required
	Name string `json:"name"`
	// Whether periodic synchronization of changed or newly created LDAP users to Keycloak should be enabled or not
	// +kubebuilder:default=false
	PeriodicChangedUsersSync bool `json:"periodicChangedUsersSync"`
	// Whether periodic full synchronization of LDAP users to Keycloak should be enabled or not
	// +kubebuilder:default=false
	PeriodicFullSync bool `json:"periodicFullSync"`
	// For one level, the search applies only for users in the DNs specified by User DNs. For subtree, the search applies to the whole subtree.
	// See LDAP documentation for more details.
	// +kubebuilder:validation:Enum="1";"2"
	// +kubebuilder:default="2"
	SearchScope string `json:"searchScope"`
	// Encrypts the connection to LDAP using STARTTLS, which will disable connection pooling
	// +kubebuilder:default=false
	StartTls bool `json:"startTls"`
	// +kubebuilder:default=false
	SyncRegistrations bool `json:"syncRegistrations"`
	// +kubebuilder:default=false
	TrustEmail bool `json:"trustEmail"`
	// User Kerberos login module for authenticating username/password against Kerberos server instead of authenticating against
	// LDAP server with Directory Service API
	// +kubebuilder:default=false
	UseKerberosForPasswordAuthentication bool `json:"useKerberosForPasswordAuthentication,omitempty"`
	// Name of the LDAP attribute, which refers to Kerberos principal. This is used to lookup appropriate LDAP user after successful
	// Kerberos/SPNEGO authentication in Keycloak. When this is empty, the LDAP user will be looked based on LDAP username corresponding
	//  to the first part of his Kerberos principal. For instance, for principal 'john@KEYCLOAK.ORG', it will assume that LDAP username is 'john'.
	// +kubebuilder:default=userPrincipalName
	KrbPrincipalAttribute string `json:"krbPrincipalAttribute"`
	// Name of kerberos realm. For example, FOO.ORG.
	// +optional
	KerberosRealm string `json:"kerberosRealm,omitempty"`
	// Full name of server principal for HTTP service including server and domain name. For example, HTTP/host.foo.org@FOO.ORG
	// +optional
	ServerPrincipal string `json:"serverPrincipal,omitempty"`
	// Location of Kerberos KeyTab file containing the credentials of server principal. For example, /etc/krb5.keytab
	// +optional
	KeyTab string `json:"keyTab"`
	// Enable/disable debug logging to standard output for Krb5LoginModule.
	// +kubebuilder:default=false
	Debug bool `json:"debug"`
	// Use the LDAPv3 Password Modify Extended Operation (RFC-3062). The password modify extended operation usually requires that
	// LDAP user already has password in the LDAP server. So when this is used with 'Sync Registrations', it can be good to add
	// also 'Hardcoded LDAP attribute mapper' with randomly generated initial password.
	// +kubebuilder:default=false
	UsePasswordModifyExtendedOp bool `json:"usePasswordModifyExtendedOp"`
	// Specifies whether LDAP connection will use the Truststore SPI with the truststore configured in standalone.xml/domain.sml.
	// 'always' means that it will always use it. 'never' means that it will not use it. 'ldapsOnly' means that it will use
	// it if your connection URL use ldaps. Note that even if standalone.xml/domain.xml is not configured, the default java cacerts
	// or certificate specified by 'javax.net.ssl.trustStore' property will be used.
	// +kubebuilder:validation:Enum=always;ldapsOnly;never
	// +kubebuilder:default=ldapsOnly
	UseTruststoreSpi string `json:"useTruststoreSpi"`
	// All values of LDAP objectClass attribute for users in LDAP, divided by commas. For example: 'inetOrgPerson, organizationalPerson'.
	// Newly created Keycloak users will be written to LDAP with all those object classes and existing LDAP user records are found just
	// if they contain all those object classes.
	// +kubebuilder:default={'person'}
	UserObjectClasses []string `json:"userObjectClasses"`
	// Name of the LDAP attribute, which is mapped as Keycloak username. For many LDAP server vendors it can be 'uid'. For Active directory
	// it can be 'sAMAccountName' or 'cn'. The attribute should be filled for all LDAP user records you want to import from LDAP to Keycloak.
	// +kubebuilder:default=samaccountname
	UsernameLDAPAttribute string `json:"usernameLDAPAttribute,omitempty"`
	// Full DN of LDAP tree where your users are. This DN is the parent of LDAP users. It could be for example 'ou=users,dc=example,dc=com'
	// assuming that your typical user will have DN like 'uid='john',ou=users,dc=example,dc=com'.
	// +required
	UsersDn string `json:"usersDn,omitempty"`
	// Name of the LDAP attribute, which is used as a unique object identifier (UUID) for objects in LDAP. For many LDAP server vendors, it is
	// 'entryUUID'; however some are different. For example, for Active directory it should be 'objectGUID'. If your LDAP server does not support
	// the notion of UUID, you can use any other attribute that is supposed to be unique among LDAP users in tree. For example 'uid' or 'entryDN'.
	// +kubebuilder:default=objectGUID
	UuidLDAPAttribute string `json:"uuidLDAPAttribute,omitempty"`
	// Determines if Keycloak should validate the password with the realm password policy before updating it
	// +kubebuilder:default=false
	ValidatePasswordPolicy bool `json:"validatePasswordPolicy"`
	// LDAP vendor (provider)
	// +kubebuilder:validation:Enum=ad;rhds;other;tivoli;edirectory
	// +required
	Vendor string `json:"vendor,omitempty"`
}

var evictionDayMapper = map[string]string{
	"sunday":    "1",
	"monday":    "2",
	"tuesday":   "3",
	"wednesday": "4",
	"thursday":  "5",
	"friday":    "6",
	"saturday":  "7",
}

func (ldap *LdapFederation) ToComponent(ctx context.Context, c client.Client, ns string) (*gocloak.Component, error) {
	cfg := map[string][]string{
		"allowKerberosAuthentication":          {strconv.FormatBool(ldap.AllowKerberosAuthentication)},
		"batchSizeForSync":                     {strconv.Itoa(ldap.BatchSizeForSync)},
		"cachePolicy":                          {ldap.CachePolicy},
		"changedSyncPeriod":                    {strconv.Itoa(int(ldap.ChangedSyncPeriod.Duration.Seconds()))},
		"connectionUrl":                        {ldap.ConnectionUrl},
		"connectionTimeout":                    {strconv.Itoa(int(ldap.ConnectionTimeout.Duration.Milliseconds()))},
		"editMode":                             {ldap.EditMode},
		"enabled":                              {strconv.FormatBool(ldap.Enabled)},
		"fullSyncPeriod":                       {strconv.Itoa(int(ldap.FullSyncPeriod.Duration.Seconds()))},
		"importEnabled":                        {strconv.FormatBool(ldap.ImportEnabled)},
		"pagination":                           {strconv.FormatBool(ldap.Pagination)},
		"priority":                             {strconv.Itoa(ldap.Priority)},
		"rdnLDAPAttribute":                     {ldap.RdnLDAPAttribute},
		"searchScope":                          {ldap.SearchScope},
		"startTls":                             {strconv.FormatBool(ldap.StartTls)},
		"syncRegistrations":                    {strconv.FormatBool(ldap.SyncRegistrations)},
		"trustEmail":                           {strconv.FormatBool(ldap.TrustEmail)},
		"useKerberosForPasswordAuthentication": {strconv.FormatBool(ldap.UseKerberosForPasswordAuthentication)},
		"useTruststoreSpi":                     {ldap.UseTruststoreSpi},
		"usePasswordModifyExtendedOp":          {strconv.FormatBool(ldap.UsePasswordModifyExtendedOp)},
		"userObjectClasses":                    {strings.Join(ldap.UserObjectClasses, ", ")},
		"usernameLDAPAttribute":                {ldap.UsernameLDAPAttribute},
		"usersDn":                              {ldap.UsersDn},
		"uuidLDAPAttribute":                    {ldap.UuidLDAPAttribute},
		"validatePasswordPolicy":               {strconv.FormatBool(ldap.ValidatePasswordPolicy)},
		"vendor":                               {strings.ToLower(ldap.Vendor)},
		"krbPrincipalAttribute":                {ldap.KrbPrincipalAttribute},
		"debug":                                {strconv.FormatBool(ldap.Debug)},
		"connectionPooling":                    {strconv.FormatBool(ldap.ConnectionPooling)},
		"connectionTrace":                      {strconv.FormatBool(ldap.ConnectionTrace)},
	}

	// Authentication options
	if ldap.BindCredentialsSecret != "" {
		secret := &corev1.Secret{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: ldap.BindCredentialsSecret}, secret); err != nil {
			return &gocloak.Component{}, err
		}
		bindDn, ok := secret.Data["bind_dn"]
		if !ok {
			return &gocloak.Component{}, fmt.Errorf("Cannot find key `bind_dn` in secret/%s (namespace: %s)", ldap.BindCredentialsSecret, ns)
		}
		bindPassword, ok := secret.Data["bind_password"]
		if !ok {
			return &gocloak.Component{}, fmt.Errorf("Cannot find key `bind_password` in secret/%s (namespace: %s)", ldap.BindCredentialsSecret, ns)
		}
		cfg["bindDn"] = []string{string(bindDn[:])}
		cfg["bindCredential"] = []string{string(bindPassword[:])}
		cfg["authType"] = []string{"simple"}
	} else {
		cfg["authType"] = []string{"none"}
	}

	// Cache policy options
	cfg["cachePolicy"] = []string{ldap.CachePolicy}
	switch ldap.CachePolicy {
	case "EVICT_DAILY":
		cfg["evictionHour"] = []string{strconv.Itoa(ldap.EvictionHour)}
		cfg["evictionMinute"] = []string{strconv.Itoa(ldap.EvictionMinute)}
	case "EVICT_WEEKLY":
		day, ok := evictionDayMapper[ldap.EvictionDay]
		if !ok {
			return &gocloak.Component{}, fmt.Errorf("Unsupported day '%s' in evictionDay", ldap.EvictionDay)
		}
		cfg["evictionDay"] = []string{day}
		cfg["evictionHour"] = []string{strconv.Itoa(ldap.EvictionHour)}
		cfg["evictionMinute"] = []string{strconv.Itoa(ldap.EvictionMinute)}
	case "MAX_LIFESPAN":
		cfg["maxLifespan"] = []string{strconv.Itoa(ldap.MaxLifespan)}
	default:
	}

	component := &gocloak.Component{
		Name:            &ldap.Name,
		ProviderID:      &LDAP_PROVIDER,
		ProviderType:    &USER_STORAGE_PROVIDER,
		ComponentConfig: &cfg,
	}
	return component, nil
}

// KeycloakLDAPFederationStatus defines the observed state of KeycloakLDAPFederation
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:validation:Optional
type KeycloakLDAPFederationStatus struct {
	// ID of the component representing the managed LDAP federation
	ComponentID string `json:"componentID,omitempty"`
	// Result of the last successful sync
	// +optional
	Result *gocloak.LDAPSyncResult `json:"result,omitempty"`
	// Base status
	// +optional
	Api ApiStatus `json:"api,omitempty"`
}

func (i *KeycloakLDAPFederation) Realm() string              { return i.Spec.Realm }
func (i *KeycloakLDAPFederation) Endpoint() EndpointSelector { return i.Spec.Endpoint }
func (i *KeycloakLDAPFederation) ApiStatus() *ApiStatus      { return &i.Status.Api }

// KeycloakLDAPFederationList contains a list of KeycloakLDAPFederation
// +kubebuilder:object:root=true
type KeycloakLDAPFederationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeycloakLDAPFederation `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeycloakLDAPFederation{}, &KeycloakLDAPFederationList{})
}
