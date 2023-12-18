/*
Copyright 2023.

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
	"fmt"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/japannext/keycloak-operator/gocloak"
)

// KeycloakLDAPMapper is the Schema for the keycloakldapmappers API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:shortName=kldapmapper,categories=keycloak
// +kubebuilder:printcolumn:name="TYPE",type="string",JSONPath=".spec.type"
// +kubebuilder:printcolumn:name="STATUS",type="string",JSONPath=".status.api.phase"
// +kubebuilder:printcolumn:name="LAST CHANGED",priority=1,type="date",JSONPath=".status.api.lastTransitionTime",description="The last time the resource was changed"
type KeycloakLDAPMapper struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KeycloakLDAPMapperSpec   `json:"spec,omitempty"`
	Status KeycloakLDAPMapperStatus `json:"status,omitempty"`
}

// KeycloakLDAPMapperSpec defines the desired state of KeycloakLDAPMapper
type KeycloakLDAPMapperSpec struct {
	Endpoint EndpointSelector `json:"endpoint,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	Realm string `json:"realm"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	Federation string `json:"federation"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	// +kubebuilder:validation:Enum=user-attribute-ldap-mapper;group-ldap-mapper;role-ldap-mapper
	Type string `json:"type"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	Name string `json:"name"`
	// +optional
	GroupLdapMapper *GroupLdapMapper `json:"groupLdapMapper,omitempty"`
	// +optional
	UserAttributeLdapMapper *UserAttributeLdapMapper `json:"userAttributeLdapMapper,omitempty"`
	// +optional
	RoleLdapMapper *RoleLdapMapper `json:"roleLdapMapper,omitempty"`
	// +optional
	FullNameLdapMapper *FullNameLdapMapper `json:"fullNameLdapMapper,omitempty"`
	// +optional
	CertificateLdapMapper *CertificateLdapMapper `json:"certificateLdapMapper,omitempty"`
	// +optional
	HardcodedLdapGroupMapper *HardcodedLdapGroupMapper `json:"hardcodedLdapGroupMapper,omitempty"`
	// +optional
	HardcodedLdapAttributeMapper *HardcodedLdapAttributeMapper `json:"hardcodedLdapAttributeMapper,omitempty"`
	// +optional
	HardcodedAttributeMapper *HardcodedAttributeMapper `json:"hardcodedAttributeMapper,omitempty"`
	// +optional
	HardcodedLdapRoleMapper *HardcodedLdapRoleMapper `json:"hardcodedLdapRoleMapper,omitempty"`
	// +optional
	MSADUserAccountControlMapper *MSADUserAccountControlMapper `json:"msadUserAccountControlMapper,omitempty"`
}

func (i *KeycloakLDAPMapper) ToComponent(fid string) (*gocloak.Component, error) {
	var cfg map[string][]string
	switch i.Spec.Type {
	case "group-ldap-mapper":
		cfg = i.Spec.GroupLdapMapper.ToComponentConfig()
	case "user-attribute-ldap-mapper":
		cfg = i.Spec.UserAttributeLdapMapper.ToComponentConfig()
	case "role-ldap-mapper":
		cfg = i.Spec.RoleLdapMapper.ToComponentConfig()
	case "full-name-ldap-mapper":
		cfg = i.Spec.FullNameLdapMapper.ToComponentConfig()
	case "certificate-ldap-mapper":
		cfg = i.Spec.CertificateLdapMapper.ToComponentConfig()
	case "hardcoded-ldap-group-mapper":
		cfg = i.Spec.HardcodedLdapGroupMapper.ToComponentConfig()
	case "hardcoded-ldap-attribute-mapper":
		cfg = i.Spec.HardcodedLdapAttributeMapper.ToComponentConfig()
	case "hardcoded-attribute-mapper":
		cfg = i.Spec.HardcodedAttributeMapper.ToComponentConfig()
	case "hardcoded-ldap-role-mapper":
		cfg = i.Spec.HardcodedLdapRoleMapper.ToComponentConfig()
	case "msad-user-account-control-mapper":
		cfg = i.Spec.MSADUserAccountControlMapper.ToComponentConfig()
	case "msad-lds-user-account-control-mapper":
		cfg = map[string][]string{}
	default:
		return &gocloak.Component{}, fmt.Errorf("Unsupported type: '%s'", i.Spec.Type)
	}
	return &gocloak.Component{
		Name:            &i.Spec.Name,
		ProviderType:    &LDAP_STORAGE_MAPPER,
		ProviderID:      &i.Spec.Type,
		ParentID:        &fid,
		ComponentConfig: &cfg,
	}, nil
}

// +kubebuilder:object:generate=true
type UserAttributeLdapMapper struct {
	// If on, then during reading of the LDAP attribute value will always used instead of the
	// value from Keycloak DB
	// +kubebuilder:default=false
	AlwaysReadValueFromLdap bool `json:"alwaysReadValueFromLdap"`
	// If there is no value in Keycloak DB and attribute is mandatory in LDAP, this value will
	// be propagated to LDAP
	// +kubebuilder:default=""
	AttributeDefaultValue string `json:"attributeDefaultValue"`
	// Should be true for binary LDAP attributes
	// +kubebuilder:default=false
	IsBinaryAttribute bool `json:"isBinaryAttribute"`
	// If true, attribute is mandatory in LDAP. Hence if there is no value in Keycloak DB,
	// the default or empty value will be set to be propagated to LDAP
	// +kubebuilder:default=false
	IsMandatoryInLdap bool `json:"isMandatoryInLdap"`
	// Name of mapped attribute on LDAP object. For example 'cn', 'sn, 'mail', 'street' etc.
	// +kubebuilder:default=""
	LdapAttribute string `json:"ldapAttribute"`
	// +kubebuilder:default=true
	// Read-only attribute is imported from LDAP to UserModel, but it's not saved back to LDAP when
	// user is updated in Keycloak.
	ReadOnly bool `json:"readOnly"`
	// Name of the UserModel property or attribute you want to map the LDAP attribute into.
	// For example 'firstName', 'lastName, 'email', 'street' etc.
	// +kubebuilder:default=""
	UserModelAttribute string `json:"userModelAttribute"`
}

func (m *UserAttributeLdapMapper) ToComponentConfig() map[string][]string {
	return map[string][]string{
		"ldap.attribute":              {m.LdapAttribute},
		"is.mandatory.in.ldap":        {strconv.FormatBool(m.IsMandatoryInLdap)},
		"read.only":                   {strconv.FormatBool(m.ReadOnly)},
		"always.read.value.from.ldap": {strconv.FormatBool(m.AlwaysReadValueFromLdap)},
		"user.model.attribute":        {m.UserModelAttribute},
		"attribute.default.value":     {m.AttributeDefaultValue},
		"is.binary.attribute":         {strconv.FormatBool(m.IsBinaryAttribute)},
	}
}

// +kubebuilder:object:generate=true
type GroupLdapMapper struct {
	// +kubebuilder:default=false
	DropNonExistingGroupsDuringSync bool `json:"dropNonExistingGroupsDuringSync"`
	// Name of LDAP attribute, which is used in group objects for name and RDN of group. Usually it will
	// be 'cn' . In this case typical group/role object may have DN like 'cn=Group1,ou=groups,dc=example,dc=org'
	// +kubebuilder:default="cn"
	GroupNameLdapAttribute string `json:"groupNameLdapAttribute,omitempty"`
	// Object class (or classes) of the group object. It's divided by comma if more classes needed. In typical LDAP
	// deployment it could be 'groupOfNames' . In Active Directory it's usually 'group'
	// +kubebuilder:default={"group"}
	GroupObjectClasses []string `json:"groupObjectClasses,omitempty"`
	// LDAP DN where are groups of this tree saved. For example 'ou=groups,dc=example,dc=org'
	// +required
	GroupsDn string `json:"groupsDn,omitempty"`
	// LDAP Filter adds additional custom filter to the whole query for retrieve LDAP groups. Leave this empty if no
	// additional filtering is needed and you want to retrieve all groups from LDAP. Otherwise make sure that filter
	// starts with '(' and ends with ')'
	// +optional
	GroupsLdapFilter string `json:"groupsLdapFilter,omitempty"`
	// Keycloak group path the LDAP groups are added to. For example if value '/Applications/App1' is used, then LDAP
	// groups will be available in Keycloak under group 'App1', which is child of top level group 'Applications'.
	// The default value is '/' so LDAP groups will be mapped to the Keycloak groups at the top level. The configured
	// group path must already exists in the Keycloak when creating this mapper.
	// +kubebuilder:default="/"
	GroupsPath string `json:"groupsPath"`
	// Ignore missing groups in the group hierarchy
	// +kubebuilder:default=false
	IgnoreMissingGroups bool `json:"ignoreMissingGroups"`
	// +kubebuilder:default=""
	MemberofLdapAttribute string `json:"memberofLdapAttribute"`
	// +kubebuilder:default=""
	MembershipAttributeType string `json:"membershipAttributeType"`
	// +kubebuilder:default=""
	MembershipLdapAttribute string `json:"membershipLdapAttribute"`
	// +kubebuilder:default=""
	MembershipUserLdapAttribute string `json:"membershipUserLdapAttribute"`
	// LDAP_ONLY means that all group mappings of users are retrieved from LDAP and saved into LDAP.
	// READ_ONLY is Read-only LDAP mode where group mappings are retrieved from both LDAP and DB and
	// merged together. New group joins are not saved to LDAP but to DB. IMPORT is Read-only LDAP mode
	// where group mappings are retrieved from LDAP just at the time when user is imported from LDAP and
	// then they are saved to local keycloak DB.
	// +kubebuilder:validation:Enum=IMPORT;LDAP_ONLY;READ_ONLY
	// +kubebuilder:default="READ_ONLY"
	Mode string `json:"mode"`
	// Flag whether group inheritance from LDAP should be propagated to Keycloak. If false, then all LDAP groups
	// will be mapped as flat top-level groups in Keycloak. Otherwise group inheritance is preserved into Keycloak,
	// but the group sync might fail if LDAP structure contains recursions or multiple parent groups per child groups
	// +kubebuilder:default=false
	PreserveGroupInheritance bool `json:"preserveGroupInheritance"`
	// Specify how to retrieve groups of user. LOAD_GROUPS_BY_MEMBER_ATTRIBUTE means that roles of user
	// will be retrieved by sending LDAP query to retrieve all groups where 'member' is our user.
	// GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE means that groups of user will be retrieved from 'memberOf'
	// attribute of our user. Or from the other attribute specified by 'Member-Of LDAP Attribute'.
	// LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY is applicable just in Active Directory and it means that
	// groups of user will be retrieved recursively with usage of LDAP_MATCHING_RULE_IN_CHAIN Ldap extension.
	// +kubebuilder:validation:Enum=GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE;LOAD_GROUPS_BY_MEMBER_ATTRIBUTE;LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY
	// +kubebuilder:default="GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE"
	UserRolesRetrieveStrategy string `json:"userRolesRetrieveStrategy"`
}

func (m *GroupLdapMapper) ToComponentConfig() map[string][]string {
	return map[string][]string{
		"drop.non.existing.groups.during.sync": {strconv.FormatBool(m.DropNonExistingGroupsDuringSync)},
		"group.name.ldap.attribute":            {m.GroupNameLdapAttribute},
		"group.object.classes":                 {strings.Join(m.GroupObjectClasses, ", ")},
		"groups.dn":                            {m.GroupsDn},
		"groups.ldap.filter":                   {m.GroupsLdapFilter},
		"groups.path":                          {m.GroupsPath},
		"ignore.missing.groups":                {strconv.FormatBool(m.IgnoreMissingGroups)},
		"memberof.ldap.attribute":              {m.MemberofLdapAttribute},
		"membership.attribute.type":            {m.MembershipAttributeType},
		"membership.ldap.attribute":            {m.MembershipLdapAttribute},
		"membership.user.ldap.attribute":       {m.MembershipUserLdapAttribute},
		"mode":                                 {m.Mode},
		"preserve.group.inheritance":           {strconv.FormatBool(m.PreserveGroupInheritance)},
		"user.roles.retrieve.strategy":         {m.UserRolesRetrieveStrategy},
	}
}

// +kubebuilder:object:generate=true
type RoleLdapMapper struct {
	// Used just when 'User Roles Retrieve Strategy' is GET_ROLES_FROM_USER_MEMBEROF_ATTRIBUTE.
	// It specifies the name of the LDAP attribute on the LDAP user, which contains the roles
	// (LDAP Groups), which the user is member of. Usually it will be 'memberOf' and that's
	// also the default value.
	// +kubebuilder:default="memberOf"
	MemberofLdapAttribute string `json:"memberofLdapAttribute,omitempty"`
	// +kubebuilder:validation:Enum=DN;UID
	// +kubebuilder:default="DN"
	MembershipAttributeType string `json:"membershipAttributeType,omitempty"`
	// +kubebuilder:default=""
	MembershipLdapAttribute string `json:"membershipLdapAttribute,omitempty"`
	// +kubebuilder:default=""
	MembershipUserLdapAttribute string `json:"membershipUserLdapAttribute,omitempty"`
	// LDAP_ONLY means that all role mappings are retrieved from LDAP and saved into LDAP. READ_ONLY
	// is Read-only LDAP mode where role mappings are retrieved from both LDAP and DB and merged together.
	// New role grants are not saved to LDAP but to DB. IMPORT is Read-only LDAP mode where role mappings are
	// retrieved from LDAP just at the time when user is imported from LDAP and then they are saved to local keycloak DB.
	// +kubebuilder:validation:Enum=READ_ONLY;IMPORT;LDAP_ONLY
	// +kubebuilder:default="READ_ONLY"
	Mode string `json:"mode"`
	// +optional
	RoleObjectClasses []string `json:"roleObjectClasses,omitempty"`
	// +kubebuilder:default=""
	RolesDn string `json:"rolesDn,omitempty"`
	// If true, then LDAP role mappings will be mapped to realm role mappings in Keycloak. Otherwise it will be mapped to client role mappings
	// +kubebuilder:default=true
	UseRealmRolesMapping bool `json:"useRealmRoleMapping"`
	// Specify how to retrieve groups of user. LOAD_GROUPS_BY_MEMBER_ATTRIBUTE means that roles of user
	// will be retrieved by sending LDAP query to retrieve all groups where 'member' is our user.
	// GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE means that groups of user will be retrieved from 'memberOf'
	// attribute of our user. Or from the other attribute specified by 'Member-Of LDAP Attribute'.
	// LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY is applicable just in Active Directory and it means that
	// groups of user will be retrieved recursively with usage of LDAP_MATCHING_RULE_IN_CHAIN Ldap extension.
	// +kubebuilder:validation:Enum=GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE;LOAD_GROUPS_BY_MEMBER_ATTRIBUTE;LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY
	// +kubebuilder:default="LOAD_GROUPS_BY_MEMBER_ATTRIBUTE"
	UserRolesRetrieveStrategy string `json:"userRolesRetrieveStrategy"`
}

func (m *RoleLdapMapper) ToComponentConfig() map[string][]string {
	return map[string][]string{
		"memberof.ldap.attribute":        {m.MemberofLdapAttribute},
		"membership.attribute.type":      {m.MembershipAttributeType},
		"membership.ldap.attribute":      {m.MembershipLdapAttribute},
		"membership.user.ldap.attribute": {m.MembershipUserLdapAttribute},
		"mode":                           {m.Mode},
		// "role.name.ldap.attribute":       {m.RoleNameLdapAttribute},
		"role.object.classes":          {strings.Join(m.RoleObjectClasses, ",")},
		"roles.dn":                     {m.RolesDn},
		"use.realm.roles.mapping":      {strconv.FormatBool(m.UseRealmRolesMapping)},
		"user.roles.retrieve.strategy": {m.UserRolesRetrieveStrategy},
	}
}

// +kubebuilder:object:generate=true
type FullNameLdapMapper struct {
	// +kubebuilder:default="cn"
	LDAPFullNameAttribute string `json:"ldapFullNameAttribute"`
	// +kubebuilder:default=true
	ReadOnly bool `json:"readOnly"`
	// +kubebuilder:default=false
	WriteOnly bool `json:"writeOnly"`
}

func (m *FullNameLdapMapper) ToComponentConfig() map[string][]string {
	return map[string][]string{
		"ldap.full.name.attribute": {m.LDAPFullNameAttribute},
		"read.only":                {strconv.FormatBool(m.ReadOnly)},
		"write.only":               {strconv.FormatBool(m.WriteOnly)},
	}
}

// +kubebuilder:object:generate=true
type CertificateLdapMapper struct {
	// +kubebuilder:default=false
	AlwaysReadValueFromLDAP bool `json:"alwaysReadValueFromLDAP"`
	// +kubebuilder:default=""
	AttributeDefaultValue string `json:"attributeDefaultValue,omitempty"`
	// +kubebuilder:default=""
	LDAPAttribute string `json:"ldapAttribute,omitempty"`
	// +kubebuilder:default=true
	ReadOnly bool `json:"readOnly"`
	// If true, attribute is mandatory in LDAP. Hence if there is no value in Keycloak DB,
	// the default or empty value will be set to be propagated to LDAP
	// +kubebuilder:default=false
	IsMandatoryInLDAP bool `json:"isMandatoryInLDAP"`
	// Should be true for binary LDAP attributes
	// +kubebuilder:default=false
	IsBinaryAttribute bool `json:"isBinaryAttribute"`
	// +kubebuilder:default=false
	IsDERFormatted bool `json:"isDERFormatted"`
	// +kubebuilder:default=""
	UserModelAttribute string `json:"userModelAttribute,omitempty"`
}

func (m *CertificateLdapMapper) ToComponentConfig() map[string][]string {
	return map[string][]string{
		"always.read.value.from.ldap": {strconv.FormatBool(m.AlwaysReadValueFromLDAP)},
		"attribute.default.value":     {m.AttributeDefaultValue},
		"ldap.attribute":              {m.LDAPAttribute},
		"read.only":                   {strconv.FormatBool(m.ReadOnly)},
		"is.mandatory.in.ldap":        {strconv.FormatBool(m.IsMandatoryInLDAP)},
		"is.binary.attribute":         {strconv.FormatBool(m.IsBinaryAttribute)},
		"is.der.formatted":            {strconv.FormatBool(m.IsDERFormatted)},
		"user.model.attribute":        {m.UserModelAttribute},
	}
}

type HardcodedAttributeMapper struct {
	// Name of the model attribute, which will be added when importing user from ldap
	// +kubebuilder:default=""
	UserModelAttributeName string `json:"userModelAttributeName,omitempty"`
	// Value of the model attribute, which will be added when importing user from ldap
	// +kubebuilder:default=""
	AttributeValue string `json:"attributeValue,omitempty"`
}

func (m *HardcodedAttributeMapper) ToComponentConfig() map[string][]string {
	return map[string][]string{
		"user.model.attribute.name": {m.UserModelAttributeName},
		"attribute.value":           {m.AttributeValue},
	}
}

type HardcodedLdapRoleMapper struct {
	// Role to give to the user. For client roles, it should be in the format
	// `<clientID>.<role>`
	Role string `json:"role,omitempty"`
}

func (m *HardcodedLdapRoleMapper) ToComponentConfig() map[string][]string {
	return map[string][]string{
		"role": {m.Role},
	}
}

type HardcodedLdapAttributeMapper struct {
	// Name of the LDAP attribute, which will be added to the new user during registration
	LDAPAttributeName string `json:"ldapAttributeName"`
	// Value of the LDAP attribute, which will be added to the new user during registration.
	// You can either hardcode any value like 'foo' but you can also use some special tokens.
	// Only supported token right now is '${RANDOM}' , which will be replaced with some randomly generated String.
	LDAPAttributeValue string `json:"ldapAttributeValue"`
}

func (m *HardcodedLdapAttributeMapper) ToComponentConfig() map[string][]string {
	return map[string][]string{
		"ldap.attribute.name":  {m.LDAPAttributeName},
		"ldap.attribute.value": {m.LDAPAttributeValue},
	}
}

type HardcodedLdapGroupMapper struct {
	// Group to add the user in. Fill the full path of the group including path.
	// For example '/root-group/child-group'
	Group string `json:"group"`
}

func (m *HardcodedLdapGroupMapper) ToComponentConfig() map[string][]string {
	return map[string][]string{
		"group": {m.Group},
	}
}

type MSADUserAccountControlMapper struct {
	// Applicable just for writable MSAD. If on, then updating password of MSAD user will use
	// LDAP_SERVER_POLICY_HINTS_OID extension, which means that advanced MSAD password policies
	// like 'password history' or 'minimal password age' will be applied. This extension works just
	// for MSAD 2008 R2 or newer.
	// +kubebuilder:default=false
	PasswordPolicyHintsEnabled bool `json:"passwordPolicyHintsEnabled"`
}

func (m *MSADUserAccountControlMapper) ToComponentConfig() map[string][]string {
	return map[string][]string{
		"password.policy.hints.enabled": {strconv.FormatBool(m.PasswordPolicyHintsEnabled)},
	}
}

// KeycloakLDAPMapperStatus defines the observed state of KeycloakLDAPMapper
type KeycloakLDAPMapperStatus struct {
	// ID of the component representing the managed LDAP mapper
	ComponentID string `json:"componentID,omitempty"`
	// ID of the LDAP Federation it belongs to
	FederationID string `json:"federationID,omitempty"`
	// Result of the last successful sync
	// +optional
	Result *gocloak.LDAPSyncResult `json:"result,omitempty"`
	// Base status
	// +optional
	Api ApiStatus `json:"api,omitempty"`
}

func (i *KeycloakLDAPMapper) Realm() string              { return i.Spec.Realm }
func (i *KeycloakLDAPMapper) Endpoint() EndpointSelector { return i.Spec.Endpoint }
func (i *KeycloakLDAPMapper) ApiStatus() *ApiStatus      { return &i.Status.Api }

// KeycloakLDAPMapperList contains a list of KeycloakLDAPMapper
// +kubebuilder:object:root=true
type KeycloakLDAPMapperList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeycloakLDAPMapper `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KeycloakLDAPMapper{}, &KeycloakLDAPMapperList{})
}
