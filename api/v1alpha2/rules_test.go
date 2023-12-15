package v1alpha2

import (
	"testing"

	// metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/assert"
)

func TestContains(t *testing.T) {
	assert := assert.New(t)
	array := []string{"a", "b", "c"}
	assert.Equal(contains(array, "c"), true, "should contain 'c'")
	assert.Equal(contains(array, "d"), false, "should not contain 'd'")
	assert.Equal(contains([]string{}, "x"), true, "empty array should return true")
	assert.Equal(contains([]string{"*"}, "x"), true, "wildcard should return true")
}

/*
func TestIsForbidden(t *testing.T) {
	assert := assert.New(t)
	rules := []Rule{
		{Name: "admin", Action: "allow", Namespaces: []string{"admin"}},
		{Name: "dev", Action: "allow", Realms: []string{"example"}, Resources: []string{"KeycloakClient", "KeycloakClientRole", "KeycloakClientProtocolMapper"}},
		{Name: "sec", Action: "allow", Namespaces: []string{"policy"}, Realms: []string{"example"}, Resources: []string{"KeycloakClientRoleMapping"}},
		{Name: "protect", Action: "reject", Realms: []string{"example"}},
	}

	i1 := &KeycloakLDAPFederation{
		TypeMeta:   metav1.TypeMeta{APIVersion: "keycloak.japannext.co.jp/v1alpha2", Kind: "KeycloakLDAPFederation"},
		ObjectMeta: metav1.ObjectMeta{Name: "mycorp", Namespace: "admin"},
		Spec:       KeycloakLDAPFederationSpec{Realm: "example"},
	}

	ok, name := IsForbidden(rules, i1, i1.Spec.Realm)
	assert.Equal(false, ok, "Should be allowed")
	assert.Equal("admin", name, "Should match 'admin' rule")

	i2 := &KeycloakClient{
		TypeMeta:   metav1.TypeMeta{APIVersion: "keycloak.japannext.co.jp/v1alpha2", Kind: "KeycloakClient"},
		ObjectMeta: metav1.ObjectMeta{Name: "myapp", Namespace: "dev1"},
		Spec:       KeycloakClientSpec{Realm: "example"},
	}
	ok, name = IsForbidden(rules, i2, i2.Spec.Realm)
	assert.Equal(false, ok, "Should be allowed")
	assert.Equal("dev", name, "Should match 'dev' rule")

	i3 := &KeycloakClientRoleMapping{
		TypeMeta:   metav1.TypeMeta{APIVersion: "keycloak.japannext.co.jp/v1alpha2", Kind: "KeycloakClientRoleMapping"},
		ObjectMeta: metav1.ObjectMeta{Name: "group1-to-role1", Namespace: "policy"},
		Spec:       KeycloakClientRoleMappingSpec{Realm: "example"},
	}
	ok, name = IsForbidden(rules, i3, i3.Spec.Realm)
	assert.Equal(false, ok, "Should be allowed")
	assert.Equal("sec", name, "Should match 'sec' rule")

	i4 := &KeycloakLDAPFederation{
		TypeMeta:   metav1.TypeMeta{APIVersion: "keycloak.japannext.co.jp/v1alpha2", Kind: "KeycloakLDAPFederation"},
		ObjectMeta: metav1.ObjectMeta{Name: "mycorp", Namespace: "dev1"},
		Spec:       KeycloakLDAPFederationSpec{Realm: "dev_realm"},
	}
	ok, name = IsForbidden(rules, i4, i4.Spec.Realm)
	assert.Equal(false, ok, "Should be allowed")
	assert.Equal("default-allow-rule", name, "Should match default rule")

	i5 := &KeycloakRealm{
		TypeMeta:   metav1.TypeMeta{APIVersion: "keycloak.japannext.co.jp/v1alpha2", Kind: "KeycloakRealm"},
		ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "dev1"},
	}
	ok, name = IsForbidden(rules, i5, "example")
	assert.Equal(true, ok, "Should be forbidden")
	assert.Equal("protect", name, "Should match 'protect' rule")
}
*/
