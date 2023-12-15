package v1alpha2

import (
	diff "github.com/r3labs/diff/v3"
)

var (
	LDAP_STORAGE_MAPPER        = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
	USER_STORAGE_PROVIDER      = "org.keycloak.storage.UserStorageProvider"
	ROLE_LDAP_MAPPER           = "role-ldap-mapper"
	USER_ATTRIBUTE_LDAP_MAPPER = "user-attribute-ldap-mapper"
	GROUP_LDAP_MAPPER          = "group-ldap-mapper"
	LDAP_PROVIDER              = "ldap"
)

func allKeys(x, y *map[string][]string) []string {
	set := make(map[string]bool)
	for k, _ := range *x {
		set[k] = true
	}
	for k, _ := range *y {
		set[k] = true
	}
	keys := make([]string, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	return keys
}

var excludedKeys = map[string]bool{"bindCredential": true, "lastSync": true}

// Return a diff of 2 component config
func DiffComponentConfigs(x, y *map[string][]string) diff.Changelog {
	changes := []diff.Change{}

	for _, k := range allKeys(x, y) {
		if _, skip := excludedKeys[k]; skip {
			continue
		}

		vx, ix := (*x)[k]
		vy, iy := (*y)[k]

		// Catching edge cases that may not happen
		if !ix && !iy {
			continue
		}
		if len(vx) == 0 && len(vy) == 0 {
			continue
		}

		if !ix || len(vx) == 0 {
			changes = append(changes, diff.Change{Type: diff.DELETE, Path: []string{k}, From: vy[0]})
			continue
		}
		if !iy || len(vy) == 0 {
			changes = append(changes, diff.Change{Type: diff.CREATE, Path: []string{k}, To: vx[0]})
			continue
		}
		if vx[0] != vy[0] {
			changes = append(changes, diff.Change{Type: diff.UPDATE, Path: []string{k}, From: vx[0], To: vy[0]})
			continue
		}
	}
	return changes
}
