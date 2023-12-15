package utils

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/japannext/keycloak-operator/api/v1alpha2"
)

const FORBIDDEN = "Forbidden"
const DEFAULT_ALLOW_RULE = "default-allow-rule"

// Check if at least one rule matches among a list of rules
func isForbidden(rules []api.Rule, i client.Object, realm string) (bool, string) {
	for _, rule := range rules {
		if rule.Match(i, realm) {
			switch rule.Action {
			case "allow":
				return false, rule.Name
			case "reject":
				return true, rule.Name
			default:
				return true, rule.Name
			}
		}
	}
	return false, DEFAULT_ALLOW_RULE
}
