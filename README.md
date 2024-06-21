# keycloak-operator

An operator for managing keycloak resources in kubernetes.

## Description

When managing a keycloak in kubernetes, configuration of its internal resources (realms, openid clients, users, groups, and LDAP federations)
can be a challenge. While it can be achieved with terraform, it has some drawbacks:
* Bootstrap requires to run terraform after deploying the helm chart.
* Managing multiple instances for testing is harder, since multiple terraform recipes are required (or source files).
* Deleting/redeploying everything requires us to delete the terraform state file.
* Restoring backups can cause issues, because of the terraform state.
* On-demand openid clients (for non-admin teams) are not easily possible.

Overall, we felt the need for a kubernetes-integrated solution.

## Features

* Realms
* Clients (OIDC/SAML)
* Client roles
* Client role mappings (to existing user and groups)
* LDAP user federation
* LDAP mappers (user-attribute/group/role)
* LDAP user federation sync (trigger the initial sync to populate user and groups)
* A LDAP sync is automatically triggered when create/update a LDAP user federation or LDAP mapper
* A rule system to complete the kubernetes RBAC rules when using a KeycloakClusterEndpoint

## Installation/Setup

```bash
helm install keycloak-operator oci://ghcr.io/japannext/helm-charts/keycloak-operator --version 1.1.4
```

> You can install the operator in the namespace of your choice.

Create an endpoint to an existing keycloak:
```yaml
---
apiVersion: keycloak.japannext.co.jp/v1alpha2
kind: KeycloakClusterEndpoint
metadata:
  name: keycloak
spec:
  baseUrl: https://keycloak.example.com
  # The admin realm to use
  realm: master
  # Reference to secret containing the keycloak admin user/password
  basicAuthSecret:
    name: keycloak-admin
    namespace: mgmt
  # Reference to CA certificate
  caConfigMap:
    key: ca.crt
    name: ca-bundle
    namespace: mgmt
```

> You need to create a secret with `username` and `password` keys set
> (e.g. a [basic authentication secret](https://kubernetes.io/docs/concepts/configuration/secret/#basic-authentication-secret)).
> This should be the admin user/password, and it's usually used to access the `master` realm.

Once created, you should see the following (if successful):
```console
> kubectl get kce
NAME       VERSION   STATUS
keycloak   19.0.3    Connected
```

You can then create a realm like so:
```yaml
---
apiVersion: keycloak.japannext.co.jp/v1alpha2
kind: KeycloakRealm
metadata:
  name: example
  namespace: mgmt
spec:
  endpoint:
    kind: KeycloakClusterRealm
    name: keycloak
  config:
    name: example
    display_name: Example CORP
    enabled: true
```

## User RBAC

When using a KeycloakEndpoint, one must pass a secret containing the keycloak admin credentials.
This contains the creation of resources to the same namespace, so whoever has access to the secret
can also use the operator with the same permissions.

When using a KeycloakClusterEndpoint, things are different. Anyone that can create a keycloak resource
can have access to the endpoint, effectively making user of other namespace keycloak admin.
This can be combatted by restricting the keycloak resources that can be created in each namespace,
but this doesn't account for keycloak specifics (realms).

In order to restrict things, and provide features like namespace protection, a rule system was introduced
to restrict certain namespaces

Here is an example of a typical use-case. A specific realm is protected (it can only be managed in
a specific namespace), while other namespaces can still create a limited set of resources that make
sense (to connect their applications to OpenID Connect in this case).

```yaml
apiVersion: keycloak.japannext.co.jp/v1alpha2
kind: KeycloakClusterEndpoint
metadata:
  name: keycloak
  # [...]
spec:
  # [...]

  # Include rule (have precedence over excludeRules)
  rules:
  # Allow a "mgmt" namespace to manage the "japannext" realm
  # Use-case: Reserve for the administrator for automated setup/configuration.
  - name: Administrators
    action: allow
    namespaces: [mgmt]
    realms: ["*"]
    resources: ["*"]

  # Allow all other namespaces to only manage clients/client roles/etc in this realm.
  # Use-case: Developers can connect new services to the system, and provide roles.
  - name: Developers
    action: allow
    namespaces: ["*"]
    realms: [japannext]
    resources:
    - KeycloakClient
    - KeycloakClientRole
    - KeycloakClientProtocolMapper

  # A namespace used for managing user-to-role mapping.
  # Use-case: Security team/Administrators can manage what user/group access to keycloak roles
  - name: Policy
    action: allow
    namespaces: [policy]
    realms: [japannext]
    resources:
    - KeycloakClientRoleMapping

  # By default, the "japannext" realm is protected
  - name: protected-realms
    action: reject
    namespaces: ["*"]
    realms: [japannext, master]
    resources: ["*"]

  # If no rule matches, it's allowed
```

Naturally, to make it possible, access to the KeycloakClusterEndpoint resource need
to be restricted to administrators only.

# Contributing

If you wish to help developing keycloak-operator, check [CONTRIBUTING.md](./CONTRIBUTING.md).
