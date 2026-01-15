# Conjur-in-Go Roadmap

This document outlines the features we aim to implement to replicate [CyberArk Conjur](https://github.com/cyberark/conjur) in Go.

## Current State

The project currently has implementations of:
- **Secrets API** - GET/POST secrets with RBAC, versioning, batch operations, expiration ✅
- **Authentication** - Pluggable authenticator framework with `authn` and `authn-jwt` ✅
- **Slosilo** - Go port of the cryptographic library (symmetric encryption, key signing) ✅
- **Policy Engine** - YAML policy parser and loader with GORM models ✅
- **Database Migrations** - 40+ migrations matching Ruby Conjur schema ✅
- **CLI (conjurctl)** - Server, db migrate, account create, policy load ✅
- **Host Factories** - Token creation, revocation, and host enrollment ✅
- **Integration Tests** - Cucumber/Godog feature tests (20 scenarios) ✅

---

## Phase 1: Foundation ✅ COMPLETE

### 1.1 Database Migrations ✅
**Status: Complete**

Using golang-migrate with SQL migration files in `db/migrations/`.

**Core Tables:**
- [x] `slosilo_keystore` - Encrypted key storage
- [x] `roles` - Identity/principal storage
- [x] `resources` - Protected resources (variables, webservices, etc.)
- [x] `role_memberships` - Role hierarchy and membership
- [x] `permissions` - RBAC permission grants
- [x] `annotations` - Metadata on resources
- [x] `credentials` - API keys and encrypted hashes
- [x] `secrets` - Versioned encrypted secret values
- [x] `policy_versions` - Policy version tracking
- [x] `host_factory_tokens` - Host factory tokens

**Database Functions:**
- [x] `is_role_allowed_to(role_id, privilege, resource_id)` - RBAC check
- [x] `all_roles(role_id)` - Recursive role membership
- [x] `roles_that_can(privilege, resource_id)` - Permission lookup
- [x] ID parsing functions (`account`, `kind`, `identifier`)
- [x] Version auto-increment triggers for secrets

### 1.2 Account Management ✅
**Status: Complete**

- [x] Create account (generates signing key in slosilo keystore) - `conjurctl account create`
- [x] List accounts - `GET /accounts`
- [x] Create account via API - `POST /accounts`
- [x] Delete account - `DELETE /accounts/{id}`

### 1.3 CLI (conjurctl) ✅
**Status: Complete**

- [x] `conjurctl server` - Start HTTP server (with auto-migrations)
- [x] `conjurctl server --no-migrate` - Start without migrations
- [x] `conjurctl account create <name>` - Create a new account
- [x] `conjurctl account delete <name>` - Delete an account
- [x] `conjurctl db migrate` - Run database migrations
- [x] `conjurctl db down [n]` - Rollback migrations (Go-only)
- [x] `conjurctl db status` - Show migration status (Go-only)
- [x] `conjurctl policy load <account> <file>` - Load policy from file
- [x] `conjurctl policy watch <account> <file>` - Watch file and reload policy
- [x] `conjurctl data-key generate` - Generate encryption key
- [x] `conjurctl role retrieve-key <role_id>` - Get role's API key
- [x] `conjurctl role reset-password <role_id>` - Reset password and rotate API key
- [x] `conjurctl wait` - Wait for server to be ready
- [x] `conjurctl export` - Export data for migration
- [x] `conjurctl configuration show` - Show configuration
- [x] `conjurctl configuration apply` - Apply configuration

---

## Phase 2: Policy Engine ✅ COMPLETE

### 2.1 Policy Loading ✅
**Status: Complete**

Policy engine integrated from `conjur-policy-go` into `pkg/policy/`.

- [x] Policy YAML parser (User, Group, Host, Variable, Layer, Policy, Grant, Permit, Deny, Delete)
- [x] Policy loader (creates roles, resources, permissions, memberships)
- [x] Statement ordering (creates before relationships)
- [x] `POST /policies/{account}/policy/{identifier}` - Create/append policy
- [x] `PUT /policies/{account}/policy/{identifier}` - Replace policy
- [x] `PATCH /policies/{account}/policy/{identifier}` - Update policy
- [x] `GET /policies/{account}/policy/{identifier}` - Get policy versions
- [x] `GET /policies/...?version=N` - Get specific policy text
- [x] `POST /policies/...?dry_run=true` - Validate policy without applying

### 2.2 Policy Versioning ✅
**Status: Complete**

- [x] `policy_versions` table (migration exists)
- [x] Track policy changes with SHA256 hash
- [x] Policy audit log (RFC5424 syslog format)

---

## Phase 3: RBAC & Resources

### 3.1 Roles API ✅
**Status: Complete**

- [x] `GET /roles/{account}/{kind}/{identifier}` - Show role
- [x] `GET /roles/...?members` - List role members
- [x] `GET /roles/...?memberships` - List role memberships
- [x] `GET /roles/...?all` - List all memberships (recursive)
- [x] `POST /roles/...?members&member=...` - Add member to role
- [x] `DELETE /roles/...?members&member=...` - Remove member from role
- [ ] `GET /roles/...?graph` - Role graph visualization

### 3.2 Resources API ✅
**Status: Complete**

- [x] `GET /resources/{account}` - List all resources
- [x] `GET /resources/{account}/{kind}` - List resources by kind
- [x] `GET /resources/{account}/{kind}/{identifier}` - Show resource
- [x] Resource visibility via `visible_resources()` function
- [x] Filtering by kind, search, limit, offset
- [x] `GET /resources/...?check` - Check permission
- [x] `GET /resources/...?permitted_roles` - List roles with permission
- [x] Resource annotations CRUD (`/resources/.../annotations`)

### 3.3 Resource Kinds ✅
**Status: Complete**

Support for standard resource kinds in policy parser:
- [x] `variable` - Secrets
- [x] `user` - Human identities
- [x] `host` - Machine identities
- [x] `group` - Collections of roles
- [x] `layer` - Collections of hosts
- [x] `policy` - Policy namespaces
- [x] `webservice` - Protected services
- [x] `host_factory` - Automated host enrollment

---

### 3.4 Policy Features ✅
**Status: Complete**

- [x] Policy versioning with SHA256 hash
- [x] POST (create/append) - delete NOT permitted
- [x] PUT (replace) - delete permitted
- [x] PATCH (modify) - delete permitted
- [x] Policy dry-run/validation (`?dry_run=true`)

---

## Phase 4: Authentication ✅ COMPLETE

### 4.1 Core Authentication ✅
**Status: Complete**

- [x] `POST /authn/{account}/{login}/authenticate` - API key auth with JWT token
- [x] JWT token generation and verification (Slosilo)
- [x] `GET /whoami` - Current identity
- [x] `GET /authn/{account}/login` - Login (get API key)
- [x] `PUT /authn/{account}/password` - Update password
- [x] `PUT /authn/{account}/api_key` - Rotate API key

### 4.2 Authenticator Framework ✅
**Status: Complete**

Pluggable authenticator architecture with registry pattern:
- [x] `GET /authenticators` - List available authenticators
- [x] `GET /{authenticator}/{account}/status` - Authenticator health check (basic)
- [x] `GET /{authenticator}/{service_id}/{account}/status` - Service-specific health check (basic)
- [x] Authenticator interface (`Name()`, `Authenticate()`)
- [x] Default registry for authenticator lookup
- [x] `authn` - API key authenticator
- [x] `authn-jwt` - JWT authenticator with inline JWKS support

**Status endpoint gap vs Ruby:** Go does basic health checks (DB connectivity, authenticator enabled, variable exists). Ruby does comprehensive validation including: signing key fetch, issuer/audience validation, enforced claims, claim aliases, identity secrets, and user access checks.

### 4.3 JWT Authenticator (authn-jwt) ✅
**Status: Complete (basic features)**

- [x] `POST /authn-jwt/{service}/{account}/authenticate` - JWT authentication
- [x] Inline public keys via `public-keys` variable (JWKS format)
- [x] Issuer validation via `issuer` variable
- [x] Identity extraction via `token-app-property` variable
- [x] Policy-based configuration (webservice + variables)
- [x] JWKS caching with expiration
- [ ] JWKS URI fetching (provider-uri, jwks-uri)
- [ ] Enforced claims validation
- [ ] Claim restrictions on hosts

### 4.4 Future Authenticators
**Priority: Low**

- [ ] `authn-ldap` - LDAP authentication
- [ ] `authn-oidc` - OpenID Connect
- [ ] `authn-k8s` - Kubernetes authentication
- [ ] `authn-iam` - AWS IAM authentication
- [ ] `authn-azure` - Azure AD authentication
- [ ] `authn-gcp` - Google Cloud authentication

---

## Phase 5: Secrets Management ✅ COMPLETE

### 5.1 Secrets API Enhancements ✅
**Status: Complete**

- [x] `GET /secrets/{account}/{kind}/{identifier}` - Fetch secret
- [x] `POST /secrets/{account}/{kind}/{identifier}` - Store secret
- [x] Secret versioning (fetch specific version with `?version=`)
- [x] RBAC checks (`execute` for read, `update` for write)
- [x] `GET /secrets?variable_ids=...` - Batch fetch secrets
- [x] `POST /secrets/{account}/values` - Batch update secrets
- [x] Secret expiration (`expires_at` column, 404 on expired secrets)
- [x] `POST /secrets/...?expirations` - Clear secret expiration

### 5.2 Public Keys ✅
**Status: Complete**

- [x] `GET /public_keys/{account}/{kind}/{identifier}` - Fetch public keys
- [x] Public keys stored as variables with pattern `public_key/{kind}/{id}/{key_name}`
- [x] Automatic decryption and sorting

---

## Phase 6: Host Factories ✅

**Status: Complete**

Host factories allow automated host enrollment.

- [x] `host_factory_tokens` table
- [x] `POST /host_factory_tokens` - Create token(s)
- [x] `DELETE /host_factory_tokens/{id}` - Revoke token
- [x] `POST /host_factories/hosts` - Create host with token

---

## Phase 7: Operational Features

### 7.1 Status & Health ✅
**Status: Complete**

- [x] `GET /` - Status endpoint (HTML and JSON)
- [x] `GET /whoami` - Current identity
- [x] `GET /authenticators` - List installed/configured/enabled authenticators
- [ ] Health checks for database, authenticators

### 7.2 Audit Logging ✅
**Status: Complete**

- [x] Audit log for authentication events (RFC5424 syslog format)
- [x] Audit log for secret access (fetch/update)
- [x] Audit log for policy changes
- [x] Audit log for permission checks
- [ ] `GET /audit` endpoints

### 7.3 Certificate Authority
**Priority: Low**

- [ ] `POST /ca/{account}/{service_id}/sign` - Sign certificates

---

## Phase 8: Advanced Features

### 8.1 Branches (Workspaces)
**Priority: Low**

- [ ] `POST /branches/{account}` - Create branch
- [ ] `GET /branches/{account}` - List branches
- [ ] `PATCH /branches/{account}/{identifier}` - Update branch
- [ ] `DELETE /branches/{account}/{identifier}` - Delete branch

### 8.2 Secret Rotation
**Priority: Low**

- [ ] Built-in rotators
- [ ] Custom rotator support

### 8.3 Dynamic Secrets (Issuers)
**Priority: Low**

- [ ] Issuer management for dynamic secret generation

---

## Non-Functional Requirements

### Performance
- [ ] Connection pooling
- [ ] Caching for RBAC lookups
- [ ] Efficient batch operations

### Security
- [ ] TLS support (recommend handling via reverse proxy)
- [x] CIDR restrictions on credentials (`restricted_to` on hosts/users)
- [ ] Trusted proxies configuration (for X-Forwarded-For handling)
- [ ] Rate limiting
- [ ] Request validation

### Observability
- [ ] Structured logging
- [ ] Prometheus metrics
- [ ] Distributed tracing

### Deployment
- [ ] Docker image
- [ ] Helm chart
- [ ] High availability support

---

## Contributing

When working on a feature:
1. Check the Ruby implementation in `conjur/` for reference
2. Write tests first
3. Follow Go idioms and project conventions
4. Update this roadmap as features are completed

## References

- [Conjur Documentation](https://docs.conjur.org/)
- [Conjur API Reference](https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API.htm)
- [Slosilo Cryptography](https://github.com/conjurinc/slosilo)
