# Testing Strategy

This document describes the testing approach used in this project.

## Test Types

### Unit Tests

Unit tests are located alongside the code they test in `*_test.go` files. They use **mock store interfaces** with `testify/mock` to isolate the code under test from external dependencies like databases.

**Key files:**
- `pkg/server/endpoints/mock_stores_test.go` - Mock implementations of store interfaces
- `pkg/server/endpoints/*_test.go` - Handler unit tests

**Example pattern:**
```go
func TestHandleFetchSecret(t *testing.T) {
    secretsStore := NewMockSecretsStore()
    authzStore := NewMockAuthzStore()

    // Set up expectations
    authzStore.On("IsRoleAllowedTo", roleID, "execute", resourceID).Return(true)
    secretsStore.On("FetchSecret", resourceID, "").Return(&store.Secret{...}, nil)

    handler := handleFetchSecret(secretsStore, authzStore)
    // ... make request and assert response

    // Verify expectations were met
    secretsStore.AssertExpectations(t)
}
```

### Integration Tests (Cucumber/Gherkin)

Integration tests use Cucumber/Gherkin feature files and run against a real PostgreSQL database. They test the full request/response cycle including authentication, authorization, and database operations.

**Testcontainers:** Integration tests use [testcontainers-go](https://golang.testcontainers.org/) to automatically manage a PostgreSQL container. This means:
- No manual database setup required
- Each test run gets a fresh, isolated database
- Tests are reproducible across different environments
- **Requires Docker** to be running on the host machine

**Location:** `test/integration/`

**Key files:**
- `test/integration/features/*.feature` - Gherkin feature files
- `test/integration/steps_*.go` - Step definitions
- `test/integration/server_instance.go` - Test server setup

**Running integration tests:**
```bash
# Uses testcontainers to automatically spin up PostgreSQL
# Requires Docker to be running

# Binary mode (default) - requires built binary
go build -o conjurctl ./cmd/conjurctl
CONJUR_BINARY=./conjurctl go test ./test/integration/...

# Inline mode - runs server in-process (no binary needed)
CONJUR_INLINE=1 go test ./test/integration/...
```

**Feature coverage:**
- `authentication.feature` - API key authentication flows
- `authorization.feature` - RBAC permission checks
- `secrets.feature` - Secret CRUD operations
- `policy.feature` - Policy loading (POST/PUT/PATCH)
- `whoami.feature` - Identity endpoint
- `authn_jwt.feature` - JWT authentication

## Mock Store Interfaces

We mock at the **store interface level** rather than the database level. This approach:

1. **Faster** - No database setup/teardown
2. **Isolated** - Tests only the handler logic
3. **Readable** - Clear expectations with `On()`/`Return()`
4. **Flexible** - Easy to simulate error conditions

**Available mocks:**
- `MockSecretsStore` - `store.SecretsStore`
- `MockAuthzStore` - `store.AuthzStore`
- `MockResourcesStore` - `store.ResourcesStore`
- `MockPolicyStore` - `store.PolicyStore`
- `MockAuthenticateStore` - `store.AuthenticateStore`

## Running Tests

```bash
# Run all unit tests
go test ./...

# Run with verbose output
go test -v ./...

# Run specific package
go test -v ./pkg/server/endpoints/...
```

## Test Helpers

Helper functions in test files:

- `requestWithIdentity(method, url, body, account, roleID)` - Creates HTTP request with identity context
- `withMuxVars(req, vars)` - Sets gorilla/mux URL variables on request

## Adding New Tests

### For new handlers:

1. Add unit tests in the corresponding `*_test.go` file
2. Use `testify/mock` to mock store dependencies
3. Use `testify/assert` for assertions
4. Add integration test scenarios to appropriate `.feature` file if needed

### For new store methods:

1. Add the method to the mock in `mock_stores_test.go`
2. Update any affected handler tests
