package endpoints

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/identity"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
)

func TestHandleFetchSecret(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		secretsStore := NewMockSecretsStore()
		authzStore := NewMockAuthzStore()

		resourceID := "myorg:variable:db/password"
		roleID := "myorg:user:admin"
		secretValue := []byte("super-secret")

		authzStore.On("IsRoleAllowedTo", roleID, "execute", resourceID).Return(true)
		secretsStore.On("FetchSecret", resourceID, "").Return(&store.Secret{
			ResourceID: resourceID,
			Value:      secretValue,
			Version:    1,
		}, nil)

		handler := handleFetchSecret(secretsStore, authzStore)

		req := requestWithIdentity("GET", "/secrets/myorg/variable/db%2Fpassword", "", "myorg", roleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"kind":       "variable",
			"identifier": "db/password",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, string(secretValue), w.Body.String())
		secretsStore.AssertExpectations(t)
		authzStore.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		secretsStore := NewMockSecretsStore()
		authzStore := NewMockAuthzStore()

		resourceID := "myorg:variable:nonexistent"
		roleID := "myorg:user:admin"

		authzStore.On("IsRoleAllowedTo", roleID, "execute", resourceID).Return(true)
		secretsStore.On("FetchSecret", resourceID, "").Return(nil, store.ErrSecretNotFound)

		handler := handleFetchSecret(secretsStore, authzStore)

		req := requestWithIdentity("GET", "/secrets/myorg/variable/nonexistent", "", "myorg", roleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"kind":       "variable",
			"identifier": "nonexistent",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("forbidden without permission", func(t *testing.T) {
		secretsStore := NewMockSecretsStore()
		authzStore := NewMockAuthzStore()

		resourceID := "myorg:variable:protected"
		roleID := "myorg:user:unprivileged"

		authzStore.On("IsRoleAllowedTo", roleID, "execute", resourceID).Return(false)

		handler := handleFetchSecret(secretsStore, authzStore)

		req := requestWithIdentity("GET", "/secrets/myorg/variable/protected", "", "myorg", roleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"kind":       "variable",
			"identifier": "protected",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("expired secret returns 404", func(t *testing.T) {
		secretsStore := NewMockSecretsStore()
		authzStore := NewMockAuthzStore()

		resourceID := "myorg:variable:expired"
		roleID := "myorg:user:admin"

		authzStore.On("IsRoleAllowedTo", roleID, "execute", resourceID).Return(true)
		secretsStore.On("FetchSecret", resourceID, "").Return(nil, store.ErrSecretExpired)

		handler := handleFetchSecret(secretsStore, authzStore)

		req := requestWithIdentity("GET", "/secrets/myorg/variable/expired", "", "myorg", roleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"kind":       "variable",
			"identifier": "expired",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestHandleCreateSecret(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		secretsStore := NewMockSecretsStore()
		authzStore := NewMockAuthzStore()

		resourceID := "myorg:variable:new/secret"
		roleID := "myorg:user:admin"

		authzStore.On("IsRoleAllowedTo", roleID, "update", resourceID).Return(true)
		secretsStore.On("CreateSecret", resourceID, []byte("my-secret-value")).Return(nil)

		handler := handleCreateSecret(secretsStore, authzStore)

		req := requestWithIdentity("POST", "/secrets/myorg/variable/new%2Fsecret", "my-secret-value", "myorg", roleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"kind":       "variable",
			"identifier": "new/secret",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		secretsStore.AssertCalled(t, "CreateSecret", resourceID, []byte("my-secret-value"))
	})

	t.Run("forbidden without permission", func(t *testing.T) {
		secretsStore := NewMockSecretsStore()
		authzStore := NewMockAuthzStore()

		resourceID := "myorg:variable:protected"
		roleID := "myorg:user:readonly"

		authzStore.On("IsRoleAllowedTo", roleID, "update", resourceID).Return(false)

		handler := handleCreateSecret(secretsStore, authzStore)

		req := requestWithIdentity("POST", "/secrets/myorg/variable/protected", "value", "myorg", roleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"kind":       "variable",
			"identifier": "protected",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		secretsStore.AssertNotCalled(t, "CreateSecret", mock.Anything, mock.Anything)
	})
}

func TestHandleExpireSecret(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		secretsStore := NewMockSecretsStore()
		authzStore := NewMockAuthzStore()

		resourceID := "myorg:variable:expiring"
		roleID := "myorg:user:admin"

		authzStore.On("IsRoleAllowedTo", roleID, "update", resourceID).Return(true)
		secretsStore.On("ExpireSecret", resourceID).Return(nil)

		handler := handleExpireSecret(secretsStore, authzStore)

		req := requestWithIdentity("POST", "/secrets/myorg/variable/expiring?expirations", "", "myorg", roleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"kind":       "variable",
			"identifier": "expiring",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		secretsStore.AssertCalled(t, "ExpireSecret", resourceID)
	})

	t.Run("non-variable kind returns 422", func(t *testing.T) {
		secretsStore := NewMockSecretsStore()
		authzStore := NewMockAuthzStore()

		resourceID := "myorg:group:test"
		roleID := "myorg:user:admin"

		authzStore.On("IsRoleAllowedTo", roleID, "update", resourceID).Return(true)

		handler := handleExpireSecret(secretsStore, authzStore)

		req := requestWithIdentity("POST", "/secrets/myorg/group/test?expirations", "", "myorg", roleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"kind":       "group",
			"identifier": "test",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	})
}

func TestHandleBatchFetchSecrets(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		secretsStore := NewMockSecretsStore()
		authzStore := NewMockAuthzStore()

		roleID := "myorg:user:admin"

		authzStore.On("IsRoleAllowedTo", roleID, "execute", "myorg:variable:var1").Return(true)
		authzStore.On("IsRoleAllowedTo", roleID, "execute", "myorg:variable:var2").Return(true)
		secretsStore.On("FetchSecret", "myorg:variable:var1", "").Return(&store.Secret{Value: []byte("value1")}, nil)
		secretsStore.On("FetchSecret", "myorg:variable:var2", "").Return(&store.Secret{Value: []byte("value2")}, nil)

		handler := handleBatchFetchSecrets(secretsStore, authzStore)

		req := requestWithIdentity("GET", "/secrets?variable_ids=myorg:variable:var1,myorg:variable:var2", "", "myorg", roleID)

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("partial forbidden fails entire request", func(t *testing.T) {
		secretsStore := NewMockSecretsStore()
		authzStore := NewMockAuthzStore()

		roleID := "myorg:user:limited"

		// Handler checks permission then fetches in order, so first var gets fetched before second permission check
		authzStore.On("IsRoleAllowedTo", roleID, "execute", "myorg:variable:allowed").Return(true)
		secretsStore.On("FetchSecret", "myorg:variable:allowed", "").Return(&store.Secret{Value: []byte("value1")}, nil)
		authzStore.On("IsRoleAllowedTo", roleID, "execute", "myorg:variable:forbidden").Return(false)

		handler := handleBatchFetchSecrets(secretsStore, authzStore)

		req := requestWithIdentity("GET", "/secrets?variable_ids=myorg:variable:allowed,myorg:variable:forbidden", "", "myorg", roleID)

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("missing variable_ids returns 400", func(t *testing.T) {
		secretsStore := NewMockSecretsStore()
		authzStore := NewMockAuthzStore()

		roleID := "myorg:user:admin"

		handler := handleBatchFetchSecrets(secretsStore, authzStore)

		req := requestWithIdentity("GET", "/secrets", "", "myorg", roleID)

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandleBatchUpdateSecrets(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		secretsStore := NewMockSecretsStore()
		authzStore := NewMockAuthzStore()

		roleID := "myorg:user:admin"

		authzStore.On("IsRoleAllowedTo", roleID, "update", "myorg:variable:var1").Return(true)
		authzStore.On("IsRoleAllowedTo", roleID, "update", "myorg:variable:var2").Return(true)
		secretsStore.On("CreateSecret", "myorg:variable:var1", []byte("value1")).Return(nil)
		secretsStore.On("CreateSecret", "myorg:variable:var2", []byte("value2")).Return(nil)

		handler := handleBatchUpdateSecrets(secretsStore, authzStore)

		// Body must have "secrets" key per BatchSecretRequest struct
		body := `{"secrets":{"myorg:variable:var1":"value1","myorg:variable:var2":"value2"}}`
		req := requestWithIdentity("POST", "/secrets/myorg/values", body, "myorg", roleID)
		req.Header.Set("Content-Type", "application/json")
		req = withMuxVars(req, map[string]string{"account": "myorg"})

		w := httptest.NewRecorder()
		handler(w, req)

		require.Equal(t, http.StatusCreated, w.Code)
	})
}

// Helper to create a request with identity context
func requestWithIdentity(method, url string, body string, account, roleID string) *http.Request {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, url, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, url, nil)
	}
	ctx := identity.Set(req.Context(), &identity.Identity{
		Account: account,
		RoleID:  roleID,
	})
	return req.WithContext(ctx)
}

// Helper to set mux vars on request
func withMuxVars(req *http.Request, vars map[string]string) *http.Request {
	return mux.SetURLVars(req, vars)
}
