package endpoints

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
)

// TestAuthorization verifies that RBAC is working correctly via mock stores
func TestAuthorization(t *testing.T) {
	t.Run("user with permission can read secret", func(t *testing.T) {
		secretsStore := NewMockSecretsStore()
		authzStore := NewMockAuthzStore()

		resourceID := "myorg:variable:protected/secret"
		aliceRoleID := "myorg:user:alice"

		authzStore.On("IsRoleAllowedTo", aliceRoleID, "execute", resourceID).Return(true)
		secretsStore.On("FetchSecret", resourceID, "").Return(&store.Secret{
			ResourceID: resourceID,
			Value:      []byte("alice-secret"),
			Version:    1,
		}, nil)

		handler := handleFetchSecret(secretsStore, authzStore)

		req := requestWithIdentity("GET", "/secrets/myorg/variable/protected%2Fsecret", "", "myorg", aliceRoleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"kind":       "variable",
			"identifier": "protected/secret",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "alice-secret", w.Body.String())
	})

	t.Run("user without permission cannot read secret", func(t *testing.T) {
		secretsStore := NewMockSecretsStore()
		authzStore := NewMockAuthzStore()

		resourceID := "myorg:variable:protected/secret"
		bobRoleID := "myorg:user:bob"

		authzStore.On("IsRoleAllowedTo", bobRoleID, "execute", resourceID).Return(false)

		handler := handleFetchSecret(secretsStore, authzStore)

		req := requestWithIdentity("GET", "/secrets/myorg/variable/protected%2Fsecret", "", "myorg", bobRoleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"kind":       "variable",
			"identifier": "protected/secret",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("user with update permission can store secret", func(t *testing.T) {
		secretsStore := NewMockSecretsStore()
		authzStore := NewMockAuthzStore()

		resourceID := "myorg:variable:protected/secret"
		aliceRoleID := "myorg:user:alice"

		authzStore.On("IsRoleAllowedTo", aliceRoleID, "update", resourceID).Return(true)
		secretsStore.On("CreateSecret", resourceID, []byte("new-secret")).Return(nil)

		handler := handleCreateSecret(secretsStore, authzStore)

		req := requestWithIdentity("POST", "/secrets/myorg/variable/protected%2Fsecret", "new-secret", "myorg", aliceRoleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"kind":       "variable",
			"identifier": "protected/secret",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		secretsStore.AssertCalled(t, "CreateSecret", resourceID, []byte("new-secret"))
	})

	t.Run("user without update permission cannot store secret", func(t *testing.T) {
		secretsStore := NewMockSecretsStore()
		authzStore := NewMockAuthzStore()

		resourceID := "myorg:variable:protected/secret"
		bobRoleID := "myorg:user:bob"

		authzStore.On("IsRoleAllowedTo", bobRoleID, "update", resourceID).Return(false)

		handler := handleCreateSecret(secretsStore, authzStore)

		req := requestWithIdentity("POST", "/secrets/myorg/variable/protected%2Fsecret", "bob-secret", "myorg", bobRoleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"kind":       "variable",
			"identifier": "protected/secret",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		secretsStore.AssertNotCalled(t, "CreateSecret", mock.Anything, mock.Anything)
	})
}
