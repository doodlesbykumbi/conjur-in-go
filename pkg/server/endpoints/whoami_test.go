package endpoints

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/identity"
)

func TestHandleWhoami(t *testing.T) {
	t.Run("returns identity for user", func(t *testing.T) {
		handler := handleWhoami()

		req := httptest.NewRequest("GET", "/whoami", nil)
		ctx := identity.Set(req.Context(), &identity.Identity{
			Account: "myorg",
			RoleID:  "myorg:user:admin",
			Login:   "admin",
		})
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var result WhoamiResponse
		err := json.Unmarshal(w.Body.Bytes(), &result)
		require.NoError(t, err)

		assert.Equal(t, "myorg", result.Account)
		assert.Equal(t, "admin", result.Username)
	})

	t.Run("returns identity for host", func(t *testing.T) {
		handler := handleWhoami()

		req := httptest.NewRequest("GET", "/whoami", nil)
		ctx := identity.Set(req.Context(), &identity.Identity{
			Account: "myorg",
			RoleID:  "myorg:host:myapp",
			Login:   "host/myapp",
		})
		req = req.WithContext(ctx)

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var result WhoamiResponse
		err := json.Unmarshal(w.Body.Bytes(), &result)
		require.NoError(t, err)

		assert.Equal(t, "myorg", result.Account)
		assert.Equal(t, "host/myapp", result.Username)
	})

	t.Run("returns 401 without identity", func(t *testing.T) {
		handler := handleWhoami()

		req := httptest.NewRequest("GET", "/whoami", nil)
		// No identity set in context

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
