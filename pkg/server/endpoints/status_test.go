package endpoints

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandleStatus(t *testing.T) {
	t.Run("returns HTML status page", func(t *testing.T) {
		handler := handleStatus()

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
		assert.Contains(t, w.Body.String(), "Your Conjur server is running!")
	})

	t.Run("returns JSON when Accept header is application/json", func(t *testing.T) {
		handler := handleStatus()

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	})
}
