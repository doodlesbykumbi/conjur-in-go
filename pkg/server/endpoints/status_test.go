package endpoints

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestStatusEndpoints(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}

	dataKey := make([]byte, 32)
	for i := range dataKey {
		dataKey[i] = byte(i)
	}

	testServer, err := NewTestServer(dbURL, dataKey)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}

	// Register endpoints
	RegisterStatusEndpoints(testServer)

	t.Run("GET / returns status", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var result StatusResponse
		body, _ := io.ReadAll(resp.Body)
		err := json.Unmarshal(body, &result)
		if err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if result.Status != "ok" {
			t.Errorf("expected status 'ok', got %q", result.Status)
		}
	})

	t.Run("GET /authenticators returns list", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/authenticators", nil)
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var result AuthenticatorsResponse
		body, _ := io.ReadAll(resp.Body)
		err := json.Unmarshal(body, &result)
		if err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if len(result.Installed) == 0 {
			t.Error("expected at least one installed authenticator")
		}

		// Check that authn is in the list
		found := false
		for _, a := range result.Installed {
			if a == "authn" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected 'authn' in installed authenticators")
		}
	})

	t.Run("status endpoints do not require auth", func(t *testing.T) {
		// These endpoints should work without Authorization header
		endpoints := []string{"/", "/authenticators"}

		for _, endpoint := range endpoints {
			req := httptest.NewRequest("GET", endpoint, nil)
			w := httptest.NewRecorder()

			testServer.Router.ServeHTTP(w, req)

			resp := w.Result()
			if resp.StatusCode == http.StatusUnauthorized {
				t.Errorf("endpoint %s should not require auth, got 401", endpoint)
			}
		}
	})
}
