package endpoints

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"conjur-in-go/pkg/slosilo"
)

func TestRoleIdFromLogin(t *testing.T) {
	tests := []struct {
		name     string
		account  string
		login    string
		expected string
	}{
		{
			name:     "simple user login",
			account:  "myorg",
			login:    "alice",
			expected: "myorg:user:alice",
		},
		{
			name:     "explicit user login",
			account:  "myorg",
			login:    "user/alice",
			expected: "myorg:user:alice",
		},
		{
			name:     "host login",
			account:  "myorg",
			login:    "host/myapp",
			expected: "myorg:host:myapp",
		},
		{
			name:     "nested host login",
			account:  "myorg",
			login:    "host/app/prod/server1",
			expected: "myorg:host:app/prod/server1",
		},
		{
			name:     "different account",
			account:  "other",
			login:    "admin",
			expected: "other:user:admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := roleIdFromLogin(tt.account, tt.login)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// Integration test - requires database
func TestAuthenticateEndpoint(t *testing.T) {
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

	cipher, _ := slosilo.NewSymmetric(dataKey)

	// Setup test account
	account := "testauth"
	apiKey := "test-api-key-12345"

	// Cleanup before and after
	CleanupTestData(testServer.DB, account)
	defer CleanupTestData(testServer.DB, account)

	err = SetupTestAccount(testServer.DB, cipher, account, apiKey)
	if err != nil {
		t.Fatalf("failed to setup test account: %v", err)
	}

	// Register the endpoint
	RegisterAuthenticateEndpoint(testServer)

	t.Run("successful authentication", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/authn/"+account+"/admin/authenticate", strings.NewReader(apiKey))
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		// Verify response is valid JSON with expected fields
		var token map[string]string
		body, _ := io.ReadAll(resp.Body)
		err := json.Unmarshal(body, &token)
		if err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if token["protected"] == "" {
			t.Error("expected 'protected' field in token")
		}
		if token["payload"] == "" {
			t.Error("expected 'payload' field in token")
		}
		if token["signature"] == "" {
			t.Error("expected 'signature' field in token")
		}
	})

	t.Run("wrong API key", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/authn/"+account+"/admin/authenticate", strings.NewReader("wrong-api-key"))
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", resp.StatusCode)
		}
	})

	t.Run("non-existent user", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/authn/"+account+"/nonexistent/authenticate", strings.NewReader(apiKey))
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", resp.StatusCode)
		}
	})

	t.Run("base64 encoding requested", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/authn/"+account+"/admin/authenticate", strings.NewReader(apiKey))
		req.Header.Set("Accept-Encoding", "base64")
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		if resp.Header.Get("Content-Encoding") != "base64" {
			t.Error("expected Content-Encoding: base64 header")
		}
	})

	t.Run("host authentication", func(t *testing.T) {
		// Create a host with credentials
		hostRoleId := account + ":host:myapp"
		hostAPIKey := "host-api-key-xyz"

		testServer.DB.Exec(`INSERT INTO roles (role_id) VALUES (?) ON CONFLICT DO NOTHING`, hostRoleId)
		encryptedKey, _ := cipher.Encrypt([]byte(hostRoleId), []byte(hostAPIKey))
		testServer.DB.Exec(`
			INSERT INTO credentials (role_id, api_key) VALUES (?, ?)
			ON CONFLICT (role_id) DO UPDATE SET api_key = EXCLUDED.api_key
		`, hostRoleId, encryptedKey)

		req := httptest.NewRequest("POST", "/authn/"+account+"/host%2Fmyapp/authenticate", strings.NewReader(hostAPIKey))
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}
	})
}
