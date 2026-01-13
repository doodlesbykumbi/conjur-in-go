package endpoints

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"conjur-in-go/pkg/slosilo"
)

func TestWhoamiEndpoint(t *testing.T) {
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
	account := "testwhoami"
	apiKey := "test-api-key-whoami"

	// Cleanup before and after
	_ = CleanupTestData(testServer.DB, account)
	defer func() { _ = CleanupTestData(testServer.DB, account) }()

	err = SetupTestAccount(testServer.DB, cipher, account, apiKey)
	if err != nil {
		t.Fatalf("failed to setup test account: %v", err)
	}

	// Register endpoints
	RegisterWhoamiEndpoint(testServer)

	t.Run("whoami with valid token", func(t *testing.T) {
		// Generate auth token for admin
		authToken, err := GenerateTestToken(testServer.DB, cipher, account, "admin")
		if err != nil {
			t.Fatalf("failed to generate auth token: %v", err)
		}
		authHeader := `Token token="` + authToken + `"`

		req := httptest.NewRequest("GET", "/whoami", nil)
		req.Header.Set("Authorization", authHeader)
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var result WhoamiResponse
		body, _ := io.ReadAll(resp.Body)
		err = json.Unmarshal(body, &result)
		if err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if result.Account != account {
			t.Errorf("expected account %q, got %q", account, result.Account)
		}
		if result.Username != "admin" {
			t.Errorf("expected username 'admin', got %q", result.Username)
		}
	})

	t.Run("whoami with host token", func(t *testing.T) {
		// Create a host with credentials
		hostRoleId := account + ":host:myapp"
		hostAPIKey := "host-api-key-whoami"

		testServer.DB.Exec(`INSERT INTO roles (role_id) VALUES (?) ON CONFLICT DO NOTHING`, hostRoleId)
		encryptedKey, _ := cipher.Encrypt([]byte(hostRoleId), []byte(hostAPIKey))
		testServer.DB.Exec(`
			INSERT INTO credentials (role_id, api_key) VALUES (?, ?)
			ON CONFLICT (role_id) DO UPDATE SET api_key = EXCLUDED.api_key
		`, hostRoleId, encryptedKey)

		// Generate auth token for host
		authToken, err := GenerateTestToken(testServer.DB, cipher, account, "host/myapp")
		if err != nil {
			t.Fatalf("failed to generate auth token: %v", err)
		}
		authHeader := `Token token="` + authToken + `"`

		req := httptest.NewRequest("GET", "/whoami", nil)
		req.Header.Set("Authorization", authHeader)
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var result WhoamiResponse
		body, _ := io.ReadAll(resp.Body)
		err = json.Unmarshal(body, &result)
		if err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if result.Account != account {
			t.Errorf("expected account %q, got %q", account, result.Account)
		}
		if result.Username != "host/myapp" {
			t.Errorf("expected username 'host/myapp', got %q", result.Username)
		}
	})

	t.Run("whoami without token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/whoami", nil)
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", resp.StatusCode)
		}
	})

	t.Run("whoami with invalid token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/whoami", nil)
		req.Header.Set("Authorization", `Token token="invalid-token"`)
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", resp.StatusCode)
		}
	})
}
