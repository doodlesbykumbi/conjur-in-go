package endpoints

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
)

// TestAuthorization verifies that RBAC is working correctly
// Users should only be able to access resources they have permissions for
func TestAuthorization(t *testing.T) {
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
	account := "testauthz"

	// Cleanup before and after
	_ = CleanupTestData(testServer.DB, account)
	defer func() { _ = CleanupTestData(testServer.DB, account) }()

	err = SetupTestAccount(testServer.DB, cipher, account, "admin-api-key")
	if err != nil {
		t.Fatalf("failed to setup test account: %v", err)
	}

	// Register endpoints
	RegisterSecretsEndpoints(testServer)
	RegisterPoliciesEndpoints(testServer)

	// Create two users: alice (with permissions) and bob (without permissions)
	policy := `- !user
  id: alice

- !user
  id: bob

- !group
  id: secret-readers

- !variable
  id: protected/secret

- !grant
  role: !group secret-readers
  member: !user alice

- !permit
  role: !group secret-readers
  privileges: [read, execute]
  resource: !variable protected/secret

- !permit
  role: !user alice
  privileges: [update]
  resource: !variable protected/secret
`
	// Load policy
	req := httptest.NewRequest("POST", "/policies/"+account+"/policy/root", strings.NewReader(policy))
	w := httptest.NewRecorder()
	testServer.Router.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(w.Result().Body)
		t.Fatalf("failed to load policy: %s", string(body))
	}

	// Store credentials for alice and bob
	aliceRoleId := account + ":user:alice"
	bobRoleId := account + ":user:bob"
	aliceAPIKey := "alice-api-key"
	bobAPIKey := "bob-api-key"

	encAliceKey, _ := cipher.Encrypt([]byte(aliceRoleId), []byte(aliceAPIKey))
	encBobKey, _ := cipher.Encrypt([]byte(bobRoleId), []byte(bobAPIKey))

	testServer.DB.Exec(`UPDATE credentials SET api_key = ? WHERE role_id = ?`, encAliceKey, aliceRoleId)
	testServer.DB.Exec(`UPDATE credentials SET api_key = ? WHERE role_id = ?`, encBobKey, bobRoleId)

	// Generate tokens
	aliceToken, _ := GenerateTestToken(testServer.DB, cipher, account, "alice")
	bobToken, _ := GenerateTestToken(testServer.DB, cipher, account, "bob")
	aliceAuth := `Token token="` + aliceToken + `"`
	bobAuth := `Token token="` + bobToken + `"`

	resourceId := account + ":variable:protected/secret"

	t.Run("alice can store secret (has update permission)", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/secrets/"+account+"/variable/protected%2Fsecret", strings.NewReader("alice-secret"))
		req.Header.Set("Authorization", aliceAuth)
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("expected status 201, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("alice can read secret (has execute permission via group)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/secrets/"+account+"/variable/protected%2Fsecret", nil)
		req.Header.Set("Authorization", aliceAuth)
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		body, _ := io.ReadAll(resp.Body)
		if string(body) != "alice-secret" {
			t.Errorf("expected 'alice-secret', got %q", string(body))
		}
	})

	t.Run("bob cannot read secret (no execute permission)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/secrets/"+account+"/variable/protected%2Fsecret", nil)
		req.Header.Set("Authorization", bobAuth)
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusForbidden {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("expected status 403 (Forbidden), got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("bob cannot store secret (no update permission)", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/secrets/"+account+"/variable/protected%2Fsecret", strings.NewReader("bob-secret"))
		req.Header.Set("Authorization", bobAuth)
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusForbidden {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("expected status 403 (Forbidden), got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("verify secret unchanged after bob's failed attempt", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/secrets/"+account+"/variable/protected%2Fsecret", nil)
		req.Header.Set("Authorization", aliceAuth)
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		body, _ := io.ReadAll(w.Result().Body)
		if string(body) != "alice-secret" {
			t.Errorf("secret should still be 'alice-secret', got %q", string(body))
		}
	})

	t.Run("admin (owner) can access everything", func(t *testing.T) {
		adminToken, _ := GenerateTestToken(testServer.DB, cipher, account, "admin")
		adminAuth := `Token token="` + adminToken + `"`

		// Admin should be able to read (as owner of root policy which owns the variable)
		req := httptest.NewRequest("GET", "/secrets/"+account+"/variable/protected%2Fsecret", nil)
		req.Header.Set("Authorization", adminAuth)
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("admin should have access, got %d: %s", resp.StatusCode, string(body))
		}
	})

	// Test that is_role_allowed_to function works correctly
	t.Run("verify is_role_allowed_to function", func(t *testing.T) {
		var aliceCanExecute, bobCanExecute, aliceCanUpdate, bobCanUpdate bool

		testServer.DB.Raw(`SELECT is_role_allowed_to(?, 'execute', ?)`, aliceRoleId, resourceId).Scan(&aliceCanExecute)
		testServer.DB.Raw(`SELECT is_role_allowed_to(?, 'execute', ?)`, bobRoleId, resourceId).Scan(&bobCanExecute)
		testServer.DB.Raw(`SELECT is_role_allowed_to(?, 'update', ?)`, aliceRoleId, resourceId).Scan(&aliceCanUpdate)
		testServer.DB.Raw(`SELECT is_role_allowed_to(?, 'update', ?)`, bobRoleId, resourceId).Scan(&bobCanUpdate)

		if !aliceCanExecute {
			t.Error("alice should have execute permission")
		}
		if bobCanExecute {
			t.Error("bob should NOT have execute permission")
		}
		if !aliceCanUpdate {
			t.Error("alice should have update permission")
		}
		if bobCanUpdate {
			t.Error("bob should NOT have update permission")
		}
	})
}
