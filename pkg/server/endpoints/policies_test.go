package endpoints

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
)

func TestPoliciesEndpoint(t *testing.T) {
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
	account := "testpolicy"

	// Cleanup before and after
	_ = CleanupTestData(testServer.DB, account)
	defer func() { _ = CleanupTestData(testServer.DB, account) }()

	err = SetupTestAccount(testServer.DB, cipher, account, "admin-api-key")
	if err != nil {
		t.Fatalf("failed to setup test account: %v", err)
	}

	// Register endpoints
	RegisterPoliciesEndpoints(testServer)

	t.Run("load simple policy", func(t *testing.T) {
		policy := `- !user
  id: alice
  annotations:
    description: Test user
`
		req := httptest.NewRequest("POST", "/policies/"+account+"/policy/root", strings.NewReader(policy))
		req.Header.Set("Content-Type", "application/x-yaml")
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 201, got %d: %s", resp.StatusCode, string(body))
		}

		// Verify response contains created roles
		var result map[string]interface{}
		body, _ := io.ReadAll(resp.Body)
		err := json.Unmarshal(body, &result)
		if err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		createdRoles, ok := result["created_roles"].(map[string]interface{})
		if !ok {
			t.Fatal("expected created_roles in response")
		}

		expectedRoleId := account + ":user:alice"
		if _, exists := createdRoles[expectedRoleId]; !exists {
			t.Errorf("expected role %q in created_roles", expectedRoleId)
		}

		// Verify user was created in database
		var count int64
		testServer.DB.Raw(`SELECT COUNT(*) FROM roles WHERE role_id = ?`, expectedRoleId).Scan(&count)
		if count != 1 {
			t.Errorf("expected 1 role in database, got %d", count)
		}
	})

	t.Run("load policy with multiple resources", func(t *testing.T) {
		policy := `- !group
  id: developers

- !variable
  id: api/key
  annotations:
    description: API key

- !host
  id: webapp
`
		req := httptest.NewRequest("POST", "/policies/"+account+"/policy/root", strings.NewReader(policy))
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 201, got %d: %s", resp.StatusCode, string(body))
		}

		// Verify resources were created
		var count int64
		testServer.DB.Raw(`SELECT COUNT(*) FROM resources WHERE resource_id LIKE ?`, account+":%").Scan(&count)
		// Should have: admin, root policy, alice (from previous test), developers, api/key, webapp = 6+
		if count < 4 {
			t.Errorf("expected at least 4 resources, got %d", count)
		}
	})

	t.Run("load policy with grant and permit", func(t *testing.T) {
		policy := `- !user
  id: bob

- !grant
  role: !group developers
  member: !user bob

- !permit
  role: !group developers
  privileges: [read, execute]
  resource: !variable api/key
`
		req := httptest.NewRequest("POST", "/policies/"+account+"/policy/root", strings.NewReader(policy))
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 201, got %d: %s", resp.StatusCode, string(body))
		}

		// Verify grant was created
		var grantCount int64
		testServer.DB.Raw(`
			SELECT COUNT(*) FROM role_memberships 
			WHERE role_id = ? AND member_id = ?
		`, account+":group:developers", account+":user:bob").Scan(&grantCount)
		if grantCount != 1 {
			t.Errorf("expected 1 grant, got %d", grantCount)
		}

		// Verify permissions were created
		var permCount int64
		testServer.DB.Raw(`
			SELECT COUNT(*) FROM permissions 
			WHERE resource_id = ? AND role_id = ?
		`, account+":variable:api/key", account+":group:developers").Scan(&permCount)
		if permCount != 2 {
			t.Errorf("expected 2 permissions (read, execute), got %d", permCount)
		}
	})

	t.Run("empty policy body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/policies/"+account+"/policy/root", strings.NewReader(""))
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected status 400 for empty body, got %d", resp.StatusCode)
		}
	})

	t.Run("invalid YAML", func(t *testing.T) {
		policy := `this is not valid yaml: [[[`
		req := httptest.NewRequest("POST", "/policies/"+account+"/policy/root", strings.NewReader(policy))
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("expected status 422 for invalid YAML, got %d", resp.StatusCode)
		}
	})

	t.Run("PUT method (replace)", func(t *testing.T) {
		policy := `- !user
  id: charlie
`
		req := httptest.NewRequest("PUT", "/policies/"+account+"/policy/root", strings.NewReader(policy))
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 201, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("PATCH method (update)", func(t *testing.T) {
		policy := `- !user
  id: dave
`
		req := httptest.NewRequest("PATCH", "/policies/"+account+"/policy/root", strings.NewReader(policy))
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 201, got %d: %s", resp.StatusCode, string(body))
		}
	})
}
