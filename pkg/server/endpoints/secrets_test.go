package endpoints

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"conjur-in-go/pkg/slosilo"
)

func TestSecretsEndpoint(t *testing.T) {
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
	account := "testsecrets"
	apiKey := "test-api-key-secrets"

	// Cleanup before and after
	_ = CleanupTestData(testServer.DB, account)
	defer func() { _ = CleanupTestData(testServer.DB, account) }()

	err = SetupTestAccount(testServer.DB, cipher, account, apiKey)
	if err != nil {
		t.Fatalf("failed to setup test account: %v", err)
	}

	// Create a test variable
	adminRoleId := account + ":user:admin"
	variableId := "db/password"
	resourceId := account + ":variable:" + variableId

	err = CreateTestVariable(testServer.DB, account, variableId, adminRoleId)
	if err != nil {
		t.Fatalf("failed to create test variable: %v", err)
	}

	// Grant execute and update permissions to admin
	err = GrantPermission(testServer.DB, "execute", resourceId, adminRoleId)
	if err != nil {
		t.Fatalf("failed to grant execute permission: %v", err)
	}
	err = GrantPermission(testServer.DB, "update", resourceId, adminRoleId)
	if err != nil {
		t.Fatalf("failed to grant update permission: %v", err)
	}

	// Generate auth token for admin
	authToken, err := GenerateTestToken(testServer.DB, cipher, account, "admin")
	if err != nil {
		t.Fatalf("failed to generate auth token: %v", err)
	}
	authHeader := `Token token="` + authToken + `"`

	// Register endpoints
	RegisterSecretsEndpoints(testServer)

	t.Run("store secret", func(t *testing.T) {
		secretValue := "super-secret-password"
		req := httptest.NewRequest("POST", "/secrets/"+account+"/variable/db%2Fpassword", strings.NewReader(secretValue))
		req.Header.Set("Authorization", authHeader)
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 201 or 200, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("retrieve secret", func(t *testing.T) {
		// First store a secret
		secretValue := "retrieve-test-secret"
		storeReq := httptest.NewRequest("POST", "/secrets/"+account+"/variable/db%2Fpassword", strings.NewReader(secretValue))
		storeReq.Header.Set("Authorization", authHeader)
		storeW := httptest.NewRecorder()
		testServer.Router.ServeHTTP(storeW, storeReq)

		// Now retrieve it
		req := httptest.NewRequest("GET", "/secrets/"+account+"/variable/db%2Fpassword", nil)
		req.Header.Set("Authorization", authHeader)
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		body, _ := io.ReadAll(resp.Body)
		if string(body) != secretValue {
			t.Errorf("expected secret value %q, got %q", secretValue, string(body))
		}
	})

	t.Run("retrieve non-existent secret", func(t *testing.T) {
		// Create variable without storing a secret
		_ = CreateTestVariable(testServer.DB, account, "empty/var", adminRoleId)
		_ = GrantPermission(testServer.DB, "execute", account+":variable:empty/var", adminRoleId)

		req := httptest.NewRequest("GET", "/secrets/"+account+"/variable/empty%2Fvar", nil)
		req.Header.Set("Authorization", authHeader)
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		// Should return 404 or similar for non-existent secret
		if resp.StatusCode == http.StatusOK {
			t.Error("expected non-200 status for non-existent secret")
		}
	})

	t.Run("retrieve secret with version", func(t *testing.T) {
		// Store multiple versions
		testServer.DB.Exec(`DELETE FROM secrets WHERE resource_id = ?`, account+":variable:db/password")

		for i := 0; i < 3; i++ {
			storeReq := httptest.NewRequest("POST", "/secrets/"+account+"/variable/db%2Fpassword",
				strings.NewReader("secret-v"+string(rune('1'+i))))
			storeReq.Header.Set("Authorization", authHeader)
			storeW := httptest.NewRecorder()
			testServer.Router.ServeHTTP(storeW, storeReq)
		}

		// Get latest (should be v3)
		req := httptest.NewRequest("GET", "/secrets/"+account+"/variable/db%2Fpassword", nil)
		req.Header.Set("Authorization", authHeader)
		w := httptest.NewRecorder()
		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		body, _ := io.ReadAll(resp.Body)
		if string(body) != "secret-v3" {
			t.Errorf("expected latest secret 'secret-v3', got %q", string(body))
		}
	})

	t.Run("expire secret clears expiration", func(t *testing.T) {
		// Create a new variable for expiration test
		expiringVarId := "expiring/secret"
		expiringResourceId := account + ":variable:" + expiringVarId
		_ = CreateTestVariable(testServer.DB, account, expiringVarId, adminRoleId)
		_ = GrantPermission(testServer.DB, "execute", expiringResourceId, adminRoleId)
		_ = GrantPermission(testServer.DB, "update", expiringResourceId, adminRoleId)

		// Store a secret first
		secretValue := "expiring-secret-value"
		storeReq := httptest.NewRequest("POST", "/secrets/"+account+"/variable/expiring%2Fsecret", strings.NewReader(secretValue))
		storeReq.Header.Set("Authorization", authHeader)
		storeW := httptest.NewRecorder()
		testServer.Router.ServeHTTP(storeW, storeReq)

		// Set an expiration directly in DB (simulating rotation)
		pastTime := time.Now().Add(-1 * time.Hour)
		testServer.DB.Model(&struct{}{}).Table("secrets").Where("resource_id = ?", expiringResourceId).Update("expires_at", pastTime)

		// Verify secret is now expired (should return 404)
		getReq := httptest.NewRequest("GET", "/secrets/"+account+"/variable/expiring%2Fsecret", nil)
		getReq.Header.Set("Authorization", authHeader)
		getW := httptest.NewRecorder()
		testServer.Router.ServeHTTP(getW, getReq)
		if getW.Result().StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404 for expired secret, got %d", getW.Result().StatusCode)
		}

		// Now expire (clear expiration) via API
		expireReq := httptest.NewRequest("POST", "/secrets/"+account+"/variable/expiring%2Fsecret?expirations", nil)
		expireReq.Header.Set("Authorization", authHeader)
		expireW := httptest.NewRecorder()
		testServer.Router.ServeHTTP(expireW, expireReq)

		resp := expireW.Result()
		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 201, got %d: %s", resp.StatusCode, string(body))
		}

		// Retrieve the secret - should work now since expiration was cleared
		getReq2 := httptest.NewRequest("GET", "/secrets/"+account+"/variable/expiring%2Fsecret", nil)
		getReq2.Header.Set("Authorization", authHeader)
		getW2 := httptest.NewRecorder()
		testServer.Router.ServeHTTP(getW2, getReq2)

		getResp := getW2.Result()
		if getResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(getResp.Body)
			t.Fatalf("expected status 200 after clearing expiration, got %d: %s", getResp.StatusCode, string(body))
		}
	})

	t.Run("retrieve expired secret returns 404", func(t *testing.T) {
		// Create a new variable for expired test
		expiredVarId := "expired/secret"
		expiredResourceId := account + ":variable:" + expiredVarId
		_ = CreateTestVariable(testServer.DB, account, expiredVarId, adminRoleId)
		_ = GrantPermission(testServer.DB, "execute", expiredResourceId, adminRoleId)
		_ = GrantPermission(testServer.DB, "update", expiredResourceId, adminRoleId)

		// Store a secret
		secretValue := "already-expired-secret"
		req := httptest.NewRequest("POST", "/secrets/"+account+"/variable/expired%2Fsecret", strings.NewReader(secretValue))
		req.Header.Set("Authorization", authHeader)
		w := httptest.NewRecorder()
		testServer.Router.ServeHTTP(w, req)

		// Set expiration to past (simulating rotation that has expired)
		pastTime := time.Now().Add(-1 * time.Hour)
		testServer.DB.Model(&struct{}{}).Table("secrets").Where("resource_id = ?", expiredResourceId).Update("expires_at", pastTime)

		// Retrieve the secret - should fail since expired
		getReq := httptest.NewRequest("GET", "/secrets/"+account+"/variable/expired%2Fsecret", nil)
		getReq.Header.Set("Authorization", authHeader)
		getW := httptest.NewRecorder()
		testServer.Router.ServeHTTP(getW, getReq)

		getResp := getW.Result()
		if getResp.StatusCode != http.StatusNotFound {
			body, _ := io.ReadAll(getResp.Body)
			t.Fatalf("expected status 404 for expired secret, got %d: %s", getResp.StatusCode, string(body))
		}
	})

	t.Run("expire non-variable kind returns 422", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/secrets/"+account+"/policy/some-policy?expirations", nil)
		req.Header.Set("Authorization", authHeader)
		w := httptest.NewRecorder()

		testServer.Router.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusUnprocessableEntity {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 422 for non-variable kind, got %d: %s", resp.StatusCode, string(body))
		}
	})
}
