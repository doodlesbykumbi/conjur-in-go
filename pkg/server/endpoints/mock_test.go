package endpoints

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"conjur-in-go/pkg/slosilo"
)

func TestMockDB(t *testing.T) {
	mockDB, err := NewMockDB()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer mockDB.Close()

	// Test that mock was created successfully
	if mockDB.DB == nil {
		t.Error("expected DB to be non-nil")
	}
	if mockDB.Mock == nil {
		t.Error("expected Mock to be non-nil")
	}
	if mockDB.GormDB == nil {
		t.Error("expected GormDB to be non-nil")
	}
}

func TestMockCredentialQuery(t *testing.T) {
	mockDB, err := NewMockDB()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer mockDB.Close()

	roleId := "myorg:user:admin"
	apiKey := []byte("encrypted-api-key")

	mockDB.ExpectCredentialQuery(roleId, apiKey)

	var result struct {
		ApiKey []byte `gorm:"column:api_key"`
	}
	err = mockDB.GormDB.Table("credentials").
		Select("api_key").
		Where("role_id = ?", roleId).
		First(&result).Error

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if string(result.ApiKey) != string(apiKey) {
		t.Errorf("expected api_key %q, got %q", apiKey, result.ApiKey)
	}

	if err := mockDB.VerifyExpectations(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestMockCredentialNotFound(t *testing.T) {
	mockDB, err := NewMockDB()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer mockDB.Close()

	roleId := "myorg:user:nonexistent"
	mockDB.ExpectCredentialNotFound(roleId)

	var result struct {
		ApiKey []byte `gorm:"column:api_key"`
	}
	err = mockDB.GormDB.Table("credentials").
		Select("api_key").
		Where("role_id = ?", roleId).
		First(&result).Error

	if err == nil {
		t.Error("expected error for non-existent credential")
	}

	if err := mockDB.VerifyExpectations(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestMockPermissionCheck(t *testing.T) {
	mockDB, err := NewMockDB()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer mockDB.Close()

	tests := []struct {
		name    string
		allowed bool
	}{
		{"permission allowed", true},
		{"permission denied", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB, err := NewMockDB()
			if err != nil {
				t.Fatalf("failed to create mock db: %v", err)
			}
			defer mockDB.Close()

			mockDB.ExpectPermissionCheck(tt.allowed)

			var result bool
			err = mockDB.GormDB.Raw(`SELECT is_role_allowed_to(?, ?, ?)`, "role", "resource", "execute").
				Scan(&result).Error

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tt.allowed {
				t.Errorf("expected %v, got %v", tt.allowed, result)
			}

			if err := mockDB.VerifyExpectations(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestMockSecretQuery(t *testing.T) {
	mockDB, err := NewMockDB()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer mockDB.Close()

	resourceId := "myorg:variable:db/password"
	encryptedValue := []byte("encrypted-secret-value")
	version := 1

	mockDB.ExpectSecretQuery(resourceId, encryptedValue, version)

	var result struct {
		ResourceId string `gorm:"column:resource_id"`
		Value      []byte `gorm:"column:value"`
		Version    int    `gorm:"column:version"`
	}
	err = mockDB.GormDB.Table("secrets").
		Select("resource_id, value, version").
		First(&result).Error

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result.ResourceId != resourceId {
		t.Errorf("expected resource_id %q, got %q", resourceId, result.ResourceId)
	}
	if string(result.Value) != string(encryptedValue) {
		t.Errorf("expected value %q, got %q", encryptedValue, result.Value)
	}
	if result.Version != version {
		t.Errorf("expected version %d, got %d", version, result.Version)
	}

	if err := mockDB.VerifyExpectations(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestMockSecretNotFound(t *testing.T) {
	mockDB, err := NewMockDB()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer mockDB.Close()

	mockDB.ExpectSecretNotFound()

	var result struct {
		Value []byte `gorm:"column:value"`
	}
	err = mockDB.GormDB.Table("secrets").
		Select("value").
		First(&result).Error

	if err == nil {
		t.Error("expected error for non-existent secret")
	}

	if err := mockDB.VerifyExpectations(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestMockTestServer(t *testing.T) {
	dataKey := make([]byte, 32)
	for i := range dataKey {
		dataKey[i] = byte(i)
	}

	server, mock, err := NewMockTestServer(dataKey)
	if err != nil {
		t.Fatalf("failed to create mock test server: %v", err)
	}

	if server == nil {
		t.Error("expected server to be non-nil")
	}
	if mock == nil {
		t.Error("expected mock to be non-nil")
	}

	// Register a simple endpoint and test it works
	RegisterStatusEndpoints(server)

	// Status endpoint doesn't need DB, so no mock expectations needed
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	server.Router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestAuthenticateWithMock(t *testing.T) {
	dataKey := make([]byte, 32)
	for i := range dataKey {
		dataKey[i] = byte(i)
	}

	cipher, _ := slosilo.NewSymmetric(dataKey)

	t.Run("credential lookup", func(t *testing.T) {
		mockDB, err := NewMockDB()
		if err != nil {
			t.Fatalf("failed to create mock db: %v", err)
		}
		defer mockDB.Close()

		roleId := "myorg:user:admin"
		apiKey := "test-api-key"

		// Encrypt the API key as it would be stored
		encryptedKey, _ := cipher.Encrypt([]byte(roleId), []byte(apiKey))

		mockDB.ExpectCredentialQuery(roleId, encryptedKey)

		var cred struct {
			ApiKey []byte `gorm:"column:api_key"`
		}
		err = mockDB.GormDB.Table("credentials").
			Select("api_key").
			Where("role_id = ?", roleId).
			First(&cred).Error

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Decrypt and verify
		decrypted, err := cipher.Decrypt([]byte(roleId), cred.ApiKey)
		if err != nil {
			t.Errorf("failed to decrypt: %v", err)
		}
		if string(decrypted) != apiKey {
			t.Errorf("expected api key %q, got %q", apiKey, decrypted)
		}

		if err := mockDB.VerifyExpectations(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

func TestSecretsWithMock(t *testing.T) {
	dataKey := make([]byte, 32)
	for i := range dataKey {
		dataKey[i] = byte(i)
	}

	cipher, _ := slosilo.NewSymmetric(dataKey)

	t.Run("secret encryption roundtrip", func(t *testing.T) {
		mockDB, err := NewMockDB()
		if err != nil {
			t.Fatalf("failed to create mock db: %v", err)
		}
		defer mockDB.Close()

		resourceId := "myorg:variable:db/password"
		secretValue := "super-secret-password"

		// Encrypt the secret as it would be stored
		encryptedValue, _ := cipher.Encrypt([]byte(resourceId), []byte(secretValue))

		mockDB.ExpectSecretQuery(resourceId, encryptedValue, 1)

		var secret struct {
			ResourceId string `gorm:"column:resource_id"`
			Value      []byte `gorm:"column:value"`
			Version    int    `gorm:"column:version"`
		}
		err = mockDB.GormDB.Table("secrets").
			Select("resource_id, value, version").
			First(&secret).Error

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Decrypt and verify
		decrypted, err := cipher.Decrypt([]byte(resourceId), secret.Value)
		if err != nil {
			t.Errorf("failed to decrypt: %v", err)
		}
		if string(decrypted) != secretValue {
			t.Errorf("expected secret %q, got %q", secretValue, decrypted)
		}

		if err := mockDB.VerifyExpectations(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

func TestResourcePermissionWithMock(t *testing.T) {
	t.Run("permission check allowed", func(t *testing.T) {
		mockDB, err := NewMockDB()
		if err != nil {
			t.Fatalf("failed to create mock db: %v", err)
		}
		defer mockDB.Close()

		mockDB.ExpectPermissionCheck(true)

		var allowed bool
		err = mockDB.GormDB.Raw(`SELECT is_role_allowed_to(?, ?, ?)`,
			"myorg:user:admin",
			"myorg:variable:db/password",
			"execute",
		).Scan(&allowed).Error

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !allowed {
			t.Error("expected permission to be allowed")
		}

		if err := mockDB.VerifyExpectations(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("permission check denied", func(t *testing.T) {
		mockDB, err := NewMockDB()
		if err != nil {
			t.Fatalf("failed to create mock db: %v", err)
		}
		defer mockDB.Close()

		mockDB.ExpectPermissionCheck(false)

		var allowed bool
		err = mockDB.GormDB.Raw(`SELECT is_role_allowed_to(?, ?, ?)`,
			"myorg:user:guest",
			"myorg:variable:db/password",
			"execute",
		).Scan(&allowed).Error

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if allowed {
			t.Error("expected permission to be denied")
		}

		if err := mockDB.VerifyExpectations(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

func TestTransactionWithMock(t *testing.T) {
	t.Run("begin and commit", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create sqlmock: %v", err)
		}
		defer db.Close()

		mock.ExpectBegin()
		mock.ExpectExec(`INSERT INTO`).WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("failed to begin tx: %v", err)
		}

		_, err = tx.Exec(`INSERT INTO test (id) VALUES (1)`)
		if err != nil {
			t.Fatalf("failed to exec: %v", err)
		}

		err = tx.Commit()
		if err != nil {
			t.Fatalf("failed to commit: %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})

	t.Run("begin and rollback", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create sqlmock: %v", err)
		}
		defer db.Close()

		mock.ExpectBegin()
		mock.ExpectExec(`INSERT INTO`).WillReturnError(sql.ErrConnDone)
		mock.ExpectRollback()

		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("failed to begin tx: %v", err)
		}

		_, err = tx.Exec(`INSERT INTO test (id) VALUES (1)`)
		if err == nil {
			t.Fatal("expected error from exec")
		}

		err = tx.Rollback()
		if err != nil {
			t.Fatalf("failed to rollback: %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

func TestSigningKeyWithMock(t *testing.T) {
	dataKey := make([]byte, 32)
	for i := range dataKey {
		dataKey[i] = byte(i)
	}

	cipher, _ := slosilo.NewSymmetric(dataKey)

	t.Run("signing key lookup", func(t *testing.T) {
		mockDB, err := NewMockDB()
		if err != nil {
			t.Fatalf("failed to create mock db: %v", err)
		}
		defer mockDB.Close()

		// Generate a test key
		key, _ := slosilo.GenerateKey()
		keyBytes, _ := key.Serialize()
		keyId := "authn:myorg"
		encryptedKey, _ := cipher.Encrypt([]byte(keyId), keyBytes)

		mockDB.ExpectSigningKeyQuery(keyId, encryptedKey, key.Fingerprint())

		var result struct {
			Id          string `gorm:"column:id"`
			Key         []byte `gorm:"column:key"`
			Fingerprint string `gorm:"column:fingerprint"`
		}
		err = mockDB.GormDB.Table("slosilo_keystore").
			Select("id, key, fingerprint").
			Where("id = ?", keyId).
			First(&result).Error

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Decrypt and verify
		decryptedKey, err := cipher.Decrypt([]byte(keyId), result.Key)
		if err != nil {
			t.Errorf("failed to decrypt key: %v", err)
		}

		recoveredKey, err := slosilo.NewKey(decryptedKey)
		if err != nil {
			t.Errorf("failed to recover key: %v", err)
		}

		if recoveredKey.Fingerprint() != key.Fingerprint() {
			t.Errorf("fingerprint mismatch: expected %s, got %s",
				key.Fingerprint(), recoveredKey.Fingerprint())
		}

		if err := mockDB.VerifyExpectations(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	})
}

func TestRoleIdFromLoginUnit(t *testing.T) {
	tests := []struct {
		name     string
		account  string
		login    string
		expected string
	}{
		{"simple user", "org", "alice", "org:user:alice"},
		{"explicit user", "org", "user/alice", "org:user:alice"},
		{"host", "org", "host/myapp", "org:host:myapp"},
		{"nested host", "org", "host/app/prod/server", "org:host:app/prod/server"},
		{"admin", "myorg", "admin", "myorg:user:admin"},
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

func TestURLDecoding(t *testing.T) {
	tests := []struct {
		name     string
		encoded  string
		expected string
	}{
		{"simple", "db/password", "db/password"},
		{"url encoded slash", "db%2Fpassword", "db/password"},
		{"multiple slashes", "app%2Fprod%2Fdb", "app/prod/db"},
		{"special chars", "my%20secret", "my secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test/"+tt.encoded, nil)
			// URL decoding happens automatically in path parsing
			if strings.Contains(req.URL.Path, "%") {
				t.Logf("Note: URL path contains encoded chars: %s", req.URL.Path)
			}
		})
	}
}
