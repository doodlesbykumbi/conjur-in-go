package authn

import (
	"context"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"conjur-in-go/pkg/authenticator"
	"conjur-in-go/pkg/slosilo"
)

func setupTestDB(t *testing.T) (*gorm.DB, sqlmock.Sqlmock, slosilo.SymmetricCipher) {
	mockDB, mock, err := sqlmock.New()
	require.NoError(t, err)

	gormDB, err := gorm.Open(
		postgres.New(postgres.Config{
			Conn:                 mockDB,
			PreferSimpleProtocol: true,
		}),
		&gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		},
	)
	require.NoError(t, err)

	dataKey := make([]byte, 32)
	for i := range dataKey {
		dataKey[i] = byte(i)
	}
	cipher, err := slosilo.NewSymmetric(dataKey)
	require.NoError(t, err)

	return gormDB, mock, cipher
}

func TestAuthenticator_Name(t *testing.T) {
	db, _, cipher := setupTestDB(t)
	auth := New(db, cipher)
	assert.Equal(t, "authn", auth.Name())
}

func TestAuthenticator_Authenticate_Success(t *testing.T) {
	db, mock, cipher := setupTestDB(t)
	auth := New(db, cipher)

	roleID := "myorg:user:alice"
	apiKey := "test-api-key-123"

	encryptedKey, err := cipher.Encrypt([]byte(roleID), []byte(apiKey))
	require.NoError(t, err)

	rows := sqlmock.NewRows([]string{"api_key"}).AddRow(encryptedKey)
	mock.ExpectQuery(`SELECT api_key FROM credentials`).
		WithArgs(roleID).
		WillReturnRows(rows)

	input := authenticator.AuthenticatorInput{
		Account:     "myorg",
		Login:       "alice",
		Credentials: []byte(apiKey),
	}

	result, err := auth.Authenticate(context.Background(), input)
	assert.NoError(t, err)
	assert.Equal(t, roleID, result)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAuthenticator_Authenticate_WrongAPIKey(t *testing.T) {
	db, mock, cipher := setupTestDB(t)
	auth := New(db, cipher)

	roleID := "myorg:user:bob"
	apiKey := "correct-api-key"

	encryptedKey, err := cipher.Encrypt([]byte(roleID), []byte(apiKey))
	require.NoError(t, err)

	rows := sqlmock.NewRows([]string{"api_key"}).AddRow(encryptedKey)
	mock.ExpectQuery(`SELECT api_key FROM credentials`).
		WithArgs(roleID).
		WillReturnRows(rows)

	input := authenticator.AuthenticatorInput{
		Account:     "myorg",
		Login:       "bob",
		Credentials: []byte("wrong-api-key"),
	}

	_, err = auth.Authenticate(context.Background(), input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestAuthenticator_Authenticate_UserNotFound(t *testing.T) {
	db, mock, cipher := setupTestDB(t)
	auth := New(db, cipher)

	roleID := "myorg:user:nonexistent"

	mock.ExpectQuery(`SELECT api_key FROM credentials`).
		WithArgs(roleID).
		WillReturnError(sql.ErrNoRows)

	input := authenticator.AuthenticatorInput{
		Account:     "myorg",
		Login:       "nonexistent",
		Credentials: []byte("any-key"),
	}

	_, err := auth.Authenticate(context.Background(), input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestAuthenticator_Authenticate_EmptyLogin(t *testing.T) {
	db, _, cipher := setupTestDB(t)
	auth := New(db, cipher)

	input := authenticator.AuthenticatorInput{
		Account:     "myorg",
		Login:       "",
		Credentials: []byte("any-key"),
	}

	_, err := auth.Authenticate(context.Background(), input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "login is required")
}

func TestAuthenticator_Status(t *testing.T) {
	db, mock, cipher := setupTestDB(t)
	auth := New(db, cipher)

	mock.ExpectExec(`SELECT 1`).WillReturnResult(sqlmock.NewResult(0, 0))

	err := auth.Status(context.Background(), "myorg", "")
	assert.NoError(t, err)
}
