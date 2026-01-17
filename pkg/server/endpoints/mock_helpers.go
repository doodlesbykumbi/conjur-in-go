package endpoints

import (
	"database/sql"

	"github.com/DATA-DOG/go-sqlmock"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/server"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo/store"
)

// MockTestServer creates a server instance with a mocked database for unit testing
// Returns the server, sqlmock instance, and any error
func NewMockTestServer(dataKey []byte) (*server.Server, sqlmock.Sqlmock, error) {
	cipher, err := slosilo.NewSymmetric(dataKey)
	if err != nil {
		return nil, nil, err
	}

	// Create sqlmock database
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		return nil, nil, err
	}

	// Wrap with GORM
	gormDB, err := gorm.Open(
		postgres.New(postgres.Config{
			Conn:                 mockDB,
			PreferSimpleProtocol: true,
		}),
		&gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		},
	)
	if err != nil {
		_ = mockDB.Close()
		return nil, nil, err
	}

	keystore := store.NewKeyStore(gormDB)
	s := server.NewServer(keystore, cipher, gormDB, "127.0.0.1", "0")

	return s, mock, nil
}

// MockDB wraps sqlmock for easier test setup
type MockDB struct {
	DB     *sql.DB
	Mock   sqlmock.Sqlmock
	GormDB *gorm.DB
}

// NewMockDB creates a new mock database connection
func NewMockDB() (*MockDB, error) {
	db, mock, err := sqlmock.New()
	if err != nil {
		return nil, err
	}

	gormDB, err := gorm.Open(
		postgres.New(postgres.Config{
			Conn:                 db,
			PreferSimpleProtocol: true,
		}),
		&gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		},
	)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	return &MockDB{
		DB:     db,
		Mock:   mock,
		GormDB: gormDB,
	}, nil
}

// Close closes the mock database
func (m *MockDB) Close() error {
	return m.DB.Close()
}

// ExpectCredentialQuery sets up expectation for credential lookup
func (m *MockDB) ExpectCredentialQuery(roleId string, apiKey []byte) {
	rows := sqlmock.NewRows([]string{"api_key"}).AddRow(apiKey)
	m.Mock.ExpectQuery(`SELECT .* FROM "credentials"`).
		WithArgs(roleId).
		WillReturnRows(rows)
}

// ExpectCredentialNotFound sets up expectation for credential not found
func (m *MockDB) ExpectCredentialNotFound(roleId string) {
	m.Mock.ExpectQuery(`SELECT .* FROM "credentials"`).
		WithArgs(roleId).
		WillReturnError(sql.ErrNoRows)
}

// ExpectRoleQuery sets up expectation for role lookup
func (m *MockDB) ExpectRoleQuery(roleId string) {
	rows := sqlmock.NewRows([]string{"role_id"}).AddRow(roleId)
	m.Mock.ExpectQuery(`SELECT .* FROM "roles"`).
		WithArgs(roleId).
		WillReturnRows(rows)
}

// ExpectRoleNotFound sets up expectation for role not found
func (m *MockDB) ExpectRoleNotFound(roleId string) {
	m.Mock.ExpectQuery(`SELECT .* FROM "roles"`).
		WithArgs(roleId).
		WillReturnError(sql.ErrNoRows)
}

// ExpectResourceQuery sets up expectation for resource lookup
func (m *MockDB) ExpectResourceQuery(resourceId string, ownerId string) {
	rows := sqlmock.NewRows([]string{"resource_id", "owner_id"}).AddRow(resourceId, ownerId)
	m.Mock.ExpectQuery(`SELECT .* FROM "resources"`).
		WithArgs(resourceId).
		WillReturnRows(rows)
}

// ExpectResourceNotFound sets up expectation for resource not found
func (m *MockDB) ExpectResourceNotFound(resourceId string) {
	m.Mock.ExpectQuery(`SELECT .* FROM "resources"`).
		WithArgs(resourceId).
		WillReturnError(sql.ErrNoRows)
}

// ExpectSecretQuery sets up expectation for secret lookup
func (m *MockDB) ExpectSecretQuery(resourceId string, value []byte, version int) {
	rows := sqlmock.NewRows([]string{"resource_id", "value", "version"}).
		AddRow(resourceId, value, version)
	m.Mock.ExpectQuery(`SELECT .* FROM "secrets"`).
		WillReturnRows(rows)
}

// ExpectSecretNotFound sets up expectation for secret not found
func (m *MockDB) ExpectSecretNotFound() {
	m.Mock.ExpectQuery(`SELECT .* FROM "secrets"`).
		WillReturnError(sql.ErrNoRows)
}

// ExpectPermissionCheck sets up expectation for permission check
func (m *MockDB) ExpectPermissionCheck(allowed bool) {
	rows := sqlmock.NewRows([]string{"is_role_allowed_to"}).AddRow(allowed)
	m.Mock.ExpectQuery(`SELECT is_role_allowed_to`).
		WillReturnRows(rows)
}

// ExpectSigningKeyQuery sets up expectation for signing key lookup
func (m *MockDB) ExpectSigningKeyQuery(keyId string, encryptedKey []byte, fingerprint string) {
	rows := sqlmock.NewRows([]string{"id", "key", "fingerprint"}).
		AddRow(keyId, encryptedKey, fingerprint)
	m.Mock.ExpectQuery(`SELECT .* FROM "slosilo_keystore"`).
		WithArgs(keyId).
		WillReturnRows(rows)
}

// ExpectSigningKeyNotFound sets up expectation for signing key not found
func (m *MockDB) ExpectSigningKeyNotFound(keyId string) {
	m.Mock.ExpectQuery(`SELECT .* FROM "slosilo_keystore"`).
		WithArgs(keyId).
		WillReturnError(sql.ErrNoRows)
}

// ExpectSecretInsert sets up expectation for secret insert
func (m *MockDB) ExpectSecretInsert() {
	m.Mock.ExpectExec(`INSERT INTO "secrets"`).
		WillReturnResult(sqlmock.NewResult(1, 1))
}

// ExpectBeginCommit sets up expectation for transaction begin and commit
func (m *MockDB) ExpectBeginCommit() {
	m.Mock.ExpectBegin()
	m.Mock.ExpectCommit()
}

// ExpectBeginRollback sets up expectation for transaction begin and rollback
func (m *MockDB) ExpectBeginRollback() {
	m.Mock.ExpectBegin()
	m.Mock.ExpectRollback()
}

// VerifyExpectations checks that all expectations were met
func (m *MockDB) VerifyExpectations() error {
	return m.Mock.ExpectationsWereMet()
}
