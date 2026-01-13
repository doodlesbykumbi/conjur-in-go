package endpoints

import (
	"context"
	"database/sql"
	"encoding/base64"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"conjur-in-go/pkg/server"
	"conjur-in-go/pkg/slosilo"
	"conjur-in-go/pkg/slosilo/store"
	"conjur-in-go/pkg/utils"
)

// TestServer creates a server instance for testing
// It requires a running PostgreSQL database
func NewTestServer(dbURL string, dataKey []byte) (*server.Server, error) {
	cipher, err := slosilo.NewSymmetric(dataKey)
	if err != nil {
		return nil, err
	}

	db, err := gorm.Open(
		postgres.New(postgres.Config{
			DSN:                  dbURL,
			PreferSimpleProtocol: true,
		}),
		&gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		},
	)
	if err != nil {
		return nil, err
	}

	ctx := context.WithValue(context.Background(), "cipher", cipher)
	db = db.WithContext(ctx)

	keystore := store.NewKeyStore(db)
	s := server.NewServer(keystore, cipher, db, "127.0.0.1", "0")

	return s, nil
}

// SetupTestAccount creates a test account with admin user and signing key
func SetupTestAccount(db *gorm.DB, cipher slosilo.SymmetricCipher, account string, adminAPIKey string) error {
	// Create signing key
	key, err := slosilo.GenerateKey()
	if err != nil {
		return err
	}

	keyBytes, err := key.Serialize()
	if err != nil {
		return err
	}

	keyId := "authn:" + account
	encryptedKey, err := cipher.Encrypt([]byte(keyId), keyBytes)
	if err != nil {
		return err
	}

	// Insert signing key
	err = db.Exec(`
		INSERT INTO slosilo_keystore (id, key, fingerprint) VALUES (?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET key = EXCLUDED.key, fingerprint = EXCLUDED.fingerprint
	`, keyId, encryptedKey, key.Fingerprint()).Error
	if err != nil {
		return err
	}

	// Create admin role
	adminRoleId := account + ":user:admin"
	err = db.Exec(`INSERT INTO roles (role_id) VALUES (?) ON CONFLICT DO NOTHING`, adminRoleId).Error
	if err != nil {
		return err
	}

	// Create admin resource
	err = db.Exec(`
		INSERT INTO resources (resource_id, owner_id) VALUES (?, ?)
		ON CONFLICT DO NOTHING
	`, adminRoleId, adminRoleId).Error
	if err != nil {
		return err
	}

	// Encrypt and store API key
	encryptedAPIKey, err := cipher.Encrypt([]byte(adminRoleId), []byte(adminAPIKey))
	if err != nil {
		return err
	}

	err = db.Exec(`
		INSERT INTO credentials (role_id, api_key) VALUES (?, ?)
		ON CONFLICT (role_id) DO UPDATE SET api_key = EXCLUDED.api_key
	`, adminRoleId, encryptedAPIKey).Error
	if err != nil {
		return err
	}

	// Create root policy
	policyRoleId := account + ":policy:root"
	err = db.Exec(`INSERT INTO roles (role_id) VALUES (?) ON CONFLICT DO NOTHING`, policyRoleId).Error
	if err != nil {
		return err
	}

	err = db.Exec(`
		INSERT INTO resources (resource_id, owner_id) VALUES (?, ?)
		ON CONFLICT DO NOTHING
	`, policyRoleId, adminRoleId).Error
	if err != nil {
		return err
	}

	return nil
}

// CleanupTestData removes test data from the database
func CleanupTestData(db *gorm.DB, account string) error {
	// Delete in reverse order of foreign key dependencies
	db.Exec(`DELETE FROM secrets WHERE resource_id LIKE ?`, account+":%")
	db.Exec(`DELETE FROM permissions WHERE resource_id LIKE ? OR role_id LIKE ?`, account+":%", account+":%")
	db.Exec(`DELETE FROM annotations WHERE resource_id LIKE ?`, account+":%")
	db.Exec(`DELETE FROM role_memberships WHERE role_id LIKE ? OR member_id LIKE ?`, account+":%", account+":%")
	db.Exec(`DELETE FROM credentials WHERE role_id LIKE ?`, account+":%")
	db.Exec(`DELETE FROM resources WHERE resource_id LIKE ?`, account+":%")
	db.Exec(`DELETE FROM roles WHERE role_id LIKE ?`, account+":%")
	db.Exec(`DELETE FROM slosilo_keystore WHERE id LIKE ?`, "authn:"+account)
	return nil
}

// CreateTestVariable creates a variable for testing
func CreateTestVariable(db *gorm.DB, account, variableId, ownerRoleId string) error {
	resourceId := account + ":variable:" + variableId

	return db.Exec(`
		INSERT INTO resources (resource_id, owner_id) VALUES (?, ?)
		ON CONFLICT DO NOTHING
	`, resourceId, ownerRoleId).Error
}

// CreateTestSecret stores an encrypted secret value
func CreateTestSecret(db *gorm.DB, cipher slosilo.SymmetricCipher, account, variableId string, value []byte) error {
	resourceId := account + ":variable:" + variableId

	encryptedValue, err := cipher.Encrypt([]byte(resourceId), value)
	if err != nil {
		return err
	}

	return db.Exec(`
		INSERT INTO secrets (resource_id, value) VALUES (?, ?)
	`, resourceId, encryptedValue).Error
}

// GrantPermission grants a permission to a role
func GrantPermission(db *gorm.DB, privilege, resourceId, roleId string) error {
	return db.Exec(`
		INSERT INTO permissions (privilege, resource_id, role_id) VALUES (?, ?, ?)
		ON CONFLICT DO NOTHING
	`, privilege, resourceId, roleId).Error
}

// MockCredential is a test credential that doesn't need encryption
type MockCredential struct {
	RoleId string
	ApiKey sql.RawBytes
}

func (MockCredential) TableName() string {
	return "credentials"
}

// GenerateTestToken creates a valid JWT token for testing
func GenerateTestToken(db *gorm.DB, cipher slosilo.SymmetricCipher, account, login string) (string, error) {
	// Get the signing key for the account
	keyId := "authn:" + account
	var keyRecord struct {
		Key []byte
	}
	err := db.Raw(`SELECT key FROM slosilo_keystore WHERE id = ?`, keyId).Scan(&keyRecord).Error
	if err != nil {
		return "", err
	}

	// Decrypt the key
	keyBytes, err := cipher.Decrypt([]byte(keyId), keyRecord.Key)
	if err != nil {
		return "", err
	}

	key, err := slosilo.NewKey(keyBytes)
	if err != nil {
		return "", err
	}

	// Create token
	headerMap := map[string]interface{}{
		"alg": "conjur.org/slosilo/v2",
		"kid": key.Fingerprint(),
	}
	claimsMap := map[string]interface{}{
		"iat": time.Now().Unix(),
		"sub": login,
	}

	header := utils.ToJson(headerMap)
	claims := utils.ToJson(claimsMap)

	salt, _ := slosilo.RandomBytes(32)
	stringToSign := strings.Join(
		[]string{
			base64.URLEncoding.EncodeToString([]byte(header)),
			base64.URLEncoding.EncodeToString([]byte(claims)),
		},
		".",
	)

	signature, err := key.Sign([]byte(stringToSign), salt)
	if err != nil {
		return "", err
	}

	jwt := map[string]string{
		"protected": base64.URLEncoding.EncodeToString([]byte(header)),
		"payload":   base64.URLEncoding.EncodeToString([]byte(claims)),
		"signature": base64.URLEncoding.EncodeToString(signature),
	}

	tokenJSON := utils.ToJson(jwt)
	return base64.URLEncoding.EncodeToString([]byte(tokenJSON)), nil
}
