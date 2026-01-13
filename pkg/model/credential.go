package model

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"gorm.io/gorm"

	"conjur-in-go/pkg/slosilo"
)

type Credential struct {
	RoleId    string
	ApiKey    sql.RawBytes
	UpdatedAt time.Time
}

func (c Credential) TableName() string {
	return "credentials"
}

// GenerateAPIKey creates a new random API key
func GenerateAPIKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	// Return URL-safe base64 encoded key
	encoded := base64.URLEncoding.EncodeToString(key)
	return []byte(encoded), nil
}

func (c *Credential) AfterFind(tx *gorm.DB) (err error) {
	decrypt := getCipherForDb(tx).Decrypt

	c.ApiKey, err = decrypt([]byte(c.RoleId), c.ApiKey)
	if err != nil {
		err = fmt.Errorf("credential decryption failed for role_id=%q", c.RoleId)
	}
	return
}

func getCipherForDb(tx *gorm.DB) slosilo.SymmetricCipher {
	cipher, ok := tx.Statement.Context.Value("cipher").(slosilo.SymmetricCipher)
	if !ok || cipher == nil {
		panic("no cipher in database context")
	}

	return cipher
}
