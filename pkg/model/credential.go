package model

import (
	"database/sql"
	"fmt"

	"gorm.io/gorm"

	"conjur-in-go/pkg/slosilo"
)

type Credential struct {
	RoleId string
	ApiKey sql.RawBytes
}

func (c Credential) TableName() string {
	return "credentials"
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
