package model

import (
	"fmt"

	"gorm.io/gorm"
)

type Secret struct {
	ResourceId string
	Value      []byte `gorm:"type:bytea;"`
}

func (s Secret) TableName() string {
	return "secrets"
}

func (s *Secret) BeforeCreate(tx *gorm.DB) error {
	encrypt := getCipherForDb(tx).Encrypt

	var err error
	s.Value, err = encrypt([]byte(s.ResourceId), s.Value)
	if err != nil {
		err = fmt.Errorf("secret decryption failed for resource_id=%q", s.ResourceId)
	}
	return err
}

func (s *Secret) AfterFind(tx *gorm.DB) (err error) {
	decrypt := getCipherForDb(tx).Decrypt

	s.Value, err = decrypt([]byte(s.ResourceId), s.Value)
	if err != nil {
		err = fmt.Errorf("secret decryption failed for resource_id=%q", s.ResourceId)
	}
	return
}
