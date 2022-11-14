package model

import (
	"fmt"

	"gorm.io/gorm"
)

type Key struct {
	Id          string
	Fingerprint string
	Key         []byte
}

func (_ Key) TableName() string {
	return "slosilo_keystore"
}

func (k *Key) AfterFind(tx *gorm.DB) (err error) {
	decrypt := getCipherForDb(tx).Decrypt

	k.Key, err = decrypt([]byte(k.Id), k.Key)
	if err != nil {
		err = fmt.Errorf("key decryption failed for id=%q", k.Id)
	}
	return
}
