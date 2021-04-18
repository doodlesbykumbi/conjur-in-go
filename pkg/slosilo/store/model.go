package store

import (
	"database/sql"
)

type StoredKey struct {
	Id          string
	Fingerprint string
	Key         sql.RawBytes
}

func (_ StoredKey) TableName() string {
	return "slosilo_keystore"
}
