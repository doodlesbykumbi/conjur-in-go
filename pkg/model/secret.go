package model

import (
	"database/sql"
)

type Secret struct {
	ResourceId string
	Value      sql.RawBytes
}

func (s Secret) TableName() string {
	return "secrets"
}
