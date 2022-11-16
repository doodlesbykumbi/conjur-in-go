package model

type Secret struct {
	ResourceId string
	Value      []byte `slosilo:";encrypted;aad:ResourceId;"`
}

func (s Secret) TableName() string {
	return "secrets"
}
