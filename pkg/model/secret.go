package model

type Secret struct {
	ResourceId string `silo:"aad"`
	Value      string `silo:"encrypted"`
}

func (s Secret) TableName() string {
	return "secrets"
}
