package model

type Credential struct {
	RoleId string
	ApiKey []byte `slosilo:"encrypted;aad:RoleId"`
	EncryptedHash []byte `slosilo:"encrypted;aad:RoleId"`
}

func (c Credential) TableName() string {
	return "credentials"
}
