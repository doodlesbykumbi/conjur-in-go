package model

type Key struct {
	Id          string
	Fingerprint string
	Key         []byte `slosilo:"encrypted;aad:Id"`
}

func (_ Key) TableName() string {
	return "slosilo_keystore"
}
