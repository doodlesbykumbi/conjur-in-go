package store

type StoredKey struct {
	Id          string `silo:"aad"`
	Fingerprint string
	Key         string `silo:"encrypted"`
}

func (_ StoredKey) TableName() string {
	return "slosilo_keystore"
}
