package store

import (
	"errors"
	"regexp"

	"gorm.io/gorm"

	"conjur-in-go/pkg/model"
	"conjur-in-go/pkg/slosilo"
)

var accountKeyIdRgx = regexp.MustCompile(`^authn:([^:]*)`)

type StoredKey struct {
	*slosilo.Key
	account string
}

func (k StoredKey) Account() string {
	return k.account
}

type KeyStore struct {
	db *gorm.DB
	// TODO: have different adapters for storing and retrieving the keys
	// See https://github.com/cyberark/slosilo/blob/master/lib/slosilo/keystore.rb#L74
	keysById          map[string]*StoredKey
	keysByFingerprint map[string]*StoredKey
}

func NewKeyStore(db *gorm.DB) *KeyStore {
	return &KeyStore{
		db: db,

		// TODO:
		keysById:          map[string]*StoredKey{},
		keysByFingerprint: map[string]*StoredKey{},
	}
}

func (k KeyStore) fetchKey(query map[string]string) (*StoredKey, error) {
	var storedKey model.Key
	tx := k.db.Where(query).First(&storedKey)
	err := tx.Error
	if err != nil {
		return nil, err
	}

	keyInstance, err := slosilo.NewKey(storedKey.Key)
	if err != nil {
		return nil, err
	}

	accountKeyIdMatches := accountKeyIdRgx.FindStringSubmatch(storedKey.Id)
	if len(accountKeyIdMatches) < 1 {
		return nil, errors.New("key has malformed id")
	}

	keyInstanceFingerprint := keyInstance.Fingerprint()
	if storedKey.Fingerprint != keyInstanceFingerprint {
		return nil, errors.New("key has bad stored fingerprint")
	}

	key := &StoredKey{
		Key:     keyInstance,
		account: accountKeyIdMatches[1],
	}

	k.keysById[storedKey.Id] = key
	k.keysByFingerprint[storedKey.Fingerprint] = key

	return key, nil
}

func (k KeyStore) ByFingerprint(fingerprint string) (*StoredKey, error) {
	if key, ok := k.keysByFingerprint[fingerprint]; ok {
		return key, nil
	}

	return k.fetchKey(map[string]string{"fingerprint": fingerprint})
}

func (k KeyStore) ByAccount(account string) (*StoredKey, error) {
	id := "authn:" + account

	if _key, ok := k.keysById[id]; ok {
		return _key, nil
	}

	return k.fetchKey(map[string]string{"id": id})
}
