package store

import (
	"errors"
	"regexp"

	"gorm.io/gorm"

	"conjur-in-go/pkg/slosilo"
)

var accountKeyIdRgx = regexp.MustCompile(`^authn:([^:]*)`)

type Key struct {
	StoredKey *StoredKey
	*slosilo.Key
	_account string
}

func (k Key) Account() string {
	return k._account
}

type KeyStore struct {
	db                *gorm.DB
	cipher            *slosilo.Symmetric
	keysById          map[string]*Key
	keysByFingerprint map[string]*Key
}

func NewKeyStore(db *gorm.DB, dataKey []byte) (*KeyStore, error) {
	cipher, err := slosilo.NewSymmetric(dataKey)
	if err != nil {
		return nil, err
	}

	return &KeyStore{
		cipher:            cipher,
		db:                db,
		keysById:          map[string]*Key{},
		keysByFingerprint: map[string]*Key{},
	}, nil
}

func (k KeyStore) fetchKey(query *StoredKey) (*Key, error) {
	if _key, ok := k.keysByFingerprint[query.Fingerprint]; ok {
		return _key, nil
	}

	if _key, ok := k.keysById[query.Id]; ok {
		return _key, nil
	}

	var storedKey StoredKey
	tx := k.db.Where(query).First(&storedKey)
	err := tx.Error
	if err != nil {
		return nil, err
	}

	decryptedKey, err := k.cipher.Decrypt([]byte(storedKey.Id), storedKey.Key)
	if err != nil {
		return nil, err
	}

	keyInstance, err := slosilo.NewKey(decryptedKey)
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

	key := &Key{
		StoredKey: &storedKey,
		Key:       keyInstance,
		_account:  accountKeyIdMatches[1],
	}

	k.keysById[storedKey.Id] = key
	k.keysByFingerprint[storedKey.Fingerprint] = key

	return key, nil
}

func (k KeyStore) ByFingerprint(fingerprint string) (*Key, error) {
	return k.fetchKey(&StoredKey{Fingerprint: fingerprint})
}

func (k KeyStore) Cipher() *slosilo.Symmetric {
	return k.cipher
}

func (k KeyStore) ByAccount(account string) (*Key, error) {
	return k.fetchKey(&StoredKey{Id: "authn:"+account})
}