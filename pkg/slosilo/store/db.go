package store

import (
	"errors"
	"regexp"

	"gorm.io/gorm"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/model"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
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

// List returns all key IDs in the keystore
func (k KeyStore) List() ([]string, error) {
	// Use raw query to avoid triggering AfterFind hook which requires cipher
	var ids []string
	if err := k.db.Raw(`SELECT id FROM slosilo_keystore`).Scan(&ids).Error; err != nil {
		return nil, err
	}
	return ids, nil
}

// Get retrieves a key by its ID
func (k KeyStore) Get(id string) (*StoredKey, error) {
	if key, ok := k.keysById[id]; ok {
		return key, nil
	}
	return k.fetchKey(map[string]string{"id": id})
}

// Put stores a key with the given ID
func (k KeyStore) Put(id string, key *slosilo.Key) error {
	fingerprint := key.Fingerprint()
	keyBytes, err := key.Serialize()
	if err != nil {
		return err
	}

	storedKey := model.Key{
		Id:          id,
		Fingerprint: fingerprint,
		Key:         keyBytes,
	}

	if err := k.db.Create(&storedKey).Error; err != nil {
		return err
	}

	// Cache the key
	accountKeyIdMatches := accountKeyIdRgx.FindStringSubmatch(id)
	account := ""
	if len(accountKeyIdMatches) > 1 {
		account = accountKeyIdMatches[1]
	}

	cached := &StoredKey{
		Key:     key,
		account: account,
	}
	k.keysById[id] = cached
	k.keysByFingerprint[fingerprint] = cached

	return nil
}

// Delete removes a key by its ID
func (k KeyStore) Delete(id string) error {
	// Remove from cache
	if key, ok := k.keysById[id]; ok {
		delete(k.keysByFingerprint, key.Fingerprint())
		delete(k.keysById, id)
	}

	// Remove from database
	return k.db.Where("id = ?", id).Delete(&model.Key{}).Error
}
