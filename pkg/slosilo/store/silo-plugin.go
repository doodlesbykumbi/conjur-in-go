package store

import (
	"conjur-in-go/pkg/slosilo"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"gorm.io/gorm"
)

type options struct {
	// The key to use for encrypt/decrypt operations
	keystore *KeyStore
}

// ApplyOption applies a give set of supplied options
type ApplyOption func(o *options)

type processor func(string, string) string

type siloPlugin struct {
	opt *options
}

// WithKeyStore applies the supplied key to the options for use in
// encryption/decryption
func WithKeyStore(keystore *KeyStore) ApplyOption {
	return func(o *options) {
		o.keystore = keystore
	}
}

func defaultOptions() *options {
	return new(options)
}

// New constructs a new plugin based silo.  It encrypts all secure labeled fields
// before write and decrypts after read.
func NewPlugin(opts ...ApplyOption) gorm.Plugin {
	dst := defaultOptions()

	for _, apply := range opts {
		apply(dst)
	}

	return siloPlugin{
		opt: dst,
	}
}

func (s siloPlugin) Name() string {
	return "silo"
}

func (s siloPlugin) encrypt(content string, additionalData string) string {
	nonce, err := slosilo.RandomNonce()
	if err != nil {
		panic(err)
	}

	result, err := s.opt.keystore.Cipher().Encrypt([]byte(additionalData), []byte(content), nonce)
	if err != nil {
		panic(err)
	}

	return string(result)
}

func (s siloPlugin) decrypt(content string, additionalData string) string {
	result, err := s.opt.keystore.Cipher().Decrypt([]byte(additionalData), []byte(content))
	if err != nil {
		panic(err)
	}
	return string(result)
}

func (s siloPlugin) Initialize(db *gorm.DB) (err error) {
	db.Callback().Create().Before("gorm:create").Register("silo:before_create", s.encryptQuery)
	db.Callback().Create().After("gorm:create").Register("silo:after_create", s.decryptQuery)
	db.Callback().Update().Before("gorm:update").Register("silo:before_update", s.encryptQuery)
	db.Callback().Query().After("gorm:query").Register("silo:after_query", s.decryptQuery)

	return
}

func (s siloPlugin) encryptQuery(db *gorm.DB) {
	s.processQuery(db, s.encrypt)
}

func (s siloPlugin) decryptQuery(db *gorm.DB) {
	s.processQuery(db, s.decrypt)
}

func (s siloPlugin) processQuery(db *gorm.DB, fn processor) {
	if db.Statement.Schema != nil {
		switch db.Statement.ReflectValue.Kind() {
		case reflect.Struct:
			var destMap map[string]interface{}
			if dest, ok := db.Statement.Dest.(map[string]interface{}); ok {
				destMap = dest
			}
			s.processFields(db, db.Statement.ReflectValue, destMap, fn)
		case reflect.Slice, reflect.Array:
			var destMapList []map[string]interface{}
			if dest, ok := db.Statement.Dest.([]map[string]interface{}); ok {
				destMapList = dest
			}
			for i := 0; i < db.Statement.ReflectValue.Len(); i++ {
				var destMap map[string]interface{}
				if i < len(destMapList) {
					destMap = destMapList[i]
				}
				s.processFields(db, db.Statement.ReflectValue.Index(i), destMap, fn)
			}
		}
	}
}

// decryptFields replaces the value on a returned record with the decrypted value
func (s siloPlugin) processFields(db *gorm.DB, reflectValue reflect.Value, dataDestination map[string]interface{}, fn processor) {
	aad := getAdditionalData(db, reflectValue)
	for _, field := range db.Statement.Schema.Fields {
		if field.Tag.Get("silo") == "encrypted" {
			if fieldValue, isZero := field.ValueOf(reflectValue); !isZero {
				switch field.FieldType.Kind() {
				case reflect.String:
					// decrypted, err := s.opt.symmetric.Decrypt([]byte(aad), []byte(fieldValue.(string)))
					result := fn(fieldValue.(string), aad)
					field.Set(reflectValue, result)
					if _, ok := dataDestination[field.Name]; ok {
						dataDestination[field.Name] = result
					}
				default:
					fmt.Printf("Unsupported encrypted field datatype: %+v\n", field)
				}
			}
		}
	}
}

// getAdditionalAdata assembles the string to use as additional data when encrypting/decrypting
// data based on schema field tags
func getAdditionalData(db *gorm.DB, reflectValue reflect.Value) (result string) {
	var aadStrings []string
	for _, field := range db.Statement.Schema.Fields {
		if field.Tag.Get("silo") == "aad" {
			if fieldValue, isZero := field.ValueOf(reflectValue); !isZero {
				kind := field.FieldType.Kind()
				switch kind {
				case reflect.String:
					aadStrings = append(aadStrings, fieldValue.(string))
				default:
					fmt.Printf("Unsupported additional data field datatype: %+v\n", field)
				}
			}
		}
	}
	// Sort the strings so they have a stable order
	sort.Strings(aadStrings)
	result = strings.Join(aadStrings, "")
	return
}
