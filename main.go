package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"conjur-in-go/slosilo"
)

// NOTES
// tokenSigningPrivateKey is stored in slosilo keystore

type StoredSecret struct {
	ResourceId string
	Value      sql.RawBytes
}

func (s StoredSecret) TableName() string {
	return "secrets"
}

type StoredKey struct {
	Id          string
	Fingerprint string
	Key         sql.RawBytes
	_key        *slosilo.Key
	_account    string
}

func (s StoredKey) TableName() string {
	return "slosilo_keystore"
}

var accountKeyIdRgx = regexp.MustCompile(`^authn:([^:]*)`)

func (s StoredKey) Account() string {
	return s._account
}
func (s StoredKey) K() *slosilo.Key {
	return s._key
}

type KeyStore struct {
	db                *gorm.DB
	cipher            *slosilo.Symmetric
	keysById          map[string]*StoredKey
	keysByFingerprint map[string]*StoredKey
}

func NewKeyStore(db *gorm.DB) (*KeyStore, error) {
	cipher, err := slosilo.NewSymmetric(dataKey)
	if err != nil {
		return nil, err
	}

	return &KeyStore{
		cipher:            cipher,
		db:                db,
		keysById:          map[string]*StoredKey{},
		keysByFingerprint: map[string]*StoredKey{},
	}, nil
}

func (k KeyStore) fetchKey(query *StoredKey) (*StoredKey, error) {
	if _key, ok := k.keysByFingerprint[query.Fingerprint]; ok {
		return _key, nil
	}

	if _key, ok := k.keysById[query.Id]; ok {
		return _key, nil
	}

	var key StoredKey
	tx := k.db.Where(query).First(&key)
	err := tx.Error
	if err != nil {
		return nil, err
	}

	decryptedKey, err := k.cipher.Decrypt([]byte(key.Id), key.Key)
	if err != nil {
		return nil, err
	}

	_key, err := slosilo.NewKey(decryptedKey)
	if err != nil {
		return nil, err
	}
	key._key = _key
	accountKeyIdMatches := accountKeyIdRgx.FindStringSubmatch(key.Id)
	if len(accountKeyIdMatches) < 1 {
		return nil, errors.New("key has malformed id")
	}
	key._account = accountKeyIdMatches[1]

	k.keysById[key.Id] = &key
	k.keysByFingerprint[key.Fingerprint] = &key

	return &key, nil
}

func (k KeyStore) ByFingerprint(fingerprint string) (*StoredKey, error) {
	return k.fetchKey(&StoredKey{Fingerprint: fingerprint})
}

func (k KeyStore) ByAccount(account string) (*StoredKey, error) {
	return k.fetchKey(&StoredKey{Id: "authn:"+account})
}

func FetchSecret(db *gorm.DB, secretId string) (*StoredSecret, error) {
	var secret StoredSecret
	tx := db.Where(&StoredSecret{ResourceId: secretId}).First(&secret)
	err := tx.Error
	if err != nil {
		return nil, err
	}

	return &secret, nil
}

func isRoleAllowedTo(db *gorm.DB, roleId, privilege, resourceId string) bool {
	var permitted bool
	db.Raw(`SELECT is_role_allowed_to(?, ?, ?)`, roleId, privilege, resourceId).Scan(&permitted)
	return permitted
}

type JWTAuthenticator struct {
	keystore *KeyStore
}

var tokenRegex = regexp.MustCompile(`^Token token="(.*)"`)

func roleId(account string, login string) string {
	tokens := strings.Split(login, "/")
	if len(tokens) == 1 {
		tokens = []string{"user", login}
	}

	return strings.Join(
		[]string{
			account, tokens[0], strings.Join(tokens[1:],"/"),
		},
		":",
	)
}

func (j JWTAuthenticator) Instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if len(authHeader) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Authorization missing"))
			return
		}

		tokenMatches := tokenRegex.FindStringSubmatch(authHeader)
		if len(tokenMatches) < 1 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Malformed authorization header"))
			return
		}

		tokenStr, err := base64.URLEncoding.DecodeString(tokenMatches[1])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Malformed authorization token"))
			return
		}

		authToken, err := slosilo.NewParsedToken(tokenStr)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Malformed authorization token"))
			return
		}

		if authToken.Expired() {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Token expired"))
			return
		}

		account, verified := authToken.Verify(func(kid string, protected, payload, signature []byte) (string, bool) {
			stringToSign := strings.Join(
				[]string{
					base64.URLEncoding.EncodeToString(protected),
					base64.URLEncoding.EncodeToString(payload),
				},
				".",
			)

			key, err := j.keystore.ByFingerprint(kid)
			if err != nil {
				return "", false
			}
			err = key.K().Verify([]byte(stringToSign), signature)
			if err != nil {
				return "", false
			}

			return key.Account(), true
		})

		if !verified {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Invalid signature"))
			return
		}

		roleId := roleId(account, authToken.Sub())
		ctx := r.Context()
		ctx = context.WithValue(ctx, "roleId", roleId)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

const acceptEncoding string = "Accept-Encoding"

func main() {
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  "host=localhost user=postgres dbname=postgres",
		PreferSimpleProtocol: true, // disables implicit prepared statement usage
	}), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	keystore, err := NewKeyStore(db)
	if err != nil {
		panic(err)
	}

	r := mux.NewRouter().UseEncodedPath()
	jwtMiddleware := &JWTAuthenticator{
		keystore: keystore,
	}

	secretsRouter := r.PathPrefix("/secrets").Subrouter()
	secretsRouter.Use(jwtMiddleware.Instrument)
	secretsRouter.HandleFunc(
		"/{account}/{kind}/{identifier}",
		func(writer http.ResponseWriter, request *http.Request) {
			vars := mux.Vars(request)
			account := vars["account"]
			kind := vars["kind"]
			identifier, err := url.PathUnescape(vars["identifier"])
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			secretId := fmt.Sprintf("%s:%s:%s", account, kind, identifier)

			// Comes from auth
			roleId := request.Context().Value("roleId").(string)

			allowed := isRoleAllowedTo(
				db,
				roleId,
				"execute",
				secretId,
			)
			if !allowed {
				http.Error(writer, "Role does not have execute permissions on secret", http.StatusForbidden)
				return
			}

			// TODO: There's definitely a better model abstraction here
			secret, err := FetchSecret(db, secretId)
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					http.Error(writer, err.Error(), http.StatusNotFound)
				}

				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}
			secretValue, err := keystore.cipher.Decrypt([]byte(secret.ResourceId), secret.Value)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}

			writer.Write(secretValue)
		},
	).Methods("GET")

	r.HandleFunc(
		"/authn/{account}/{login}/authenticate",
		func(writer http.ResponseWriter, request *http.Request) {
			// TODO: check if api key matches against DB

			vars := mux.Vars(request)
			account := vars["account"]
			login, err := url.PathUnescape(vars["login"])
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			// Detect what encoding to use
			var base64Encoding bool
			for _, curEnc := range strings.Split(request.Header.Get(acceptEncoding), ",") {
				curEnc = strings.TrimSpace(curEnc)
				if curEnc == "base64" {
					base64Encoding = true
					break
				}
			}

			newclaimsMap := map[string]interface{}{
				"iat": time.Now().Unix(),
				"sub": login,
			}
			key, err := keystore.ByAccount(account)
			if err != nil {
				http.Error(writer, fmt.Sprintf("Error on key by account: %s", err.Error()), http.StatusBadRequest)
				return
			}

			newheaderMap := map[string]interface{}{
				"alg": "conjur.org/slosilo/v2",
				"kid": key.Fingerprint,
			}

			newheader := toJson(newheaderMap)
			newclaims := toJson(newclaimsMap)

			newsalt, _ := slosilo.RandomBytes(32)
			stringToSign := strings.Join(
				[]string{
					base64.URLEncoding.EncodeToString([]byte(newheader)),
					base64.URLEncoding.EncodeToString([]byte(newclaims)),
				},
				".",
			)

			// TODO: this needs to be more sophisticated
			//  Conjur in ruby forces the thing being signed to be encoded in ASCII-8BIT
			//  https://github.com/cyberark/slosilo/blob/master/lib/slosilo/key.rb#L198-L202
			newsignature, err := key.K().Sign(
				[]byte(
					stringToSign,
				),
				newsalt,
			)
			newjwt := map[string]string{
				"protected": base64.URLEncoding.EncodeToString([]byte(newheader)),
				"payload": base64.URLEncoding.EncodeToString([]byte(newclaims)),
				"signature": base64.URLEncoding.EncodeToString(newsignature),
			}

			newjwtJSON := []byte(toJson(newjwt))

			if base64Encoding {
				writer.Header().Add("Content-Encoding", "base64")
				base64.NewEncoder(base64.StdEncoding.Strict(), writer).Write(newjwtJSON)
				return
			}

			writer.Header().Add("Content-Type", "application/json")
			writer.Write(newjwtJSON)
		},
	).Methods("POST")

	srv := &http.Server{
		Handler: handlers.LoggingHandler(os.Stdout, r),
		Addr:    "127.0.0.1:8000",
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("Running server...")
	log.Fatal(srv.ListenAndServe())
}


func toJson(input interface{}) string {
	output, _ := json.Marshal(input)
	return string(output)
}
