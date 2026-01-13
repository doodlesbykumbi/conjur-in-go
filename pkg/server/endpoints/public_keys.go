package endpoints

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/gorilla/mux"
	"gorm.io/gorm"

	"conjur-in-go/pkg/server"
	"conjur-in-go/pkg/server/middleware"
	"conjur-in-go/pkg/slosilo"
)

// RegisterPublicKeysEndpoints registers the public keys API endpoints
func RegisterPublicKeysEndpoints(s *server.Server) {
	db := s.DB
	cipher := s.Cipher

	jwtMiddleware := middleware.NewJWTAuthenticator(s.Keystore)

	publicKeysRouter := s.Router.PathPrefix("/public_keys").Subrouter()
	publicKeysRouter.Use(jwtMiddleware.Middleware)

	// GET /public_keys/{account}/{kind}/{identifier} - Get public keys for a user/host
	publicKeysRouter.HandleFunc("/{account}/{kind}/{identifier:.+}", handleGetPublicKeys(db, cipher)).Methods("GET")
}

func handleGetPublicKeys(db *gorm.DB, cipher slosilo.SymmetricCipher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])

		// Public keys are stored as variables with identifier pattern: public_key/{kind}/{identifier}/{key_name}
		// The resource_id pattern is: {account}:variable:public_key/{kind}/{identifier}/%
		pattern := account + ":variable:public_key/" + kind + "/" + identifier + "/%"

		// Query for latest version of each public key
		type keyRow struct {
			ResourceID string `gorm:"column:resource_id"`
			Value      []byte
		}
		var rows []keyRow

		// Get the latest version of each public key matching the pattern
		db.Raw(`
			WITH max_versions AS (
				SELECT resource_id, MAX(version) as version
				FROM secrets
				WHERE resource_id LIKE ?
				GROUP BY resource_id
			)
			SELECT s.resource_id, s.value
			FROM secrets s
			JOIN max_versions mv ON s.resource_id = mv.resource_id AND s.version = mv.version
			ORDER BY s.resource_id
		`, pattern).Scan(&rows)

		// Collect and sort the keys (decrypt each value)
		keys := make([]string, 0, len(rows))
		for _, row := range rows {
			// Decrypt the value using the resource_id as AAD
			decrypted, err := cipher.Decrypt([]byte(row.ResourceID), row.Value)
			if err != nil {
				// Skip keys that can't be decrypted
				continue
			}
			key := strings.TrimSpace(string(decrypted))
			if key != "" {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)

		// Return as plain text, one key per line
		result := strings.Join(keys, "\n")
		if len(keys) > 0 {
			result += "\n"
		}

		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(result))
	}
}
