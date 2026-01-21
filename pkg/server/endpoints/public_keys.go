package endpoints

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/gorilla/mux"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/server"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
)

// RegisterPublicKeysEndpoints registers the public keys API endpoints
func RegisterPublicKeysEndpoints(s *server.Server) {
	publicKeysRouter := s.Router.PathPrefix("/public_keys").Subrouter()
	publicKeysRouter.Use(s.JWTMiddleware.Middleware)

	// GET /public_keys/{account}/{kind}/{identifier} - Get public keys for a user/host
	publicKeysRouter.HandleFunc("/{account}/{kind}/{identifier:.+}", handleGetPublicKeys(s.SecretsStore)).Methods("GET")
}

func handleGetPublicKeys(secretsStore store.SecretsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])

		// Public keys are stored as variables with identifier pattern: public_key/{kind}/{identifier}/{key_name}
		// The resource_id prefix is: {account}:variable:public_key/{kind}/{identifier}/
		prefix := account + ":variable:public_key/" + kind + "/" + identifier + "/"

		// Get the latest version of each public key matching the prefix
		secrets, err := secretsStore.FetchSecretsWithPrefix(prefix)
		if err != nil {
			// Return empty on error
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(""))
			return
		}

		// Collect and sort the keys (values are already decrypted by the store)
		keys := make([]string, 0, len(secrets))
		for _, secret := range secrets {
			key := strings.TrimSpace(string(secret.Value))
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
