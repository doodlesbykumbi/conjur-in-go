package endpoints

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/audit"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/identity"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
)

func RegisterSecretsEndpoints(s *server.Server) {
	router := s.Router
	secretsStore := s.SecretsStore
	authzStore := s.AuthzStore

	secretsRouter := router.PathPrefix("/secrets").Subrouter()
	secretsRouter.Use(s.JWTMiddleware.Middleware)

	// GET /secrets?variable_ids=... - Batch fetch secrets
	secretsRouter.HandleFunc("", handleBatchFetchSecrets(secretsStore, authzStore)).Methods("GET").Queries("variable_ids", "{variable_ids}")

	// GET /secrets/{account}/{kind}/{identifier} - Fetch single secret
	secretsRouter.HandleFunc(
		"/{account}/{kind}/{identifier:.+}",
		handleFetchSecret(secretsStore, authzStore),
	).Methods("GET")

	// POST /secrets/{account}/{kind}/{identifier}?expirations - Expire a secret
	secretsRouter.HandleFunc(
		"/{account}/{kind}/{identifier:.+}",
		handleExpireSecret(secretsStore, authzStore),
	).Methods("POST").Queries("expirations", "")

	// POST /secrets/{account}/{kind}/{identifier} - Create/update a secret value
	secretsRouter.HandleFunc(
		"/{account}/{kind}/{identifier:.+}",
		handleCreateSecret(secretsStore, authzStore),
	).Methods("POST")

	// POST /secrets/{account}/values - Batch update secrets
	secretsRouter.HandleFunc(
		"/{account}/values",
		handleBatchUpdateSecrets(secretsStore, authzStore),
	).Methods("POST")
}

func handleBatchFetchSecrets(secretsStore store.SecretsStore, authzStore store.AuthzStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		variableIdsParam := r.URL.Query().Get("variable_ids")
		if variableIdsParam == "" {
			http.Error(w, "variable_ids parameter required", http.StatusBadRequest)
			return
		}

		variableIds := strings.Split(variableIdsParam, ",")

		id, _ := identity.Get(r.Context())
		roleId := id.RoleID

		useBase64 := strings.EqualFold(r.Header.Get("Accept-Encoding"), "base64")

		results := make(map[string]string)
		for _, varId := range variableIds {
			varId = strings.TrimSpace(varId)
			if varId == "" {
				continue
			}

			if !authzStore.IsRoleAllowedTo(roleId, "execute", varId) {
				respondWithError(w, http.StatusForbidden, map[string]string{
					"error": fmt.Sprintf("Forbidden: role does not have execute permission on %s", varId),
				})
				return
			}

			secret, err := secretsStore.FetchSecret(varId, "")
			if err != nil {
				if errors.Is(err, store.ErrSecretNotFound) {
					respondWithError(w, http.StatusNotFound, map[string]string{
						"error": fmt.Sprintf("Variable %s has no secret value", varId),
					})
					return
				}
				if errors.Is(err, store.ErrSecretExpired) {
					respondWithError(w, http.StatusNotFound, map[string]string{
						"error": fmt.Sprintf("Variable %s has expired", varId),
					})
					return
				}
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			value := string(secret.Value)
			if useBase64 {
				value = base64.StdEncoding.EncodeToString(secret.Value)
			}
			results[varId] = value
		}

		if useBase64 {
			w.Header().Set("Content-Encoding", "base64")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(results)
	}
}

func handleFetchSecret(secretsStore store.SecretsStore, authzStore store.AuthzStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secretVersion := r.URL.Query().Get("version")

		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, err := url.PathUnescape(vars["identifier"])
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resourceId := fmt.Sprintf("%s:%s:%s", account, kind, identifier)

		id, _ := identity.Get(r.Context())
		roleId := id.RoleID
		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		if !authzStore.IsRoleAllowedTo(roleId, "execute", resourceId) {
			audit.Log(audit.FetchEvent{
				UserID:       roleId,
				ClientIP:     clientIP,
				ResourceID:   resourceId,
				Version:      secretVersion,
				Success:      false,
				ErrorMessage: "permission denied",
			})
			http.Error(w, "role does not have execute permissions on secret", http.StatusForbidden)
			return
		}

		secret, err := secretsStore.FetchSecret(resourceId, secretVersion)
		if err != nil {
			if errors.Is(err, store.ErrSecretNotFound) {
				audit.Log(audit.FetchEvent{
					UserID:       roleId,
					ClientIP:     clientIP,
					ResourceID:   resourceId,
					Version:      secretVersion,
					Success:      false,
					ErrorMessage: "secret not found",
				})
				respondWithError(w, http.StatusNotFound, map[string]string{"message": "secret is empty or not found."})
				return
			}
			if errors.Is(err, store.ErrSecretExpired) {
				audit.Log(audit.FetchEvent{
					UserID:       roleId,
					ClientIP:     clientIP,
					ResourceID:   resourceId,
					Version:      secretVersion,
					Success:      false,
					ErrorMessage: "secret has expired",
				})
				respondWithError(w, http.StatusNotFound, map[string]string{"message": "secret has expired"})
				return
			}

			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		audit.Log(audit.FetchEvent{
			UserID:     roleId,
			ClientIP:   clientIP,
			ResourceID: resourceId,
			Version:    secretVersion,
			Success:    true,
		})
		_, _ = w.Write(secret.Value)
	}
}

func handleExpireSecret(secretsStore store.SecretsStore, authzStore store.AuthzStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, err := url.PathUnescape(vars["identifier"])
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if kind != "variable" {
			respondWithError(w, http.StatusUnprocessableEntity, map[string]string{
				"error": fmt.Sprintf("Invalid secret kind: %s", kind),
			})
			return
		}

		resourceId := fmt.Sprintf("%s:%s:%s", account, kind, identifier)

		id, _ := identity.Get(r.Context())
		roleId := id.RoleID

		if !authzStore.IsRoleAllowedTo(roleId, "update", resourceId) {
			http.Error(w, "role does not have update permissions on secret", http.StatusForbidden)
			return
		}

		if err := secretsStore.ExpireSecret(resourceId); err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
			return
		}

		w.WriteHeader(http.StatusCreated)
	}
}

func handleCreateSecret(secretsStore store.SecretsStore, authzStore store.AuthzStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		newSecretValue, err := io.ReadAll(r.Body)
		defer func() { _ = r.Body.Close() }()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, err := url.PathUnescape(vars["identifier"])
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resourceId := fmt.Sprintf("%s:%s:%s", account, kind, identifier)

		id, _ := identity.Get(r.Context())
		roleId := id.RoleID
		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		if !authzStore.IsRoleAllowedTo(roleId, "update", resourceId) {
			audit.Log(audit.UpdateEvent{
				UserID:       roleId,
				ClientIP:     clientIP,
				ResourceID:   resourceId,
				Success:      false,
				ErrorMessage: "permission denied",
			})
			http.Error(w, "role does not have update permissions on secret", http.StatusForbidden)
			return
		}

		if err := secretsStore.CreateSecret(resourceId, newSecretValue); err != nil {
			audit.Log(audit.UpdateEvent{
				UserID:       roleId,
				ClientIP:     clientIP,
				ResourceID:   resourceId,
				Success:      false,
				ErrorMessage: err.Error(),
			})
			respondWithError(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
			return
		}

		audit.Log(audit.UpdateEvent{
			UserID:     roleId,
			ClientIP:   clientIP,
			ResourceID: resourceId,
			Success:    true,
		})
		w.WriteHeader(http.StatusCreated)
	}
}

// BatchSecretRequest represents a request to update multiple secrets
type BatchSecretRequest struct {
	Secrets map[string]string `json:"secrets"`
}

// BatchSecretResponse represents the response from batch secret update
type BatchSecretResponse struct {
	Updated []string          `json:"updated"`
	Errors  map[string]string `json:"errors,omitempty"`
}

func handleBatchUpdateSecrets(secretsStore store.SecretsStore, authzStore store.AuthzStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]

		id, _ := identity.Get(r.Context())
		roleId := id.RoleID
		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		var req BatchSecretRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondWithError(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body"})
			return
		}
		defer func() { _ = r.Body.Close() }()

		if len(req.Secrets) == 0 {
			respondWithError(w, http.StatusBadRequest, map[string]string{"error": "No secrets provided"})
			return
		}

		response := BatchSecretResponse{
			Updated: make([]string, 0),
			Errors:  make(map[string]string),
		}

		for varId, value := range req.Secrets {
			resourceId := varId
			if !strings.Contains(varId, ":") {
				resourceId = account + ":variable:" + varId
			}

			if !authzStore.IsRoleAllowedTo(roleId, "update", resourceId) {
				response.Errors[varId] = "permission denied"
				audit.Log(audit.UpdateEvent{
					UserID:       roleId,
					ClientIP:     clientIP,
					ResourceID:   resourceId,
					Success:      false,
					ErrorMessage: "permission denied",
				})
				continue
			}

			if err := secretsStore.CreateSecret(resourceId, []byte(value)); err != nil {
				response.Errors[varId] = err.Error()
				audit.Log(audit.UpdateEvent{
					UserID:       roleId,
					ClientIP:     clientIP,
					ResourceID:   resourceId,
					Success:      false,
					ErrorMessage: err.Error(),
				})
			} else {
				response.Updated = append(response.Updated, varId)
				audit.Log(audit.UpdateEvent{
					UserID:     roleId,
					ClientIP:   clientIP,
					ResourceID: resourceId,
					Success:    true,
				})
			}
		}

		statusCode := http.StatusCreated
		if len(response.Errors) > 0 {
			statusCode = http.StatusMultiStatus
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(response)
	}
}
