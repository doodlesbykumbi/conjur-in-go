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
	"gorm.io/gorm"

	"conjur-in-go/pkg/audit"
	"conjur-in-go/pkg/model"
	"conjur-in-go/pkg/server"
	"conjur-in-go/pkg/server/middleware"
)

func fetchSecret(db *gorm.DB, resourceId string, secretVersion string) (*model.Secret, error) {
	var secret model.Secret
	query := map[string]interface{}{"resource_id": resourceId}
	if secretVersion != "" {
		query["version"] = secretVersion
	}

	tx := db.Order("version desc").Where(query).First(&secret)
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

func RegisterSecretsEndpoints(server *server.Server) {
	keystore := server.Keystore
	router := server.Router
	db := server.DB

	// TODO: this isn't right. The middleware should be available everywhere for consumption by multiple routes
	jwtMiddleware := middleware.NewJWTAuthenticator(keystore)

	secretsRouter := router.PathPrefix("/secrets").Subrouter()
	secretsRouter.Use(jwtMiddleware.Middleware)

	// GET /secrets?variable_ids=... - Batch fetch secrets
	secretsRouter.HandleFunc(
		"",
		func(writer http.ResponseWriter, request *http.Request) {
			variableIdsParam := request.URL.Query().Get("variable_ids")
			if variableIdsParam == "" {
				http.Error(writer, "variable_ids parameter required", http.StatusBadRequest)
				return
			}

			// Parse comma-separated variable IDs
			variableIds := strings.Split(variableIdsParam, ",")

			// Get role from auth context
			tokenInfo, _ := middleware.GetTokenInfo(request.Context())
			roleId := tokenInfo.RoleID

			// Check if base64 encoding is requested
			useBase64 := strings.EqualFold(request.Header.Get("Accept-Encoding"), "base64")

			// Fetch each secret
			results := make(map[string]string)
			for _, varId := range variableIds {
				varId = strings.TrimSpace(varId)
				if varId == "" {
					continue
				}

				// Check permission
				if !isRoleAllowedTo(db, roleId, "execute", varId) {
					// Return 403 for unauthorized access
					respondWithError(writer, http.StatusForbidden, map[string]string{
						"error": fmt.Sprintf("Forbidden: role does not have execute permission on %s", varId),
					})
					return
				}

				// Fetch the secret
				secret, err := fetchSecret(db, varId, "")
				if err != nil {
					if errors.Is(err, gorm.ErrRecordNotFound) {
						respondWithError(writer, http.StatusNotFound, map[string]string{
							"error": fmt.Sprintf("Variable %s has no secret value", varId),
						})
						return
					}
					http.Error(writer, err.Error(), http.StatusInternalServerError)
					return
				}

				value := string(secret.Value)
				if useBase64 {
					value = base64.StdEncoding.EncodeToString(secret.Value)
				}
				results[varId] = value
			}

			if useBase64 {
				writer.Header().Set("Content-Encoding", "base64")
			}
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(results)
		},
	).Methods("GET").Queries("variable_ids", "{variable_ids}")

	// GET /secrets/{account}/{kind}/{identifier} - Fetch single secret
	secretsRouter.HandleFunc(
		"/{account}/{kind}/{identifier:.+}", // For 'identifier' we grab the rest of the URL including slashes
		func(writer http.ResponseWriter, request *http.Request) {
			secretVersion := request.URL.Query().Get("version")

			vars := mux.Vars(request)
			account := vars["account"]
			kind := vars["kind"]
			identifier, err := url.PathUnescape(vars["identifier"])
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			// TODO: use a "service" object to serve the endpoint
			//  getSecret(roleId, resourceId) ?

			resourceId := fmt.Sprintf("%s:%s:%s", account, kind, identifier)

			// Comes from auth
			tokenInfo, _ := middleware.GetTokenInfo(request.Context())
			roleId := tokenInfo.RoleID
			clientIP := request.RemoteAddr
			if forwarded := request.Header.Get("X-Forwarded-For"); forwarded != "" {
				clientIP = forwarded
			}

			allowed := isRoleAllowedTo(
				db,
				roleId,
				"execute",
				resourceId,
			)
			if !allowed {
				audit.Log(audit.FetchEvent{
					UserID:       roleId,
					ClientIP:     clientIP,
					ResourceID:   resourceId,
					Version:      secretVersion,
					Success:      false,
					ErrorMessage: "permission denied",
				})
				http.Error(writer, "role does not have execute permissions on secret", http.StatusForbidden)
				return
			}

			// TODO: There's definitely a better model abstraction here
			secret, err := fetchSecret(db, resourceId, secretVersion)
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					audit.Log(audit.FetchEvent{
						UserID:       roleId,
						ClientIP:     clientIP,
						ResourceID:   resourceId,
						Version:      secretVersion,
						Success:      false,
						ErrorMessage: "secret not found",
					})
					respondWithError(writer, http.StatusNotFound, map[string]string{"message": "secret is empty or not found."})
					return
				}

				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}

			audit.Log(audit.FetchEvent{
				UserID:     roleId,
				ClientIP:   clientIP,
				ResourceID: resourceId,
				Version:    secretVersion,
				Success:    true,
			})
			_, _ = writer.Write(secret.Value)
		},
	).Methods("GET")

	secretsRouter.HandleFunc(
		"/{account}/{kind}/{identifier:.+}", // For 'identifier' we grab the rest of the URL including slashes
		func(writer http.ResponseWriter, request *http.Request) {
			newSecretValue, err := io.ReadAll(request.Body)
			defer func() { _ = request.Body.Close() }()
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			vars := mux.Vars(request)
			account := vars["account"]
			kind := vars["kind"]
			identifier, err := url.PathUnescape(vars["identifier"])
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			resourceId := fmt.Sprintf("%s:%s:%s", account, kind, identifier)

			// Comes from auth
			tokenInfo, _ := middleware.GetTokenInfo(request.Context())
			roleId := tokenInfo.RoleID
			clientIP := request.RemoteAddr
			if forwarded := request.Header.Get("X-Forwarded-For"); forwarded != "" {
				clientIP = forwarded
			}

			// TODO: turn this into "#authorize(action)" utility function
			allowed := isRoleAllowedTo(
				db,
				roleId,
				"update",
				resourceId,
			)
			if !allowed {
				audit.Log(audit.UpdateEvent{
					UserID:       roleId,
					ClientIP:     clientIP,
					ResourceID:   resourceId,
					Success:      false,
					ErrorMessage: "permission denied",
				})
				http.Error(writer, "role does not have update permissions on secret", http.StatusForbidden)
				return
			}

			// TODO: There's definitely a better model abstraction here
			tx := db.Create(&model.Secret{
				ResourceId: resourceId,
				Value:      newSecretValue,
			})
			err = tx.Error
			if err != nil {
				audit.Log(audit.UpdateEvent{
					UserID:       roleId,
					ClientIP:     clientIP,
					ResourceID:   resourceId,
					Success:      false,
					ErrorMessage: err.Error(),
				})
				respondWithError(writer, http.StatusInternalServerError, map[string]string{"message": err.Error()})
				return
			}

			audit.Log(audit.UpdateEvent{
				UserID:     roleId,
				ClientIP:   clientIP,
				ResourceID: resourceId,
				Success:    true,
			})
			writer.WriteHeader(http.StatusCreated)
		},
	).Methods("POST")

	// POST /secrets/{account}/values - Batch update secrets
	secretsRouter.HandleFunc(
		"/{account}/values",
		handleBatchUpdateSecrets(db),
	).Methods("POST")
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

func handleBatchUpdateSecrets(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]

		// Get role from auth context
		tokenInfo, _ := middleware.GetTokenInfo(r.Context())
		roleId := tokenInfo.RoleID
		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		// Parse request body
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

		// Process each secret
		for varId, value := range req.Secrets {
			// Build full resource ID if not already qualified
			resourceId := varId
			if !strings.Contains(varId, ":") {
				resourceId = account + ":variable:" + varId
			}

			// Check permission
			if !isRoleAllowedTo(db, roleId, "update", resourceId) {
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

			// Update the secret
			err := db.Create(&model.Secret{
				ResourceId: resourceId,
				Value:      []byte(value),
			}).Error

			if err != nil {
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

		// Return 207 Multi-Status if there were any errors, 201 if all succeeded
		statusCode := http.StatusCreated
		if len(response.Errors) > 0 {
			statusCode = http.StatusMultiStatus
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(response)
	}
}
