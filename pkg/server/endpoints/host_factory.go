package endpoints

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"gorm.io/gorm"

	"conjur-in-go/pkg/model"
	"conjur-in-go/pkg/server"
	"conjur-in-go/pkg/server/middleware"
	"conjur-in-go/pkg/slosilo"
)

// RegisterHostFactoryEndpoints registers the host factory API endpoints
func RegisterHostFactoryEndpoints(s *server.Server) {
	db := s.DB
	cipher := s.Cipher

	jwtMiddleware := middleware.NewJWTAuthenticator(s.Keystore)

	// POST /host_factory_tokens - Create token(s) (requires JWT auth)
	tokensRouter := s.Router.PathPrefix("/host_factory_tokens").Subrouter()
	tokensRouter.Use(jwtMiddleware.Middleware)

	tokensRouter.HandleFunc("", handleCreateToken(db, cipher)).Methods("POST")
	tokensRouter.HandleFunc("/{token}", handleDeleteToken(db)).Methods("DELETE")

	// POST /host_factories/hosts - Create host using HF token (uses token auth, not JWT)
	s.Router.HandleFunc("/host_factories/hosts", handleCreateHost(db, cipher, s)).Methods("POST")
}

// handleCreateToken creates one or more host factory tokens
func handleCreateToken(db *gorm.DB, cipher slosilo.SymmetricCipher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse request body
		var req struct {
			HostFactory string   `json:"host_factory"`
			Expiration  string   `json:"expiration"`
			Count       int      `json:"count"`
			CIDR        []string `json:"cidr"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// Try form values
			req.HostFactory = r.FormValue("host_factory")
			req.Expiration = r.FormValue("expiration")
			if countStr := r.FormValue("count"); countStr != "" {
				req.Count, _ = strconv.Atoi(countStr)
			}
			if cidrStr := r.FormValue("cidr"); cidrStr != "" {
				req.CIDR = strings.Split(cidrStr, ",")
			}
		}

		if req.HostFactory == "" {
			respondWithError(w, http.StatusBadRequest, map[string]string{"error": "host_factory parameter required"})
			return
		}

		if req.Expiration == "" {
			respondWithError(w, http.StatusBadRequest, map[string]string{"error": "expiration parameter required"})
			return
		}

		// Parse expiration
		expiration, err := time.Parse(time.RFC3339, req.Expiration)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, map[string]string{"error": "Invalid expiration format, use ISO8601"})
			return
		}

		if expiration.Before(time.Now()) {
			respondWithError(w, http.StatusBadRequest, map[string]string{"error": "Expiration must be in the future"})
			return
		}

		// Default count to 1
		count := req.Count
		if count <= 0 {
			count = 1
		}

		// Get role from auth context
		roleId := r.Context().Value("roleId").(string)

		// Check if user has execute permission on the host factory
		if !isRoleAllowedTo(db, roleId, "execute", req.HostFactory) {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		// Verify the resource is a host_factory
		var resourceKind string
		db.Raw(`SELECT kind(resource_id) FROM resources WHERE resource_id = ?`, req.HostFactory).Scan(&resourceKind)
		if resourceKind != "host_factory" {
			respondWithError(w, http.StatusBadRequest, map[string]string{"error": "Invalid resource kind, must be host_factory"})
			return
		}

		// Format CIDR for PostgreSQL array
		cidrArray := "{}"
		if len(req.CIDR) > 0 {
			cidrArray = "{" + strings.Join(req.CIDR, ",") + "}"
		}

		// Create tokens
		tokens := make([]model.HostFactoryTokenResponse, 0, count)
		for i := 0; i < count; i++ {
			plainToken := model.GenerateToken()
			tokenHash := model.HashToken(plainToken)

			// Encrypt the token for storage (use token hash as AAD)
			encryptedToken, err := cipher.Encrypt([]byte(tokenHash), []byte(plainToken))
			if err != nil {
				respondWithError(w, http.StatusInternalServerError, map[string]string{"error": "Failed to encrypt token"})
				return
			}

			hfToken := model.HostFactoryToken{
				TokenSHA256: tokenHash,
				Token:       encryptedToken,
				ResourceID:  req.HostFactory,
				CIDR:        cidrArray,
				Expiration:  expiration,
				PlainToken:  plainToken,
			}

			if err := db.Create(&hfToken).Error; err != nil {
				respondWithError(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create token"})
				return
			}

			tokens = append(tokens, hfToken.ToResponse())
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(tokens)
	}
}

// handleDeleteToken revokes a host factory token
func handleDeleteToken(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		token := vars["token"]

		// Find the token by hash
		tokenHash := model.HashToken(token)

		var hfToken model.HostFactoryToken
		if err := db.Where("token_sha256 = ?", tokenHash).First(&hfToken).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				respondWithError(w, http.StatusNotFound, map[string]string{"error": "Token not found"})
				return
			}
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		// Get role from auth context
		roleId := r.Context().Value("roleId").(string)

		// Check if user has update permission on the host factory
		if !isRoleAllowedTo(db, roleId, "update", hfToken.ResourceID) {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		// Delete the token
		if err := db.Delete(&hfToken).Error; err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// handleCreateHost creates a host using a host factory token
func handleCreateHost(db *gorm.DB, cipher slosilo.SymmetricCipher, srv *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondWithError(w, http.StatusUnauthorized, map[string]string{"error": "Authorization required"})
			return
		}

		// Parse Token token="..."
		var token string
		if strings.HasPrefix(authHeader, "Token token=\"") && strings.HasSuffix(authHeader, "\"") {
			token = authHeader[13 : len(authHeader)-1]
		} else {
			respondWithError(w, http.StatusUnauthorized, map[string]string{"error": "Invalid authorization format"})
			return
		}

		// Find the token
		tokenHash := model.HashToken(token)
		var hfToken model.HostFactoryToken
		if err := db.Where("token_sha256 = ?", tokenHash).First(&hfToken).Error; err != nil {
			respondWithError(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
			return
		}

		// Decrypt and verify token
		decryptedToken, err := cipher.Decrypt([]byte(hfToken.TokenSHA256), hfToken.Token)
		if err != nil || string(decryptedToken) != token {
			respondWithError(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
			return
		}

		// Validate token (expiration and CIDR)
		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		if !hfToken.IsValid(clientIP) {
			respondWithError(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
			return
		}

		// Parse request body
		var req struct {
			ID          string            `json:"id"`
			Annotations map[string]string `json:"annotations"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// Try form values
			req.ID = r.FormValue("id")
		}

		if req.ID == "" {
			respondWithError(w, http.StatusBadRequest, map[string]string{"error": "id parameter required"})
			return
		}

		// Get the host factory resource to determine account
		var hostFactoryResource struct {
			ResourceID string
			OwnerID    string
		}
		db.Raw(`SELECT resource_id, owner_id FROM resources WHERE resource_id = ?`, hfToken.ResourceID).Scan(&hostFactoryResource)

		// Extract account from host factory resource ID
		parts := strings.SplitN(hfToken.ResourceID, ":", 3)
		if len(parts) < 3 {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": "Invalid host factory resource ID"})
			return
		}
		account := parts[0]

		// Create the host role and resource
		hostRoleID := fmt.Sprintf("%s:host:%s", account, req.ID)
		hostResourceID := hostRoleID

		// Check if host already exists
		var exists bool
		db.Raw(`SELECT EXISTS(SELECT 1 FROM roles WHERE role_id = ?)`, hostRoleID).Scan(&exists)
		if exists {
			respondWithError(w, http.StatusConflict, map[string]string{"error": "Host already exists"})
			return
		}

		// Generate API key for the host
		apiKeyBytes, err := model.GenerateAPIKey()
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": "Failed to generate API key"})
			return
		}
		apiKey := string(apiKeyBytes)

		// Encrypt the API key (use role ID as AAD)
		encryptedAPIKey, err := cipher.Encrypt([]byte(hostRoleID), []byte(apiKey))
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": "Failed to encrypt API key"})
			return
		}

		// Create role
		if err := db.Exec(`INSERT INTO roles (role_id, created_at) VALUES (?, NOW())`, hostRoleID).Error; err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create host role"})
			return
		}

		// Create resource
		if err := db.Exec(`INSERT INTO resources (resource_id, owner_id, created_at) VALUES (?, ?, NOW())`,
			hostResourceID, hostFactoryResource.OwnerID).Error; err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create host resource"})
			return
		}

		// Create credential
		if err := db.Exec(`INSERT INTO credentials (role_id, api_key, encrypted_hash) VALUES (?, ?, ?)`,
			hostRoleID, encryptedAPIKey, encryptedAPIKey).Error; err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create host credential"})
			return
		}

		// Add host to layers associated with the host factory
		var layers []string
		db.Raw(`
			SELECT rm.member_id FROM role_memberships rm
			WHERE rm.role_id = ? AND rm.member_id LIKE ?
		`, hfToken.ResourceID, account+":%:layer:%").Pluck("member_id", &layers)

		for _, layerID := range layers {
			db.Exec(`INSERT INTO role_memberships (role_id, member_id, admin_option, ownership) VALUES (?, ?, false, false)
				ON CONFLICT DO NOTHING`, layerID, hostRoleID)
		}

		// Create annotations if provided
		for name, value := range req.Annotations {
			db.Exec(`INSERT INTO annotations (resource_id, name, value) VALUES (?, ?, ?)`,
				hostResourceID, name, value)
		}

		// Return response
		response := map[string]interface{}{
			"id":         hostResourceID,
			"owner":      hostFactoryResource.OwnerID,
			"created_at": time.Now().UTC().Format(time.RFC3339),
			"api_key":    apiKey,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	}
}
