package endpoints

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/identity"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/model"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
)

// RegisterHostFactoryEndpoints registers the host factory API endpoints
func RegisterHostFactoryEndpoints(s *server.Server) {
	hfStore := s.HostFactoryStore
	authzStore := s.AuthzStore

	// POST /host_factory_tokens - Create token(s) (requires JWT auth)
	tokensRouter := s.Router.PathPrefix("/host_factory_tokens").Subrouter()
	tokensRouter.Use(s.JWTMiddleware.Middleware)

	tokensRouter.HandleFunc("", handleCreateToken(hfStore, authzStore)).Methods("POST")
	tokensRouter.HandleFunc("/{token}", handleDeleteToken(hfStore, authzStore)).Methods("DELETE")

	// POST /host_factories/hosts - Create host using HF token (uses token auth, not JWT)
	s.Router.HandleFunc("/host_factories/hosts", handleCreateHost(hfStore)).Methods("POST")
}

func handleCreateToken(hfStore store.HostFactoryStore, authzStore store.AuthzStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			HostFactory string   `json:"host_factory"`
			Expiration  string   `json:"expiration"`
			Count       int      `json:"count"`
			CIDR        []string `json:"cidr"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

		expiration, err := time.Parse(time.RFC3339, req.Expiration)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, map[string]string{"error": "Invalid expiration format, use ISO8601"})
			return
		}

		if expiration.Before(time.Now()) {
			respondWithError(w, http.StatusBadRequest, map[string]string{"error": "Expiration must be in the future"})
			return
		}

		count := req.Count
		if count <= 0 {
			count = 1
		}

		id, _ := identity.Get(r.Context())
		roleId := id.RoleID

		if !authzStore.IsRoleAllowedTo(roleId, "execute", req.HostFactory) {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		if hfStore.GetResourceKind(req.HostFactory) != "host_factory" {
			respondWithError(w, http.StatusBadRequest, map[string]string{"error": "Invalid resource kind, must be host_factory"})
			return
		}

		tokens := make([]model.HostFactoryTokenResponse, 0, count)
		for i := 0; i < count; i++ {
			hfToken, err := hfStore.CreateToken(req.HostFactory, expiration, req.CIDR)
			if err != nil {
				respondWithError(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}

			tokens = append(tokens, model.HostFactoryTokenResponse{
				Token:      hfToken.Token,
				Expiration: hfToken.Expiration.Format(time.RFC3339),
				CIDR:       hfToken.CIDR,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(tokens)
	}
}

func handleDeleteToken(hfStore store.HostFactoryStore, authzStore store.AuthzStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		token := vars["token"]

		hfToken, err := hfStore.FindToken(token)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if hfToken == nil {
			respondWithError(w, http.StatusNotFound, map[string]string{"error": "Token not found"})
			return
		}

		id, _ := identity.Get(r.Context())
		roleId := id.RoleID

		if !authzStore.IsRoleAllowedTo(roleId, "update", hfToken.ResourceID) {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		if err := hfStore.DeleteToken(hfToken); err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func handleCreateHost(hfStore store.HostFactoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondWithError(w, http.StatusUnauthorized, map[string]string{"error": "Authorization required"})
			return
		}

		var token string
		if strings.HasPrefix(authHeader, "Token token=\"") && strings.HasSuffix(authHeader, "\"") {
			token = authHeader[13 : len(authHeader)-1]
		} else {
			respondWithError(w, http.StatusUnauthorized, map[string]string{"error": "Invalid authorization format"})
			return
		}

		hfToken, err := hfStore.FindToken(token)
		if err != nil || hfToken == nil {
			respondWithError(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
			return
		}

		if !hfStore.ValidateToken(hfToken, token) {
			respondWithError(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
			return
		}

		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		if !hfToken.IsValid(clientIP) {
			respondWithError(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
			return
		}

		var req struct {
			ID          string            `json:"id"`
			Annotations map[string]string `json:"annotations"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			req.ID = r.FormValue("id")
		}

		if req.ID == "" {
			respondWithError(w, http.StatusBadRequest, map[string]string{"error": "id parameter required"})
			return
		}

		parts := strings.SplitN(hfToken.ResourceID, ":", 3)
		if len(parts) < 3 {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": "Invalid host factory resource ID"})
			return
		}
		account := parts[0]

		hostRoleID := fmt.Sprintf("%s:host:%s", account, req.ID)

		if hfStore.RoleExists(hostRoleID) {
			respondWithError(w, http.StatusConflict, map[string]string{"error": "Host already exists"})
			return
		}

		apiKey, err := hfStore.GenerateAPIKey()
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": "Failed to generate API key"})
			return
		}

		ownerID := hfStore.GetResourceOwner(hfToken.ResourceID)

		if err := hfStore.CreateHost(hostRoleID, ownerID, apiKey); err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		if err := hfStore.AddHostToLayers(hfToken.ResourceID, hostRoleID, account); err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		if len(req.Annotations) > 0 {
			if err := hfStore.CreateAnnotations(hostRoleID, req.Annotations); err != nil {
				respondWithError(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
		}

		response := map[string]interface{}{
			"id":         hostRoleID,
			"owner":      ownerID,
			"created_at": time.Now().UTC().Format(time.RFC3339),
			"api_key":    apiKey,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(response)
	}
}
