package endpoints

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/audit"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/identity"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
)

// ResourceResponse represents a resource in the API response
type ResourceResponse struct {
	ID          string               `json:"id"`
	Owner       string               `json:"owner"`
	Policy      string               `json:"policy,omitempty"`
	CreatedAt   string               `json:"created_at,omitempty"`
	Permissions []PermissionResponse `json:"permissions"`
	Annotations map[string]string    `json:"annotations"`
	Secrets     []SecretMetaResponse `json:"secrets,omitempty"`
}

// PermissionResponse represents a permission in the API response
type PermissionResponse struct {
	Privilege string `json:"privilege"`
	Role      string `json:"role"`
	Policy    string `json:"policy,omitempty"`
}

// SecretMetaResponse represents secret metadata (not the value)
type SecretMetaResponse struct {
	Version   int    `json:"version"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// RegisterResourcesEndpoints registers the resources API endpoints
func RegisterResourcesEndpoints(s *server.Server) {
	resourcesStore := s.ResourcesStore
	authzStore := s.AuthzStore

	resourcesRouter := s.Router.PathPrefix("/resources").Subrouter()
	resourcesRouter.Use(s.JWTMiddleware.Middleware)

	// GET /resources/{account} - List all resources
	// GET /resources/{account}/{kind} - List resources by kind
	resourcesRouter.HandleFunc("/{account}", handleListResources(resourcesStore)).Methods("GET")
	resourcesRouter.HandleFunc("/{account}/", handleListResources(resourcesStore)).Methods("GET")
	resourcesRouter.HandleFunc("/{account}/{kind}", handleListResources(resourcesStore)).Methods("GET")

	// GET /resources/{account}/{kind}/{identifier} - Show single resource
	resourcesRouter.HandleFunc("/{account}/{kind}/{identifier:.+}", handleShowResource(resourcesStore, authzStore)).Methods("GET")
}

func handleListResources(resourcesStore store.ResourcesStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]

		id, _ := identity.Get(r.Context())
		roleId := id.RoleID

		if kindParam := r.URL.Query().Get("kind"); kindParam != "" {
			kind = kindParam
		}
		limit := 0
		offset := 0
		search := r.URL.Query().Get("search")

		if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
			if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
				limit = l
			}
		}
		if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
			if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
				offset = o
			}
		}

		if r.URL.Query().Get("count") == "true" {
			count := resourcesStore.CountResources(account, kind, roleId, search)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]int{"count": count})
			return
		}

		resources := resourcesStore.ListResources(account, kind, roleId, search, limit, offset)

		// Convert to response format
		responses := make([]ResourceResponse, 0, len(resources))
		for _, res := range resources {
			responses = append(responses, toResourceResponse(res))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(responses)
	}
}

func handleShowResource(resourcesStore store.ResourcesStore, authzStore store.AuthzStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])

		resourceId := account + ":" + kind + ":" + identifier

		id, _ := identity.Get(r.Context())
		authRoleId := id.RoleID

		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		// Check if this is a permission check request
		if r.URL.Query().Get("check") == "true" {
			handlePermissionCheck(resourcesStore, authzStore, w, r, account, resourceId, authRoleId, clientIP)
			return
		}

		// Check if this is a permitted_roles request
		if _, hasPermittedRoles := r.URL.Query()["permitted_roles"]; hasPermittedRoles {
			handlePermittedRoles(resourcesStore, w, r, resourceId)
			return
		}

		// Check if user can see this resource
		if !resourcesStore.IsResourceVisible(resourceId, authRoleId) {
			if !resourcesStore.ResourceExists(resourceId) {
				respondWithError(w, http.StatusNotFound, map[string]string{"error": "Resource not found"})
			} else {
				respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			}
			return
		}

		resource := resourcesStore.FetchResource(resourceId)
		if resource == nil {
			respondWithError(w, http.StatusNotFound, map[string]string{"error": "Resource not found"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toResourceResponse(*resource))
	}
}

func handlePermittedRoles(resourcesStore store.ResourcesStore, w http.ResponseWriter, r *http.Request, resourceId string) {
	privilege := r.URL.Query().Get("privilege")
	if privilege == "" {
		respondWithError(w, http.StatusBadRequest, map[string]string{"error": "privilege parameter is required"})
		return
	}

	roleIds := resourcesStore.PermittedRoles(privilege, resourceId)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(roleIds)
}

func handlePermissionCheck(resourcesStore store.ResourcesStore, authzStore store.AuthzStore, w http.ResponseWriter, r *http.Request, account, resourceId, authRoleId, clientIP string) {
	privilege := r.URL.Query().Get("privilege")
	if privilege == "" {
		respondWithError(w, http.StatusBadRequest, map[string]string{"error": "privilege parameter is required"})
		return
	}

	checkRoleId := authRoleId
	if roleParam := r.URL.Query().Get("role"); roleParam != "" {
		if !strings.Contains(roleParam, ":") {
			checkRoleId = account + ":user:" + roleParam
		} else {
			checkRoleId = roleParam
		}
	}

	if !resourcesStore.ResourceExists(resourceId) {
		audit.Log(audit.CheckEvent{
			UserID:       authRoleId,
			ClientIP:     clientIP,
			ResourceID:   resourceId,
			Privilege:    privilege,
			Allowed:      false,
			ErrorMessage: "resource not found",
		})
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if !resourcesStore.RoleExists(checkRoleId) {
		audit.Log(audit.CheckEvent{
			UserID:       authRoleId,
			ClientIP:     clientIP,
			ResourceID:   resourceId,
			Privilege:    privilege,
			Allowed:      false,
			ErrorMessage: "role not found",
		})
		w.WriteHeader(http.StatusForbidden)
		return
	}

	allowed := authzStore.IsRoleAllowedTo(checkRoleId, privilege, resourceId)

	audit.Log(audit.CheckEvent{
		UserID:     authRoleId,
		ClientIP:   clientIP,
		ResourceID: resourceId,
		Privilege:  privilege,
		Allowed:    allowed,
	})

	if allowed {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

func toResourceResponse(res store.Resource) ResourceResponse {
	response := ResourceResponse{
		ID:          res.ID,
		Owner:       res.Owner,
		Annotations: res.Annotations,
	}

	response.Permissions = make([]PermissionResponse, 0, len(res.Permissions))
	for _, p := range res.Permissions {
		response.Permissions = append(response.Permissions, PermissionResponse{
			Privilege: p.Privilege,
			Role:      p.Role,
			Policy:    p.Policy,
		})
	}

	response.Secrets = make([]SecretMetaResponse, 0, len(res.Secrets))
	for _, s := range res.Secrets {
		response.Secrets = append(response.Secrets, SecretMetaResponse{
			Version:   s.Version,
			ExpiresAt: s.ExpiresAt,
		})
	}

	return response
}
