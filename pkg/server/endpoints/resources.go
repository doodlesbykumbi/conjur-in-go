package endpoints

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"gorm.io/gorm"

	"conjur-in-go/pkg/audit"
	"conjur-in-go/pkg/server"
	"conjur-in-go/pkg/server/middleware"
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
	db := s.DB

	jwtMiddleware := middleware.NewJWTAuthenticator(s.Keystore)

	resourcesRouter := s.Router.PathPrefix("/resources").Subrouter()
	resourcesRouter.Use(jwtMiddleware.Middleware)

	// GET /resources/{account} - List all resources
	// GET /resources/{account}/{kind} - List resources by kind
	resourcesRouter.HandleFunc("/{account}", handleListResources(db)).Methods("GET")
	resourcesRouter.HandleFunc("/{account}/", handleListResources(db)).Methods("GET")
	resourcesRouter.HandleFunc("/{account}/{kind}", handleListResources(db)).Methods("GET")

	// GET /resources/{account}/{kind}/{identifier} - Show single resource
	resourcesRouter.HandleFunc("/{account}/{kind}/{identifier:.+}", handleShowResource(db)).Methods("GET")
}

func handleListResources(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]

		// Get role from auth context
		roleId := r.Context().Value("roleId").(string)

		// Parse query parameters - kind can come from URL path or query param
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

		// Check if count only is requested
		if r.URL.Query().Get("count") == "true" {
			count := countResources(db, account, kind, roleId, search)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]int{"count": count})
			return
		}

		// Fetch resources
		resources := listResources(db, account, kind, roleId, search, limit, offset)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resources)
	}
}

func handleShowResource(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])

		resourceId := account + ":" + kind + ":" + identifier

		// Get role from auth context (the authenticated user)
		authRoleId := r.Context().Value("roleId").(string)

		// Get client IP for audit
		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		// Check if this is a permission check request
		if r.URL.Query().Get("check") == "true" {
			handlePermissionCheck(db, w, r, account, resourceId, authRoleId, clientIP)
			return
		}

		// Check if this is a permitted_roles request
		if _, hasPermittedRoles := r.URL.Query()["permitted_roles"]; hasPermittedRoles {
			handlePermittedRoles(db, w, r, resourceId)
			return
		}

		// Check if user can see this resource
		var canSee bool
		db.Raw(`SELECT is_resource_visible(?, ?)`, resourceId, authRoleId).Scan(&canSee)
		if !canSee {
			// Check if resource exists at all
			var exists bool
			db.Raw(`SELECT EXISTS(SELECT 1 FROM resources WHERE resource_id = ?)`, resourceId).Scan(&exists)
			if !exists {
				respondWithError(w, http.StatusNotFound, map[string]string{"error": "Resource not found"})
			} else {
				respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			}
			return
		}

		resource := fetchResource(db, resourceId)
		if resource == nil {
			respondWithError(w, http.StatusNotFound, map[string]string{"error": "Resource not found"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resource)
	}
}

// handlePermittedRoles returns all roles that have a given privilege on a resource
// GET /resources/{account}/{kind}/{identifier}?permitted_roles=true&privilege={privilege}
func handlePermittedRoles(db *gorm.DB, w http.ResponseWriter, r *http.Request, resourceId string) {
	privilege := r.URL.Query().Get("privilege")
	if privilege == "" {
		respondWithError(w, http.StatusBadRequest, map[string]string{"error": "privilege parameter is required"})
		return
	}

	// Use the roles_that_can function
	type roleRow struct {
		RoleID string `gorm:"column:role_id"`
	}
	var rows []roleRow
	db.Raw(`SELECT role_id FROM roles_that_can(?, ?)`, privilege, resourceId).Scan(&rows)

	roleIds := make([]string, 0, len(rows))
	for _, row := range rows {
		roleIds = append(roleIds, row.RoleID)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(roleIds)
}

// handlePermissionCheck implements the permission check endpoint
// GET /resources/{account}/{kind}/{identifier}?check=true&privilege={privilege}&role={role}
// Returns 204 if allowed, 404 if not allowed, 403 if role doesn't exist
func handlePermissionCheck(db *gorm.DB, w http.ResponseWriter, r *http.Request, account, resourceId, authRoleId, clientIP string) {
	privilege := r.URL.Query().Get("privilege")
	if privilege == "" {
		respondWithError(w, http.StatusBadRequest, map[string]string{"error": "privilege parameter is required"})
		return
	}

	// Determine which role to check - either specified role or authenticated user
	checkRoleId := authRoleId
	if roleParam := r.URL.Query().Get("role"); roleParam != "" {
		// If role doesn't contain ":", assume it's relative to account
		if !strings.Contains(roleParam, ":") {
			checkRoleId = account + ":user:" + roleParam
		} else {
			checkRoleId = roleParam
		}
	}

	// Check if the resource exists and is visible to the authenticated user
	var resourceExists bool
	db.Raw(`SELECT EXISTS(SELECT 1 FROM resources WHERE resource_id = ?)`, resourceId).Scan(&resourceExists)
	if !resourceExists {
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

	// Check if the role to check exists
	var roleExists bool
	db.Raw(`SELECT EXISTS(SELECT 1 FROM roles WHERE role_id = ?)`, checkRoleId).Scan(&roleExists)
	if !roleExists {
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

	// Check if the role has the privilege on the resource
	allowed := isRoleAllowedTo(db, checkRoleId, privilege, resourceId)

	// Audit log the check
	audit.Log(audit.CheckEvent{
		UserID:     authRoleId,
		ClientIP:   clientIP,
		ResourceID: resourceId,
		Privilege:  privilege,
		Allowed:    allowed,
	})

	if allowed {
		w.WriteHeader(http.StatusNoContent) // 204
	} else {
		w.WriteHeader(http.StatusNotFound) // 404
	}
}

func listResources(db *gorm.DB, account, kind, roleId, search string, limit, offset int) []ResourceResponse {
	// Build query using visible_resources function
	query := `
		SELECT resource_id, owner_id, created_at
		FROM visible_resources(?)
		WHERE account(resource_id) = ?
	`
	args := []interface{}{roleId, account}

	if kind != "" {
		query += ` AND kind(resource_id) = ?`
		args = append(args, kind)
	}

	if search != "" {
		query += ` AND resource_id ILIKE ?`
		args = append(args, "%"+search+"%")
	}

	query += ` ORDER BY resource_id`

	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	if offset > 0 {
		query += ` OFFSET ?`
		args = append(args, offset)
	}

	type resourceRow struct {
		ResourceId string
		OwnerId    string
		CreatedAt  *string
	}

	var rows []resourceRow
	db.Raw(query, args...).Scan(&rows)

	resources := make([]ResourceResponse, 0, len(rows))
	for _, row := range rows {
		resource := ResourceResponse{
			ID:    row.ResourceId,
			Owner: row.OwnerId,
		}

		// Fetch permissions
		resource.Permissions = fetchPermissions(db, row.ResourceId)

		// Fetch annotations
		resource.Annotations = fetchAnnotations(db, row.ResourceId)

		// Fetch secret metadata for variables
		if strings.Contains(row.ResourceId, ":variable:") {
			resource.Secrets = fetchSecretMeta(db, row.ResourceId)
		}

		resources = append(resources, resource)
	}

	return resources
}

func countResources(db *gorm.DB, account, kind, roleId, search string) int {
	query := `
		SELECT COUNT(*)
		FROM visible_resources(?)
		WHERE account(resource_id) = ?
	`
	args := []interface{}{roleId, account}

	if kind != "" {
		query += ` AND kind(resource_id) = ?`
		args = append(args, kind)
	}

	if search != "" {
		query += ` AND resource_id ILIKE ?`
		args = append(args, "%"+search+"%")
	}

	var count int
	db.Raw(query, args...).Scan(&count)
	return count
}

func fetchResource(db *gorm.DB, resourceId string) *ResourceResponse {
	type resourceRow struct {
		ResourceId string
		OwnerId    string
		CreatedAt  *string
	}

	var row resourceRow
	result := db.Raw(`
		SELECT resource_id, owner_id, created_at
		FROM resources WHERE resource_id = ?
	`, resourceId).Scan(&row)

	if result.Error != nil || row.ResourceId == "" {
		return nil
	}

	resource := &ResourceResponse{
		ID:    row.ResourceId,
		Owner: row.OwnerId,
	}

	resource.Permissions = fetchPermissions(db, resourceId)
	resource.Annotations = fetchAnnotations(db, resourceId)

	if strings.Contains(resourceId, ":variable:") {
		resource.Secrets = fetchSecretMeta(db, resourceId)
	}

	return resource
}

func fetchPermissions(db *gorm.DB, resourceId string) []PermissionResponse {
	type permRow struct {
		Privilege string
		RoleId    string
		PolicyId  *string
	}

	var rows []permRow
	db.Raw(`
		SELECT privilege, role_id, policy_id
		FROM permissions WHERE resource_id = ?
		ORDER BY role_id, privilege
	`, resourceId).Scan(&rows)

	perms := make([]PermissionResponse, 0, len(rows))
	for _, row := range rows {
		perm := PermissionResponse{
			Privilege: row.Privilege,
			Role:      row.RoleId,
		}
		if row.PolicyId != nil {
			perm.Policy = *row.PolicyId
		}
		perms = append(perms, perm)
	}
	return perms
}

func fetchAnnotations(db *gorm.DB, resourceId string) map[string]string {
	type annRow struct {
		Name  string
		Value string
	}

	var rows []annRow
	db.Raw(`
		SELECT name, value FROM annotations WHERE resource_id = ?
	`, resourceId).Scan(&rows)

	annotations := make(map[string]string)
	for _, row := range rows {
		annotations[row.Name] = row.Value
	}
	return annotations
}

func fetchSecretMeta(db *gorm.DB, resourceId string) []SecretMetaResponse {
	type secretRow struct {
		Version   int
		ExpiresAt *string
	}

	var rows []secretRow
	db.Raw(`
		SELECT version, expires_at FROM secrets WHERE resource_id = ? ORDER BY version
	`, resourceId).Scan(&rows)

	secrets := make([]SecretMetaResponse, 0, len(rows))
	for _, row := range rows {
		secret := SecretMetaResponse{
			Version: row.Version,
		}
		if row.ExpiresAt != nil {
			secret.ExpiresAt = *row.ExpiresAt
		}
		secrets = append(secrets, secret)
	}
	return secrets
}
