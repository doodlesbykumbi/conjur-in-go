package endpoints

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"gorm.io/gorm"

	"conjur-in-go/pkg/model"
	"conjur-in-go/pkg/policy"
	"conjur-in-go/pkg/server"
	"conjur-in-go/pkg/server/middleware"
)

// PolicyLoadResponse is the response from loading a policy
type PolicyLoadResponse struct {
	CreatedRoles map[string]policy.RoleCredentials `json:"created_roles"`
	Version      int                               `json:"version"`
	DryRun       bool                              `json:"dry_run,omitempty"`
}

// PolicyVersionResponse represents a policy version in the API response
type PolicyVersionResponse struct {
	Version      int        `json:"version"`
	CreatedAt    time.Time  `json:"created_at"`
	PolicySHA256 string     `json:"policy_sha256"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	ClientIP     string     `json:"client_ip,omitempty"`
	RoleID       string     `json:"role_id,omitempty"`
}

// RegisterPoliciesEndpoints registers the policy-related HTTP endpoints
func RegisterPoliciesEndpoints(s *server.Server) {
	jwtMiddleware := middleware.NewJWTAuthenticator(s.Keystore)

	policiesRouter := s.Router.PathPrefix("/policies").Subrouter()
	policiesRouter.Use(jwtMiddleware.Middleware)

	// GET /policies/{account}/policy/{identifier} - Get policy versions
	policiesRouter.HandleFunc("/{account}/policy/{identifier}", handleGetPolicy(s.DB)).Methods("GET")

	// POST /policies/{account}/policy/{identifier} - Load policy (create mode)
	policiesRouter.HandleFunc("/{account}/policy/{identifier}", handlePolicyLoad(s)).Methods("POST")

	// PUT /policies/{account}/policy/{identifier} - Replace policy
	policiesRouter.HandleFunc("/{account}/policy/{identifier}", handlePolicyLoad(s)).Methods("PUT")

	// PATCH /policies/{account}/policy/{identifier} - Update policy
	policiesRouter.HandleFunc("/{account}/policy/{identifier}", handlePolicyLoad(s)).Methods("PATCH")
}

// handleGetPolicy returns policy versions
func handleGetPolicy(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		identifier := vars["identifier"]

		policyID := account + ":policy:" + identifier

		// Get role from auth context
		tokenInfo, _ := middleware.GetTokenInfo(r.Context())
		roleId := tokenInfo.RoleID

		// Check if user can see this policy
		var canSee bool
		db.Raw(`SELECT is_resource_visible(?, ?)`, policyID, roleId).Scan(&canSee)
		if !canSee {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		// Check for version query param
		if versionStr := r.URL.Query().Get("version"); versionStr != "" {
			version, err := strconv.Atoi(versionStr)
			if err != nil {
				respondWithError(w, http.StatusBadRequest, map[string]string{"error": "Invalid version"})
				return
			}

			var pv model.PolicyVersion
			result := db.Where("resource_id = ? AND version = ?", policyID, version).First(&pv)
			if result.Error != nil {
				respondWithError(w, http.StatusNotFound, map[string]string{"error": "Policy version not found"})
				return
			}

			// Return policy text
			w.Header().Set("Content-Type", "application/x-yaml")
			_, _ = w.Write([]byte(pv.PolicyText))
			return
		}

		// Return list of versions
		type versionRow struct {
			Version      int
			CreatedAt    time.Time
			PolicySHA256 string
			FinishedAt   *time.Time
			ClientIP     string
			RoleID       string
		}
		var rows []versionRow
		db.Raw(`
			SELECT version, created_at, policy_sha256, finished_at, client_ip, role_id
			FROM policy_versions
			WHERE resource_id = ?
			ORDER BY version DESC
		`, policyID).Scan(&rows)

		versions := make([]PolicyVersionResponse, 0, len(rows))
		for _, row := range rows {
			versions = append(versions, PolicyVersionResponse{
				Version:      row.Version,
				CreatedAt:    row.CreatedAt,
				PolicySHA256: row.PolicySHA256,
				FinishedAt:   row.FinishedAt,
				ClientIP:     row.ClientIP,
				RoleID:       row.RoleID,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(versions)
	}
}

func handlePolicyLoad(s *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		identifier := vars["identifier"] // e.g., "root" - used for target policy

		// Read policy body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		defer func() { _ = r.Body.Close() }()

		if len(body) == 0 {
			http.Error(w, "Policy body is required", http.StatusBadRequest)
			return
		}

		// Get role ID from auth context (set by JWT middleware)
		roleID := ""
		if rid := r.Context().Value("roleId"); rid != nil {
			roleID = rid.(string)
		}

		// Get client IP
		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		// Build policy resource ID
		policyID := account + ":policy:" + identifier

		// Determine if delete is permitted based on HTTP method
		// POST (create/append) - delete NOT permitted
		// PUT (replace) - delete permitted
		// PATCH (modify) - delete permitted
		deletePermitted := r.Method == "PUT" || r.Method == "PATCH"

		// Check for dry-run mode
		dryRun := r.URL.Query().Get("dry_run") == "true"

		// Load policy using the shared loader with versioning info
		loader := policy.NewLoader(s.DB, s.Cipher, account).
			WithPolicyID(policyID).
			WithRoleID(roleID).
			WithClientIP(clientIP).
			WithDeletePermitted(deletePermitted).
			WithDryRun(dryRun)
		result, err := loader.LoadFromString(string(body))
		if err != nil {
			http.Error(w, "Failed to load policy: "+err.Error(), http.StatusUnprocessableEntity)
			return
		}

		// Return response
		response := PolicyLoadResponse{
			CreatedRoles: result.CreatedRoles,
			Version:      result.Version,
			DryRun:       dryRun,
		}

		w.Header().Set("Content-Type", "application/json")
		if dryRun {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusCreated)
		}
		_ = json.NewEncoder(w).Encode(response)
	}
}
