package endpoints

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"gorm.io/gorm"

	"conjur-in-go/pkg/server"
	"conjur-in-go/pkg/server/middleware"
)

// RoleResponse represents a role in the API response
type RoleResponse struct {
	ID      string            `json:"id"`
	Members []MembershipGrant `json:"members,omitempty"`
}

// MembershipGrant represents a role membership grant
type MembershipGrant struct {
	Role        string `json:"role"`
	Member      string `json:"member"`
	AdminOption bool   `json:"admin_option"`
	Ownership   bool   `json:"ownership"`
	Policy      string `json:"policy,omitempty"`
}

// RegisterRolesEndpoints registers the roles API endpoints
func RegisterRolesEndpoints(s *server.Server) {
	db := s.DB

	rolesRouter := s.Router.PathPrefix("/roles").Subrouter()
	rolesRouter.Use(s.JWTMiddleware.Middleware)

	// GET /roles/{account}/{kind}/{identifier} - Show role
	// Also handles ?members, ?memberships, ?all query params
	rolesRouter.HandleFunc("/{account}/{kind}/{identifier:.+}", handleShowRole(db)).Methods("GET")

	// POST /roles/{account}/{kind}/{identifier}?members&member={member_id} - Add member
	rolesRouter.HandleFunc("/{account}/{kind}/{identifier:.+}", handleAddMember(db)).Methods("POST").Queries("members", "")

	// DELETE /roles/{account}/{kind}/{identifier}?members&member={member_id} - Remove member
	rolesRouter.HandleFunc("/{account}/{kind}/{identifier:.+}", handleDeleteMember(db)).Methods("DELETE").Queries("members", "")
}

func handleShowRole(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])

		roleId := account + ":" + kind + ":" + identifier

		// Get authenticated role from context
		tokenInfo, _ := middleware.GetTokenInfo(r.Context())
		authRoleId := tokenInfo.RoleID

		// Check query parameters for specific actions
		if _, hasMembers := r.URL.Query()["members"]; hasMembers {
			handleRoleMembers(db, w, r, roleId, authRoleId)
			return
		}

		if _, hasMemberships := r.URL.Query()["memberships"]; hasMemberships {
			handleRoleMemberships(db, w, r, roleId, authRoleId)
			return
		}

		if _, hasAll := r.URL.Query()["all"]; hasAll {
			handleAllMemberships(db, w, r, roleId, authRoleId)
			return
		}

		// Check if role exists and is visible
		var exists bool
		db.Raw(`SELECT EXISTS(SELECT 1 FROM roles WHERE role_id = ?)`, roleId).Scan(&exists)
		if !exists {
			respondWithError(w, http.StatusNotFound, map[string]string{"error": "Role not found"})
			return
		}

		// Fetch role with memberships
		role := fetchRole(db, roleId)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(role)
	}
}

// handleRoleMembers returns the members of a role (who is IN this role)
func handleRoleMembers(db *gorm.DB, w http.ResponseWriter, r *http.Request, roleId, authRoleId string) {
	// Parse query parameters
	limit := 0
	offset := 0
	search := r.URL.Query().Get("search")
	kind := r.URL.Query().Get("kind")

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		limit, _ = strconv.Atoi(limitStr)
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		offset, _ = strconv.Atoi(offsetStr)
	}

	// Check if count only
	if r.URL.Query().Get("count") != "" {
		count := countRoleMembers(db, roleId, search, kind)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"count": count})
		return
	}

	members := fetchRoleMembers(db, roleId, search, kind, limit, offset)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(members)
}

// handleRoleMemberships returns the direct memberships of a role (what roles is this role a member of)
func handleRoleMemberships(db *gorm.DB, w http.ResponseWriter, r *http.Request, roleId, authRoleId string) {
	// Check if count only
	if r.URL.Query().Get("count") != "" {
		count := countRoleMemberships(db, roleId)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"count": count})
		return
	}

	memberships := fetchRoleMemberships(db, roleId)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(memberships)
}

// handleAllMemberships returns all memberships recursively
func handleAllMemberships(db *gorm.DB, w http.ResponseWriter, r *http.Request, roleId, authRoleId string) {
	// Check if count only
	if _, hasCount := r.URL.Query()["count"]; hasCount {
		count := countAllMemberships(db, roleId)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"count": count})
		return
	}

	// Use the all_roles function to get recursive memberships
	type roleRow struct {
		RoleId string `gorm:"column:role_id"`
	}
	var rows []roleRow
	db.Raw(`SELECT role_id FROM all_roles(?)`, roleId).Scan(&rows)

	roleIds := make([]string, 0, len(rows))
	for _, row := range rows {
		roleIds = append(roleIds, row.RoleId)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(roleIds)
}

func fetchRole(db *gorm.DB, roleId string) RoleResponse {
	role := RoleResponse{
		ID: roleId,
	}

	// Fetch memberships (roles this role is a member of)
	role.Members = fetchRoleMemberships(db, roleId)

	return role
}

func fetchRoleMembers(db *gorm.DB, roleId, search, kind string, limit, offset int) []MembershipGrant {
	query := `
		SELECT role_id, member_id, admin_option, ownership, policy_id
		FROM role_memberships
		WHERE role_id = ?
	`
	args := []interface{}{roleId}

	if search != "" {
		query += ` AND member_id ILIKE ?`
		args = append(args, "%"+search+"%")
	}

	if kind != "" {
		query += ` AND kind(member_id) = ?`
		args = append(args, kind)
	}

	query += ` ORDER BY member_id`

	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	if offset > 0 {
		query += ` OFFSET ?`
		args = append(args, offset)
	}

	type memberRow struct {
		RoleId      string
		MemberId    string
		AdminOption bool
		Ownership   bool
		PolicyId    *string
	}

	var rows []memberRow
	db.Raw(query, args...).Scan(&rows)

	members := make([]MembershipGrant, 0, len(rows))
	for _, row := range rows {
		grant := MembershipGrant{
			Role:        row.RoleId,
			Member:      row.MemberId,
			AdminOption: row.AdminOption,
			Ownership:   row.Ownership,
		}
		if row.PolicyId != nil {
			grant.Policy = *row.PolicyId
		}
		members = append(members, grant)
	}
	return members
}

func countRoleMembers(db *gorm.DB, roleId, search, kind string) int {
	query := `SELECT COUNT(*) FROM role_memberships WHERE role_id = ?`
	args := []interface{}{roleId}

	if search != "" {
		query += ` AND member_id ILIKE ?`
		args = append(args, "%"+search+"%")
	}

	if kind != "" {
		query += ` AND kind(member_id) = ?`
		args = append(args, kind)
	}

	var count int
	db.Raw(query, args...).Scan(&count)
	return count
}

func fetchRoleMemberships(db *gorm.DB, roleId string) []MembershipGrant {
	type memberRow struct {
		RoleId      string
		MemberId    string
		AdminOption bool
		Ownership   bool
		PolicyId    *string
	}

	var rows []memberRow
	db.Raw(`
		SELECT role_id, member_id, admin_option, ownership, policy_id
		FROM role_memberships
		WHERE member_id = ?
		ORDER BY role_id
	`, roleId).Scan(&rows)

	memberships := make([]MembershipGrant, 0, len(rows))
	for _, row := range rows {
		grant := MembershipGrant{
			Role:        row.RoleId,
			Member:      row.MemberId,
			AdminOption: row.AdminOption,
			Ownership:   row.Ownership,
		}
		if row.PolicyId != nil {
			grant.Policy = *row.PolicyId
		}
		memberships = append(memberships, grant)
	}
	return memberships
}

func countRoleMemberships(db *gorm.DB, roleId string) int {
	var count int
	db.Raw(`SELECT COUNT(*) FROM role_memberships WHERE member_id = ?`, roleId).Scan(&count)
	return count
}

func countAllMemberships(db *gorm.DB, roleId string) int {
	var count int
	db.Raw(`SELECT COUNT(*) FROM all_roles(?)`, roleId).Scan(&count)
	return count
}

// AddMemberRequest represents a request to add a member to a role
type AddMemberRequest struct {
	Member string `json:"member"`
}

// handleAddMember adds a member to a role
func handleAddMember(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])

		roleId := account + ":" + kind + ":" + identifier

		// Get member from query param
		memberId := r.URL.Query().Get("member")
		if memberId == "" {
			respondWithError(w, http.StatusBadRequest, map[string]string{"error": "member parameter required"})
			return
		}

		// Make full ID if needed
		if !strings.Contains(memberId, ":") {
			memberId = account + ":user:" + memberId
		}

		// Get authenticated role from context
		tokenInfo, _ := middleware.GetTokenInfo(r.Context())
		authRoleId := tokenInfo.RoleID

		// Check if user has create permission on the role's policy
		var policyId string
		db.Raw(`SELECT policy_id FROM resources WHERE resource_id = ?`, roleId).Scan(&policyId)
		if policyId == "" {
			policyId = roleId
		}

		if !isRoleAllowedTo(db, authRoleId, "create", policyId) {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		// Check if member exists
		var memberExists bool
		db.Raw(`SELECT EXISTS(SELECT 1 FROM roles WHERE role_id = ?)`, memberId).Scan(&memberExists)
		if !memberExists {
			respondWithError(w, http.StatusNotFound, map[string]string{"error": "Member not found"})
			return
		}

		// Add membership
		result := db.Exec(`
			INSERT INTO role_memberships (role_id, member_id, admin_option, ownership, policy_id)
			VALUES (?, ?, false, false, ?)
			ON CONFLICT DO NOTHING
		`, roleId, memberId, policyId)

		if result.Error != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": result.Error.Error()})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// handleDeleteMember removes a member from a role
func handleDeleteMember(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])

		roleId := account + ":" + kind + ":" + identifier

		// Get member from query param
		memberId := r.URL.Query().Get("member")
		if memberId == "" {
			respondWithError(w, http.StatusBadRequest, map[string]string{"error": "member parameter required"})
			return
		}

		// Make full ID if needed
		if !strings.Contains(memberId, ":") {
			memberId = account + ":user:" + memberId
		}

		// Get authenticated role from context
		tokenInfo, _ := middleware.GetTokenInfo(r.Context())
		authRoleId := tokenInfo.RoleID

		// Check if user has update permission on the role's policy
		var policyId string
		db.Raw(`SELECT policy_id FROM resources WHERE resource_id = ?`, roleId).Scan(&policyId)
		if policyId == "" {
			policyId = roleId
		}

		if !isRoleAllowedTo(db, authRoleId, "update", policyId) {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		// Check if membership exists
		var membershipExists bool
		db.Raw(`SELECT EXISTS(SELECT 1 FROM role_memberships WHERE role_id = ? AND member_id = ?)`,
			roleId, memberId).Scan(&membershipExists)
		if !membershipExists {
			respondWithError(w, http.StatusNotFound, map[string]string{"error": "Membership not found"})
			return
		}

		// Delete membership
		result := db.Exec(`DELETE FROM role_memberships WHERE role_id = ? AND member_id = ?`, roleId, memberId)
		if result.Error != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": result.Error.Error()})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
