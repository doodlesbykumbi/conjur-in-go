package endpoints

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/identity"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
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
	rolesStore := s.RolesStore
	authzStore := s.AuthzStore

	rolesRouter := s.Router.PathPrefix("/roles").Subrouter()
	rolesRouter.Use(s.JWTMiddleware.Middleware)

	// GET /roles/{account}/{kind}/{identifier} - Show role
	rolesRouter.HandleFunc("/{account}/{kind}/{identifier:.+}", handleShowRole(rolesStore)).Methods("GET")

	// POST /roles/{account}/{kind}/{identifier}?members&member={member_id} - Add member
	rolesRouter.HandleFunc("/{account}/{kind}/{identifier:.+}", handleAddMember(rolesStore, authzStore)).Methods("POST").Queries("members", "")

	// DELETE /roles/{account}/{kind}/{identifier}?members&member={member_id} - Remove member
	rolesRouter.HandleFunc("/{account}/{kind}/{identifier:.+}", handleDeleteMember(rolesStore, authzStore)).Methods("DELETE").Queries("members", "")
}

func handleShowRole(rolesStore store.RolesStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])

		roleId := account + ":" + kind + ":" + identifier

		id, _ := identity.Get(r.Context())
		authRoleId := id.RoleID

		if _, hasMembers := r.URL.Query()["members"]; hasMembers {
			handleRoleMembers(rolesStore, w, r, roleId)
			return
		}

		if _, hasMemberships := r.URL.Query()["memberships"]; hasMemberships {
			handleRoleMemberships(rolesStore, w, r, roleId)
			return
		}

		if _, hasAll := r.URL.Query()["all"]; hasAll {
			handleAllMemberships(rolesStore, w, r, roleId)
			return
		}

		_ = authRoleId // May be used for visibility checks in future

		if !rolesStore.RoleExists(roleId) {
			respondWithError(w, http.StatusNotFound, map[string]string{"error": "Role not found"})
			return
		}

		role := rolesStore.FetchRole(roleId)
		response := toRoleResponse(role)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}

func handleRoleMembers(rolesStore store.RolesStore, w http.ResponseWriter, r *http.Request, roleId string) {
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

	if r.URL.Query().Get("count") != "" {
		count := rolesStore.CountRoleMembers(roleId, search, kind)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"count": count})
		return
	}

	members := rolesStore.FetchRoleMembers(roleId, search, kind, limit, offset)
	response := toMembershipGrants(members)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func handleRoleMemberships(rolesStore store.RolesStore, w http.ResponseWriter, r *http.Request, roleId string) {
	if r.URL.Query().Get("count") != "" {
		count := rolesStore.CountRoleMemberships(roleId)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"count": count})
		return
	}

	memberships := rolesStore.FetchRoleMemberships(roleId)
	response := toMembershipGrants(memberships)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func handleAllMemberships(rolesStore store.RolesStore, w http.ResponseWriter, r *http.Request, roleId string) {
	if _, hasCount := r.URL.Query()["count"]; hasCount {
		count := rolesStore.CountAllMemberships(roleId)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"count": count})
		return
	}

	roleIds := rolesStore.FetchAllMemberships(roleId)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(roleIds)
}

func handleAddMember(rolesStore store.RolesStore, authzStore store.AuthzStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])

		roleId := account + ":" + kind + ":" + identifier

		memberId := r.URL.Query().Get("member")
		if memberId == "" {
			respondWithError(w, http.StatusBadRequest, map[string]string{"error": "member parameter required"})
			return
		}

		if !strings.Contains(memberId, ":") {
			memberId = account + ":user:" + memberId
		}

		id, _ := identity.Get(r.Context())
		authRoleId := id.RoleID

		policyId := rolesStore.GetRolePolicyID(roleId)
		if policyId == "" {
			policyId = roleId
		}

		if !authzStore.IsRoleAllowedTo(authRoleId, "create", policyId) {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		if !rolesStore.RoleExists(memberId) {
			respondWithError(w, http.StatusNotFound, map[string]string{"error": "Member not found"})
			return
		}

		if err := rolesStore.AddMembership(roleId, memberId, policyId); err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func handleDeleteMember(rolesStore store.RolesStore, authzStore store.AuthzStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])

		roleId := account + ":" + kind + ":" + identifier

		memberId := r.URL.Query().Get("member")
		if memberId == "" {
			respondWithError(w, http.StatusBadRequest, map[string]string{"error": "member parameter required"})
			return
		}

		if !strings.Contains(memberId, ":") {
			memberId = account + ":user:" + memberId
		}

		id, _ := identity.Get(r.Context())
		authRoleId := id.RoleID

		policyId := rolesStore.GetRolePolicyID(roleId)
		if policyId == "" {
			policyId = roleId
		}

		if !authzStore.IsRoleAllowedTo(authRoleId, "update", policyId) {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		if !rolesStore.MembershipExists(roleId, memberId) {
			respondWithError(w, http.StatusNotFound, map[string]string{"error": "Membership not found"})
			return
		}

		if err := rolesStore.DeleteMembership(roleId, memberId); err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func toRoleResponse(role *store.Role) RoleResponse {
	if role == nil {
		return RoleResponse{}
	}
	return RoleResponse{
		ID:      role.ID,
		Members: toMembershipGrants(role.Members),
	}
}

func toMembershipGrants(memberships []store.Membership) []MembershipGrant {
	grants := make([]MembershipGrant, 0, len(memberships))
	for _, m := range memberships {
		grants = append(grants, MembershipGrant{
			Role:        m.Role,
			Member:      m.Member,
			AdminOption: m.AdminOption,
			Ownership:   m.Ownership,
			Policy:      m.Policy,
		})
	}
	return grants
}
