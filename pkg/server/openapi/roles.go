package openapi

import (
	"encoding/json"
	"net/http"

	"github.com/doodlesbykumbi/conjur-in-go/api"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/identity"
)

// GetRole implements api.ServerInterface
func (s *APIServer) GetRole(w http.ResponseWriter, r *http.Request, account api.Account, kind api.Kind, identifier api.Identifier, params api.GetRoleParams) {
	roleId := account + ":" + kind + ":" + identifier

	id, _ := identity.Get(r.Context())
	authRoleId := id.RoleID

	// Check if role exists
	if !s.rolesStore.RoleExists(roleId) {
		respondWithError(w, http.StatusNotFound, map[string]string{"error": "Role not found"})
		return
	}

	// Handle members query
	if params.Members != nil && *params.Members {
		search := ""
		if params.Search != nil {
			search = *params.Search
		}
		limit := 0
		if params.Limit != nil {
			limit = *params.Limit
		}
		offset := 0
		if params.Offset != nil {
			offset = *params.Offset
		}

		// Handle count
		if params.Count != nil && *params.Count {
			count := s.rolesStore.CountRoleMembers(roleId, search, "")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]int{"count": count})
			return
		}

		members := s.rolesStore.FetchRoleMembers(roleId, search, "", limit, offset)
		grants := make([]api.MembershipGrant, 0, len(members))
		for _, m := range members {
			grant := api.MembershipGrant{
				Role:        &roleId,
				Member:      &m.Member,
				AdminOption: &m.AdminOption,
				Ownership:   &m.Ownership,
			}
			if m.Policy != "" {
				grant.Policy = &m.Policy
			}
			grants = append(grants, grant)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(grants)
		return
	}

	// Handle memberships query
	if params.Memberships != nil && *params.Memberships {
		all := params.All != nil && *params.All

		// Handle count
		if params.Count != nil && *params.Count {
			var count int
			if all {
				count = s.rolesStore.CountAllMemberships(roleId)
			} else {
				count = s.rolesStore.CountRoleMemberships(roleId)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]int{"count": count})
			return
		}

		if all {
			memberships := s.rolesStore.FetchAllMemberships(roleId)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(memberships)
		} else {
			memberships := s.rolesStore.FetchRoleMemberships(roleId)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(memberships)
		}
		return
	}

	// Return role details
	role := s.rolesStore.FetchRole(roleId)
	if role == nil {
		respondWithError(w, http.StatusNotFound, map[string]string{"error": "Role not found"})
		return
	}

	// Check visibility
	if !s.resourcesStore.IsResourceVisible(roleId, authRoleId) {
		respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
		return
	}

	response := api.Role{
		Id: &role.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// AddRoleMember implements api.ServerInterface
func (s *APIServer) AddRoleMember(w http.ResponseWriter, r *http.Request, account api.Account, kind api.Kind, identifier api.Identifier, params api.AddRoleMemberParams) {
	roleId := account + ":" + kind + ":" + identifier
	memberId := params.Member

	id, _ := identity.Get(r.Context())
	authRoleId := id.RoleID

	// Check if role exists
	if !s.rolesStore.RoleExists(roleId) {
		respondWithError(w, http.StatusNotFound, map[string]string{"error": "Role not found"})
		return
	}

	// Check if member exists
	if !s.rolesStore.RoleExists(memberId) {
		respondWithError(w, http.StatusNotFound, map[string]string{"error": "Member role not found"})
		return
	}

	// Check permission - must have update on the role
	if !s.authzStore.IsRoleAllowedTo(authRoleId, "update", roleId) {
		respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
		return
	}

	policyID := s.rolesStore.GetRolePolicyID(roleId)
	if err := s.rolesStore.AddMembership(roleId, memberId, policyID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// DeleteRoleMember implements api.ServerInterface
func (s *APIServer) DeleteRoleMember(w http.ResponseWriter, r *http.Request, account api.Account, kind api.Kind, identifier api.Identifier, params api.DeleteRoleMemberParams) {
	roleId := account + ":" + kind + ":" + identifier
	memberId := params.Member

	id, _ := identity.Get(r.Context())
	authRoleId := id.RoleID

	// Check if role exists
	if !s.rolesStore.RoleExists(roleId) {
		respondWithError(w, http.StatusNotFound, map[string]string{"error": "Role not found"})
		return
	}

	// Check permission - must have update on the role
	if !s.authzStore.IsRoleAllowedTo(authRoleId, "update", roleId) {
		respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
		return
	}

	if err := s.rolesStore.DeleteMembership(roleId, memberId); err != nil {
		respondWithError(w, http.StatusNotFound, map[string]string{"error": "Membership not found"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
