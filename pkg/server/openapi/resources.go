package openapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/doodlesbykumbi/conjur-in-go/api"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/audit"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/identity"
)

// ListResources implements api.ServerInterface
func (s *APIServer) ListResources(w http.ResponseWriter, r *http.Request, account api.Account, params api.ListResourcesParams) {
	id, _ := identity.Get(r.Context())
	roleId := id.RoleID

	kind := ""
	if params.Kind != nil {
		kind = *params.Kind
	}

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

	// Handle count request
	if params.Count != nil && *params.Count {
		count := s.resourcesStore.CountResources(account, kind, roleId, search)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"count": count})
		return
	}

	resources := s.resourcesStore.ListResources(account, kind, roleId, search, limit, offset)

	responses := make([]api.Resource, 0, len(resources))
	for _, res := range resources {
		resource := api.Resource{
			Id:    &res.ID,
			Owner: &res.Owner,
		}
		if res.Annotations != nil {
			resource.Annotations = &res.Annotations
		}
		responses = append(responses, resource)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(responses)
}

// ListResourcesByKind implements api.ServerInterface
func (s *APIServer) ListResourcesByKind(w http.ResponseWriter, r *http.Request, account api.Account, kind api.Kind, params api.ListResourcesByKindParams) {
	id, _ := identity.Get(r.Context())
	roleId := id.RoleID

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

	resources := s.resourcesStore.ListResources(account, kind, roleId, search, limit, offset)

	responses := make([]api.Resource, 0, len(resources))
	for _, res := range resources {
		resource := api.Resource{
			Id:    &res.ID,
			Owner: &res.Owner,
		}
		if res.Annotations != nil {
			resource.Annotations = &res.Annotations
		}
		responses = append(responses, resource)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(responses)
}

// GetResource implements api.ServerInterface
func (s *APIServer) GetResource(w http.ResponseWriter, r *http.Request, account api.Account, kind api.Kind, identifier api.Identifier, params api.GetResourceParams) {
	resourceId := account + ":" + kind + ":" + identifier

	id, _ := identity.Get(r.Context())
	authRoleId := id.RoleID
	clientIP := getClientIP(r)

	// Handle permission check
	if params.Check != nil && *params.Check {
		privilege := ""
		if params.Privilege != nil {
			privilege = *params.Privilege
		}
		if privilege == "" {
			http.Error(w, "privilege parameter is required for permission check", http.StatusBadRequest)
			return
		}

		checkRoleId := authRoleId
		if params.Role != nil && *params.Role != "" {
			roleParam := *params.Role
			if !strings.Contains(roleParam, ":") {
				checkRoleId = account + ":user:" + roleParam
			} else {
				checkRoleId = roleParam
			}
		}

		if !s.resourcesStore.ResourceExists(resourceId) {
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

		if !s.resourcesStore.RoleExists(checkRoleId) {
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

		allowed := s.authzStore.IsRoleAllowedTo(checkRoleId, privilege, resourceId)

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
			w.WriteHeader(http.StatusForbidden)
		}
		return
	}

	// Handle permitted_roles query
	if params.PermittedRoles != nil && *params.PermittedRoles {
		// Not implemented yet
		http.Error(w, "permitted_roles query not implemented", http.StatusNotImplemented)
		return
	}

	// Regular resource fetch
	if !s.resourcesStore.IsResourceVisible(resourceId, authRoleId) {
		if !s.resourcesStore.ResourceExists(resourceId) {
			respondWithError(w, http.StatusNotFound, map[string]string{"error": "Resource not found"})
		} else {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
		}
		return
	}

	resource := s.resourcesStore.FetchResource(resourceId)
	if resource == nil {
		respondWithError(w, http.StatusNotFound, map[string]string{"error": "Resource not found"})
		return
	}

	response := api.Resource{
		Id:    &resource.ID,
		Owner: &resource.Owner,
	}
	if resource.Annotations != nil {
		response.Annotations = &resource.Annotations
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}
