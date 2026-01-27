package openapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/doodlesbykumbi/conjur-in-go/api"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/identity"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/policy/loader"
)

// GetPolicy implements api.ServerInterface
func (s *APIServer) GetPolicy(w http.ResponseWriter, r *http.Request, account api.Account, identifier api.Identifier, params api.GetPolicyParams) {
	policyID := account + ":policy:" + identifier

	id, _ := identity.Get(r.Context())
	roleId := id.RoleID

	if !s.resourcesStore.IsResourceVisible(policyID, roleId) {
		respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
		return
	}

	if params.Version != nil {
		pv, err := s.policyStore.GetPolicyVersion(policyID, *params.Version)
		if err != nil {
			respondWithError(w, http.StatusNotFound, map[string]string{"error": "Policy version not found"})
			return
		}
		w.Header().Set("Content-Type", "application/x-yaml")
		_, _ = w.Write([]byte(pv.PolicyText))
		return
	}

	rows := s.policyStore.ListPolicyVersions(policyID)
	versions := make([]api.PolicyVersion, 0, len(rows))
	for _, row := range rows {
		pv := api.PolicyVersion{
			Version:      &row.Version,
			PolicySha256: &row.PolicySHA256,
			ClientIp:     &row.ClientIP,
			RoleId:       &row.RoleID,
		}
		createdAt := row.CreatedAt
		pv.CreatedAt = &createdAt
		if row.FinishedAt != nil {
			pv.FinishedAt = row.FinishedAt
		}
		versions = append(versions, pv)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(versions)
}

// LoadPolicy implements api.ServerInterface (POST - append)
func (s *APIServer) LoadPolicy(w http.ResponseWriter, r *http.Request, account api.Account, identifier api.Identifier, params api.LoadPolicyParams) {
	s.handlePolicyLoad(w, r, account, identifier, false, params.DryRun)
}

// ReplacePolicy implements api.ServerInterface (PUT - replace)
func (s *APIServer) ReplacePolicy(w http.ResponseWriter, r *http.Request, account api.Account, identifier api.Identifier, params api.ReplacePolicyParams) {
	s.handlePolicyLoad(w, r, account, identifier, true, params.DryRun)
}

// UpdatePolicy implements api.ServerInterface (PATCH - update)
func (s *APIServer) UpdatePolicy(w http.ResponseWriter, r *http.Request, account api.Account, identifier api.Identifier, params api.UpdatePolicyParams) {
	s.handlePolicyLoad(w, r, account, identifier, true, params.DryRun)
}

func (s *APIServer) handlePolicyLoad(w http.ResponseWriter, r *http.Request, account, identifier string, deletePermitted bool, dryRun *bool) {
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

	roleID := ""
	if id, ok := identity.Get(r.Context()); ok {
		roleID = id.RoleID
	}

	clientIP := getClientIP(r)
	policyID := account + ":policy:" + identifier

	isDryRun := dryRun != nil && *dryRun

	l := loader.NewLoader(s.loaderStore, account).
		WithPolicyID(policyID).
		WithRoleID(roleID).
		WithClientIP(clientIP).
		WithDeletePermitted(deletePermitted).
		WithDryRun(isDryRun)

	result, err := l.LoadFromString(string(body))
	if err != nil {
		http.Error(w, "Failed to load policy: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	createdRoles := make(map[string]struct {
		ApiKey *string `json:"api_key,omitempty"`
		Id     *string `json:"id,omitempty"`
	})
	for k, v := range result.CreatedRoles {
		apiKey := v.APIKey
		id := v.ID
		createdRoles[k] = struct {
			ApiKey *string `json:"api_key,omitempty"`
			Id     *string `json:"id,omitempty"`
		}{
			ApiKey: &apiKey,
			Id:     &id,
		}
	}

	response := api.PolicyLoadResponse{
		CreatedRoles: &createdRoles,
		Version:      &result.Version,
		DryRun:       &isDryRun,
	}

	w.Header().Set("Content-Type", "application/json")
	if isDryRun {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
	_ = json.NewEncoder(w).Encode(response)
}
