package openapi

import (
	"net/http"
	"strconv"

	"github.com/doodlesbykumbi/conjur-in-go/api"
	"github.com/gorilla/mux"
)

// HandleGetSecret handles GET /secrets/{account}/{kind}/{identifier:.+}
func HandleGetSecret(s *APIServer, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	account := vars["account"]
	kind := vars["kind"]
	identifier := vars["identifier"]

	var params api.GetSecretParams
	if v := r.URL.Query().Get("version"); v != "" {
		if version, err := strconv.Atoi(v); err == nil {
			params.Version = &version
		}
	}

	s.GetSecret(w, r, account, kind, identifier, params)
}

// HandleCreateSecret handles POST /secrets/{account}/{kind}/{identifier:.+}
func HandleCreateSecret(s *APIServer, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	account := vars["account"]
	kind := vars["kind"]
	identifier := vars["identifier"]

	var params api.CreateSecretParams
	// Check if expirations parameter exists (even if empty value)
	if _, hasExpirations := r.URL.Query()["expirations"]; hasExpirations {
		v := r.URL.Query().Get("expirations")
		params.Expirations = &v
	}

	s.CreateSecret(w, r, account, kind, identifier, params)
}

// HandleGetResource handles GET /resources/{account}/{kind}/{identifier:.+}
func HandleGetResource(s *APIServer, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	account := vars["account"]
	kind := vars["kind"]
	identifier := vars["identifier"]

	var params api.GetResourceParams
	if v := r.URL.Query().Get("check"); v != "" {
		check := v == "true" || v == "1"
		params.Check = &check
	}
	if v := r.URL.Query().Get("privilege"); v != "" {
		params.Privilege = &v
	}
	if v := r.URL.Query().Get("role"); v != "" {
		params.Role = &v
	}
	if v := r.URL.Query().Get("permitted_roles"); v != "" {
		pr := v == "true" || v == "1"
		params.PermittedRoles = &pr
	}

	s.GetResource(w, r, account, kind, identifier, params)
}

// HandleGetRole handles GET /roles/{account}/{kind}/{identifier:.+}
func HandleGetRole(s *APIServer, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	account := vars["account"]
	kind := vars["kind"]
	identifier := vars["identifier"]

	var params api.GetRoleParams
	if v := r.URL.Query().Get("members"); v != "" {
		members := true
		params.Members = &members
	}
	if v := r.URL.Query().Get("memberships"); v != "" {
		memberships := true
		params.Memberships = &memberships
	}
	if v := r.URL.Query().Get("all"); v != "" {
		all := v == "true" || v == "1"
		params.All = &all
	}
	if v := r.URL.Query().Get("count"); v != "" {
		count := v == "true" || v == "1"
		params.Count = &count
	}
	if v := r.URL.Query().Get("search"); v != "" {
		params.Search = &v
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if limit, err := strconv.Atoi(v); err == nil {
			params.Limit = &limit
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if offset, err := strconv.Atoi(v); err == nil {
			params.Offset = &offset
		}
	}

	s.GetRole(w, r, account, kind, identifier, params)
}

// HandleAddRoleMember handles POST /roles/{account}/{kind}/{identifier:.+}
func HandleAddRoleMember(s *APIServer, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	account := vars["account"]
	kind := vars["kind"]
	identifier := vars["identifier"]

	params := api.AddRoleMemberParams{
		Members: r.URL.Query().Get("members"),
		Member:  r.URL.Query().Get("member"),
	}

	s.AddRoleMember(w, r, account, kind, identifier, params)
}

// HandleDeleteRoleMember handles DELETE /roles/{account}/{kind}/{identifier:.+}
func HandleDeleteRoleMember(s *APIServer, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	account := vars["account"]
	kind := vars["kind"]
	identifier := vars["identifier"]

	params := api.DeleteRoleMemberParams{
		Members: r.URL.Query().Get("members"),
		Member:  r.URL.Query().Get("member"),
	}

	s.DeleteRoleMember(w, r, account, kind, identifier, params)
}

// HandleGetPolicy handles GET /policies/{account}/policy/{identifier:.+}
func HandleGetPolicy(s *APIServer, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	account := vars["account"]
	identifier := vars["identifier"]

	var params api.GetPolicyParams
	if v := r.URL.Query().Get("version"); v != "" {
		if version, err := strconv.Atoi(v); err == nil {
			params.Version = &version
		}
	}

	s.GetPolicy(w, r, account, identifier, params)
}

// HandleLoadPolicy handles POST /policies/{account}/policy/{identifier:.+}
func HandleLoadPolicy(s *APIServer, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	account := vars["account"]
	identifier := vars["identifier"]

	var params api.LoadPolicyParams
	if v := r.URL.Query().Get("dry_run"); v != "" {
		dryRun := v == "true" || v == "1"
		params.DryRun = &dryRun
	}

	s.LoadPolicy(w, r, account, identifier, params)
}

// HandleReplacePolicy handles PUT /policies/{account}/policy/{identifier:.+}
func HandleReplacePolicy(s *APIServer, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	account := vars["account"]
	identifier := vars["identifier"]

	var params api.ReplacePolicyParams
	if v := r.URL.Query().Get("dry_run"); v != "" {
		dryRun := v == "true" || v == "1"
		params.DryRun = &dryRun
	}

	s.ReplacePolicy(w, r, account, identifier, params)
}

// HandleUpdatePolicy handles PATCH /policies/{account}/policy/{identifier:.+}
func HandleUpdatePolicy(s *APIServer, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	account := vars["account"]
	identifier := vars["identifier"]

	var params api.UpdatePolicyParams
	if v := r.URL.Query().Get("dry_run"); v != "" {
		dryRun := v == "true" || v == "1"
		params.DryRun = &dryRun
	}

	s.UpdatePolicy(w, r, account, identifier, params)
}
