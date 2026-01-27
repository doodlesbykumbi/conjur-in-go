package openapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/doodlesbykumbi/conjur-in-go/api"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/config"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/identity"
)

// GetStatus implements api.ServerInterface
func (s *APIServer) GetStatus(w http.ResponseWriter, r *http.Request) {
	version := "0.1.0"
	accept := r.Header.Get("Accept")
	format := r.URL.Query().Get("format")

	if format == "json" || strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"version": version})
		return
	}

	html := `<!DOCTYPE html>
<html>
  <head>
    <title>Conjur Status</title>
  </head>
  <body>
    <h1>Status</h1>
    <p>Your Conjur server is running!</p>
    <p>Version: ` + version + `</p>
  </body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

// GetAuthenticators implements api.ServerInterface
func (s *APIServer) GetAuthenticators(w http.ResponseWriter, r *http.Request) {
	installed := make([]string, len(config.ValidAuthenticators))
	copy(installed, config.ValidAuthenticators)

	enabled := s.config.Authenticators
	if s.config.AuthnAPIKeyDefault {
		hasAuthn := false
		for _, a := range enabled {
			if a == "authn" {
				hasAuthn = true
				break
			}
		}
		if !hasAuthn {
			enabled = append([]string{"authn"}, enabled...)
		}
	}

	response := api.AuthenticatorsResponse{
		Installed:  &installed,
		Configured: &enabled,
		Enabled:    &enabled,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// GetAuthenticatorStatus implements api.ServerInterface
func (s *APIServer) GetAuthenticatorStatus(w http.ResponseWriter, r *http.Request, authenticator api.Authenticator, account api.Account) {
	// Check if authenticator is enabled
	enabled := false
	for _, a := range s.config.Authenticators {
		if a == authenticator || strings.HasPrefix(a, authenticator+"/") {
			enabled = true
			break
		}
	}

	if !enabled && authenticator == "authn" && s.config.AuthnAPIKeyDefault {
		enabled = true
	}

	if !enabled {
		http.Error(w, "Authenticator not enabled", http.StatusNotImplemented)
		return
	}

	status := "ok"
	response := api.AuthenticatorsResponse{
		Status: &status,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// GetAuthenticatorServiceStatus implements api.ServerInterface
func (s *APIServer) GetAuthenticatorServiceStatus(w http.ResponseWriter, r *http.Request, authenticator api.Authenticator, serviceId api.ServiceId, account api.Account) {
	// Check if authenticator service is enabled
	fullName := authenticator + "/" + serviceId
	enabled := false
	for _, a := range s.config.Authenticators {
		if a == fullName {
			enabled = true
			break
		}
	}

	if !enabled {
		status := "error"
		response := api.AuthenticatorsResponse{
			Status: &status,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	status := "ok"
	response := api.AuthenticatorsResponse{
		Status: &status,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// Whoami implements api.ServerInterface
func (s *APIServer) Whoami(w http.ResponseWriter, r *http.Request) {
	id, ok := identity.Get(r.Context())
	if !ok {
		http.Error(w, "Unable to determine identity", http.StatusUnauthorized)
		return
	}

	response := api.WhoAmI{
		Account:  id.Account,
		Username: id.Login,
	}
	if !id.IssuedAt.IsZero() {
		iat := id.IssuedAt
		response.TokenIssuedAt = &iat
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}
