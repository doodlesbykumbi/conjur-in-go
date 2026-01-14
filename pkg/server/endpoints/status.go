package endpoints

import (
	"encoding/json"
	"net/http"
	"os"

	"conjur-in-go/pkg/server"
)

// AuthenticatorsResponse represents the response from /authenticators
type AuthenticatorsResponse struct {
	Installed  []string `json:"installed"`
	Configured []string `json:"configured"`
	Enabled    []string `json:"enabled"`
}

// AuthenticatorStatusResponse represents the response from authenticator status endpoint
type AuthenticatorStatusResponse struct {
	Status string `json:"status"`
}

// RegisterStatusEndpoints registers the status and info endpoints
func RegisterStatusEndpoints(s *server.Server) {
	// GET / - Status page (no auth required) - returns HTML like Ruby
	s.Router.HandleFunc("/", handleStatus()).Methods("GET")

	// GET /authenticators - List authenticators (no auth required)
	s.Router.HandleFunc("/authenticators", handleAuthenticators()).Methods("GET")

	// GET /{authenticator}/{account}/status - Authenticator status (no auth required for now)
	// This matches the Ruby pattern: /:authenticator(/:service_id)/:account/status
	s.Router.HandleFunc("/{authenticator}/{account}/status", handleAuthenticatorStatus()).Methods("GET")
	s.Router.HandleFunc("/{authenticator}/{service_id}/{account}/status", handleAuthenticatorStatus()).Methods("GET")
}

func handleStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		version := os.Getenv("CONJUR_VERSION_DISPLAY")
		if version == "" {
			version = "0.1.0"
		}
		apiVersion := os.Getenv("API_VERSION")
		if apiVersion == "" {
			apiVersion = "5.0.0"
		}

		// Return HTML status page like Ruby Conjur
		html := `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width">
    <title>Conjur Status</title>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
      .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
      h1 { color: #333; margin-top: 0; }
      .status { color: #28a745; font-size: 1.2em; }
      .info { margin-top: 20px; }
      .info dt { font-weight: bold; margin-top: 10px; }
      .info dd { margin-left: 0; color: #666; }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>Conjur Status</h1>
      <p class="status">Your Conjur server is running!</p>
      <dl class="info">
        <dt>Version</dt>
        <dd>` + version + `</dd>
        <dt>API Version</dt>
        <dd>` + apiVersion + `</dd>
      </dl>
    </div>
  </body>
</html>`

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(html))
	}
}

func handleAuthenticators() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// For now, we only support the basic authn authenticator
		response := AuthenticatorsResponse{
			Installed:  []string{"authn"},
			Configured: []string{"authn"},
			Enabled:    []string{"authn"},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}

func handleAuthenticatorStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// For now, all configured authenticators are considered healthy
		// In the future, this would check specific authenticator health
		// (e.g., OIDC provider connectivity, LDAP server availability)
		response := AuthenticatorStatusResponse{
			Status: "ok",
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}
