package endpoints

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"

	"conjur-in-go/pkg/authenticator"
	"conjur-in-go/pkg/server"

	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

// InfoResponse represents the response from / when JSON is requested
type InfoResponse struct {
	Version    string `json:"version"`
	APIVersion string `json:"api_version"`
}

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
	db := s.DB

	// GET / - Status page (no auth required) - returns HTML like Ruby
	s.Router.HandleFunc("/", handleStatus()).Methods("GET")

	// GET /authenticators - List authenticators (no auth required)
	s.Router.HandleFunc("/authenticators", handleAuthenticators()).Methods("GET")

	// GET /{authenticator}/{account}/status - Authenticator status (no auth required for now)
	// This matches the Ruby pattern: /:authenticator(/:service_id)/:account/status
	s.Router.HandleFunc("/{authenticator}/{account}/status", handleAuthenticatorStatus(db)).Methods("GET")
	s.Router.HandleFunc("/{authenticator}/{service_id}/{account}/status", handleAuthenticatorStatus(db)).Methods("GET")
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

		// Check if JSON is requested via Accept header or format query param
		accept := r.Header.Get("Accept")
		format := r.URL.Query().Get("format")
		if format == "json" || strings.Contains(accept, "application/json") {
			response := InfoResponse{
				Version:    version,
				APIVersion: apiVersion,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)
			return
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
		registry := authenticator.DefaultRegistry

		installed := registry.Installed()
		enabled := registry.Enabled()

		// Sort for consistent output
		sort.Strings(installed)
		sort.Strings(enabled)

		// For now, configured = enabled (in future, read from DB)
		response := AuthenticatorsResponse{
			Installed:  installed,
			Configured: enabled,
			Enabled:    enabled,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}

// AuthenticatorStatusErrorResponse represents an error response from authenticator status
type AuthenticatorStatusErrorResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

func handleAuthenticatorStatus(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		authnType := vars["authenticator"]
		account := vars["account"]
		serviceID := vars["service_id"]

		// Check 1: Database connectivity
		if err := db.Exec("SELECT 1").Error; err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(AuthenticatorStatusErrorResponse{
				Status: "error",
				Error:  "database connectivity check failed",
			})
			return
		}

		// Check 2: Authenticator is enabled
		registry := authenticator.DefaultRegistry
		authnName := authnType
		if serviceID != "" {
			authnName = authnType + "/" + serviceID
		}

		if !registry.IsEnabled(authnName) && !registry.IsEnabled(authnType) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			_ = json.NewEncoder(w).Encode(AuthenticatorStatusErrorResponse{
				Status: "error",
				Error:  "authenticator is not enabled",
			})
			return
		}

		// Check 3: For authn-jwt, verify required variables exist
		if authnType == "authn-jwt" && serviceID != "" {
			// Check if public-keys or jwks-uri variable exists
			publicKeysVar := account + ":variable:conjur/authn-jwt/" + serviceID + "/public-keys"
			jwksURIVar := account + ":variable:conjur/authn-jwt/" + serviceID + "/jwks-uri"

			var count int64
			db.Raw(`SELECT COUNT(*) FROM resources WHERE resource_id IN (?, ?)`, publicKeysVar, jwksURIVar).Scan(&count)

			if count == 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotImplemented)
				_ = json.NewEncoder(w).Encode(AuthenticatorStatusErrorResponse{
					Status: "error",
					Error:  "authenticator is not configured: missing public-keys or jwks-uri variable",
				})
				return
			}
		}

		// All checks passed
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthenticatorStatusResponse{
			Status: "ok",
		})
	}
}
