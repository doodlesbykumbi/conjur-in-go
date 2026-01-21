package endpoints

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/config"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"

	"github.com/gorilla/mux"
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
	healthStore := s.HealthStore
	resourcesStore := s.ResourcesStore
	cfg := s.Config

	// GET / - Status page (no auth required) - returns HTML like Ruby
	s.Router.HandleFunc("/", handleStatus()).Methods("GET")

	// GET /authenticators - List authenticators (no auth required)
	s.Router.HandleFunc("/authenticators", handleAuthenticators(cfg)).Methods("GET")

	// GET /{authenticator}/{account}/status - Authenticator status (no auth required for now)
	// This matches the Ruby pattern: /:authenticator(/:service_id)/:account/status
	s.Router.HandleFunc("/{authenticator}/{account}/status", handleAuthenticatorStatus(healthStore, resourcesStore, cfg)).Methods("GET")
	s.Router.HandleFunc("/{authenticator}/{service_id}/{account}/status", handleAuthenticatorStatus(healthStore, resourcesStore, cfg)).Methods("GET")
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
		fipsMode := os.Getenv("FIPS_MODE_STATUS")
		if fipsMode == "" {
			fipsMode = "N/A"
		}

		// Check if JSON is requested via Accept header or format query param
		accept := r.Header.Get("Accept")
		format := r.URL.Query().Get("format")
		if format == "json" || strings.Contains(accept, "application/json") {
			// Match Ruby: {"version":"..."}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"version": version})
			return
		}

		// Return HTML status page matching Ruby Conjur template
		html := `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width">

    <link rel="stylesheet" href="/css/status-page.css">
    <title>Conjur Status</title>
  </head>
  <body>

    <header>
      <div class="logo-cont">
        <img src="/img/conjur-logo-all-white.svg"/>
      </div>
      <div class="links-cont">
        <a href="https://discuss.cyberarkcommons.org" target="_blank">Discourse</a>
        |
        <a href="https://github.com/cyberark/conjur" target="_blank">Github</a>
      </div>
    </header>

    <main>
      <div class="left-panel">
        <h1>Status</h1>
        <p class="status-text">Your Conjur server is running!</p>

        <h2>Security Check:</h2>
        <p>Does your browser show a green lock icon on the left side of the address bar?</p>

        <dl>
          <dt>Green lock:</dt>
          <dd>Good, Conjur is secured and authenticated.</dd>
          <dt>Yellow lock or green with warning sign:</dt>
          <dd>
          OK, Conjur is secured but not authenticated. Send your Conjur admin to the
          <a href="https://www.conjur.org/tutorials/nginx.html" title="Tutorial - NGINX Proxy">
            Conjur+TLS guide
          </a>
          to learn how to use your own certificate &amp; upgrade to green lock.
          </dd>
          <dt>Red broken lock or no lock:</dt>
          <dd>
          Conjur is running in insecure development mode. Don't put any
          production secrets in there! Visit the
          <a href="https://www.conjur.org/tutorials/nginx.html" title="Tutorial - NGINX Proxy">
            Conjur+TLS guide
          </a>
          to learn how to deploy Conjur securely &amp;
          <a href="https://discuss.cyberarkcommons.org">contact CyberArk</a>
          with any questions.
          </dd>
        </dl>
      </div>

      <div class="right-panel">
        <dl>
          <dt>Details:</dt>
          <dd>Version ` + version + `</dd>
          <dd>API Version <a href="https://github.com/cyberark/conjur-openapi-spec/releases/tag/v` + apiVersion + `">` + apiVersion + `</a>
          <dd>FIPS mode ` + fipsMode + `</a>
          <dt>More Info:</dt>
          <dd>
            <ul>
              <li><a href="https://docs.conjur.org/Latest/en/Content/Resources/_TopNav/cc_Home.htm" target="_blank">Documentation</a></li>
              <li><a href="https://www.cyberark.com/products/privileged-account-security-solution/application-access-manager/" target="_blank">CyberArk Application Access Manager</a></li>
              <li><a href="https://www.conjur.org/" target="_blank">Conjur.org</a></li>
            </ul>
          </dd>
        </dl>

      </div>
    </main>

    <footer>
      <div class="logo-cont">
        <img src="/img/cyberark-white.png"/>
      </div>
      <p class="copyright">
        Conjur Open Source copyright 2020 CyberArk. All rights reserved.
      </p>
    </footer>

  </body>
</html>
`

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(html))
	}
}

func handleAuthenticators(cfg *config.ConjurConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Installed = all valid authenticator types
		installed := make([]string, len(config.ValidAuthenticators))
		copy(installed, config.ValidAuthenticators)

		// Enabled = from config
		enabled := cfg.Authenticators
		if cfg.AuthnAPIKeyDefault {
			// Add "authn" if not already present
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

		// Sort for consistent output
		sort.Strings(installed)
		sort.Strings(enabled)

		// For now, configured = enabled
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

func handleAuthenticatorStatus(healthStore store.HealthStore, resourcesStore store.ResourcesStore, cfg *config.ConjurConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		authnType := vars["authenticator"]
		account := vars["account"]
		serviceID := vars["service_id"]

		// Check 1: Database connectivity
		if err := healthStore.CheckConnectivity(); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(AuthenticatorStatusErrorResponse{
				Status: "error",
				Error:  "database connectivity check failed",
			})
			return
		}

		// Check 2: Authenticator is enabled
		authnName := authnType
		if serviceID != "" {
			authnName = authnType + "/" + serviceID
		}

		if !cfg.IsAuthenticatorEnabled(authnName) && !cfg.IsAuthenticatorEnabled(authnType) {
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

			if !resourcesStore.ResourceExists(publicKeysVar) && !resourcesStore.ResourceExists(jwksURIVar) {
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
