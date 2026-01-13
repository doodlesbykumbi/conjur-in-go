package endpoints

import (
	"encoding/json"
	"net/http"

	"conjur-in-go/pkg/server"
)

// StatusResponse represents the response from the / status endpoint
type StatusResponse struct {
	Status        string            `json:"status"`
	Version       string            `json:"version,omitempty"`
	Configuration map[string]string `json:"configuration,omitempty"`
}

// AuthenticatorsResponse represents the response from /authenticators
type AuthenticatorsResponse struct {
	Installed  []string `json:"installed"`
	Configured []string `json:"configured"`
	Enabled    []string `json:"enabled"`
}

// RegisterStatusEndpoints registers the status and info endpoints
func RegisterStatusEndpoints(s *server.Server) {
	// GET / - Status endpoint (no auth required)
	s.Router.HandleFunc("/", handleStatus()).Methods("GET")

	// GET /authenticators - List authenticators (no auth required)
	s.Router.HandleFunc("/authenticators", handleAuthenticators()).Methods("GET")
}

func handleStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response := StatusResponse{
			Status:  "ok",
			Version: "0.1.0", // TODO: make this configurable
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
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
		json.NewEncoder(w).Encode(response)
	}
}
