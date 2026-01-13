package endpoints

import (
	"encoding/json"
	"net/http"
	"strings"

	"conjur-in-go/pkg/server"
	"conjur-in-go/pkg/server/middleware"
)

// WhoamiResponse represents the response from the /whoami endpoint
type WhoamiResponse struct {
	Account  string `json:"account"`
	Username string `json:"username"`
	TokenIAT int64  `json:"token_iat,omitempty"`
}

// RegisterWhoamiEndpoint registers the /whoami endpoint
func RegisterWhoamiEndpoint(s *server.Server) {
	jwtMiddleware := middleware.NewJWTAuthenticator(s.Keystore)

	// Create a subrouter for /whoami that uses JWT auth
	whoamiRouter := s.Router.PathPrefix("/whoami").Subrouter()
	whoamiRouter.Use(jwtMiddleware.Middleware)

	whoamiRouter.HandleFunc("", handleWhoami()).Methods("GET")
}

func handleWhoami() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get roleId from context (set by JWT middleware)
		roleId, ok := r.Context().Value("roleId").(string)
		if !ok || roleId == "" {
			http.Error(w, "Unable to determine identity", http.StatusUnauthorized)
			return
		}

		// Parse roleId: account:kind:identifier
		parts := strings.SplitN(roleId, ":", 3)
		if len(parts) < 3 {
			http.Error(w, "Invalid role ID format", http.StatusInternalServerError)
			return
		}

		account := parts[0]
		kind := parts[1]
		identifier := parts[2]

		// Format username as kind/identifier (e.g., "user/admin" or "host/myapp")
		var username string
		if kind == "user" {
			username = identifier
		} else {
			username = kind + "/" + identifier
		}

		response := WhoamiResponse{
			Account:  account,
			Username: username,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}
