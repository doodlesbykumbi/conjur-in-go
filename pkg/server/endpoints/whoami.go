package endpoints

import (
	"encoding/json"
	"net/http"

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
		// Get token info from context (set by JWT middleware)
		tokenInfo, ok := middleware.GetTokenInfo(r.Context())
		if !ok {
			http.Error(w, "Unable to determine identity", http.StatusUnauthorized)
			return
		}

		response := WhoamiResponse{
			Account:  tokenInfo.Account,
			Username: tokenInfo.Login,
			TokenIAT: tokenInfo.IssuedAt.Unix(),
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}
