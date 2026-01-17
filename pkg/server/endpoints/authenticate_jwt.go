package endpoints

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/audit"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/authenticator"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/authenticator/authn_jwt"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/config"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo/store"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/utils"
)

// RegisterJWTAuthenticateEndpoint registers the JWT authentication endpoints
func RegisterJWTAuthenticateEndpoint(s *server.Server) {
	keystore := s.Keystore
	router := s.Router

	// POST /authn-jwt/{service_id}/{account}/authenticate - Authenticate with JWT token
	router.HandleFunc(
		"/authn-jwt/{service_id}/{account}/authenticate",
		handleJWTAuthenticate(s, keystore),
	).Methods("POST")

	// POST /authn-jwt/{service_id}/{account}/{id}/authenticate - Authenticate with JWT token (identity in URL)
	router.HandleFunc(
		"/authn-jwt/{service_id}/{account}/{id}/authenticate",
		handleJWTAuthenticate(s, keystore),
	).Methods("POST")
}

// handleJWTAuthenticate handles JWT authentication requests
func handleJWTAuthenticate(s *server.Server, keystore *store.KeyStore) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		vars := mux.Vars(request)
		account := vars["account"]
		serviceID := vars["service_id"]
		login := vars["id"] // Optional - identity from URL

		// Read JWT token from request body
		// Ruby expects form-encoded body with jwt=<token> field
		body, err := io.ReadAll(request.Body)
		defer func() { _ = request.Body.Close() }()
		if err != nil {
			http.Error(writer, "Failed to read request body", http.StatusBadRequest)
			return
		}

		// Parse as URL-encoded form data (matches Ruby's URI.decode_www_form)
		values, err := url.ParseQuery(string(body))
		if err != nil {
			http.Error(writer, "Failed to parse request body", http.StatusBadRequest)
			return
		}

		jwtToken := strings.TrimSpace(values.Get("jwt"))
		if jwtToken == "" {
			http.Error(writer, "Missing request param: jwt", http.StatusBadRequest)
			return
		}

		// Check if this authenticator is enabled via config
		authName := "authn-jwt/" + serviceID
		cfg := config.Get()
		if !cfg.IsAuthenticatorEnabled(authName) {
			http.Error(writer, "JWT authenticator not enabled", http.StatusForbidden)
			return
		}

		// Create JWT authenticator on-demand - it reads config from DB
		auth := authn_jwt.NewFromDB(s.DB, s.Cipher, serviceID, account)

		// Check if the authenticator is actually configured (has webservice in policy)
		// The webservice can be created with or without trailing slash depending on policy format
		var count int64
		webservicePattern := account + ":webservice:conjur/authn-jwt/" + serviceID + "%"
		if err := s.DB.Raw(`SELECT COUNT(*) FROM resources WHERE resource_id LIKE ?`, webservicePattern).Scan(&count).Error; err != nil || count == 0 {
			http.Error(writer, "JWT authenticator not configured", http.StatusNotFound)
			return
		}

		clientIP := request.RemoteAddr
		if forwarded := request.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		// Authenticate
		input := authenticator.AuthenticatorInput{
			Account:     account,
			ServiceID:   serviceID,
			Login:       login,
			Credentials: []byte(jwtToken),
			ClientIP:    clientIP,
			Request:     request,
		}

		roleID, err := auth.Authenticate(context.Background(), input)
		if err != nil {
			audit.Log(audit.AuthenticateEvent{
				RoleID:            roleID,
				ClientIP:          clientIP,
				AuthenticatorName: authName,
				Success:           false,
				ErrorMessage:      err.Error(),
			})
			http.Error(writer, "Authentication failed", http.StatusUnauthorized)
			return
		}

		// Log successful authentication
		audit.Log(audit.AuthenticateEvent{
			RoleID:            roleID,
			ClientIP:          clientIP,
			AuthenticatorName: authName,
			Success:           true,
		})

		// Extract login from roleID for token claims
		parts := strings.SplitN(roleID, ":", 3)
		tokenLogin := login
		if len(parts) == 3 {
			tokenLogin = parts[1] + "/" + parts[2]
		}

		// Detect the encoding to use
		var base64Encoding bool
		for _, curEnc := range strings.Split(request.Header.Get("Accept-Encoding"), ",") {
			curEnc = strings.TrimSpace(curEnc)
			if curEnc == "base64" {
				base64Encoding = true
				break
			}
		}

		// Generate Conjur token with TTL from config
		// JWT authenticated identities are typically hosts
		now := time.Now()
		tokenTTL := cfg.HostTokenTTL()

		newclaimsMap := map[string]interface{}{
			"iat": now.Unix(),
			"exp": now.Add(tokenTTL).Unix(),
			"sub": tokenLogin,
		}
		key, err := keystore.ByAccount(account)
		if err != nil {
			http.Error(writer, fmt.Sprintf("Error on key by account: %s", err.Error()), http.StatusBadRequest)
			return
		}

		newheaderMap := map[string]interface{}{
			"alg": "conjur.org/slosilo/v2",
			"kid": key.Fingerprint(),
		}

		newheader := utils.ToJson(newheaderMap)
		newclaims := utils.ToJson(newclaimsMap)

		newsalt, _ := slosilo.RandomBytes(32)
		stringToSign := strings.Join(
			[]string{
				base64.URLEncoding.EncodeToString([]byte(newheader)),
				base64.URLEncoding.EncodeToString([]byte(newclaims)),
			},
			".",
		)

		newsignature, signErr := key.Sign([]byte(stringToSign), newsalt)
		if signErr != nil {
			http.Error(writer, fmt.Sprintf("Error signing token: %s", signErr.Error()), http.StatusInternalServerError)
			return
		}

		newjwt := map[string]string{
			"protected": base64.URLEncoding.EncodeToString([]byte(newheader)),
			"payload":   base64.URLEncoding.EncodeToString([]byte(newclaims)),
			"signature": base64.URLEncoding.EncodeToString(newsignature),
		}

		newjwtJSON := []byte(utils.ToJson(newjwt))

		if base64Encoding {
			writer.Header().Add("Content-Encoding", "base64")
			_, _ = base64.NewEncoder(base64.StdEncoding.Strict(), writer).Write(newjwtJSON)
			return
		}

		writer.Header().Add("Content-Type", "application/json")
		_, _ = writer.Write(newjwtJSON)
	}
}
