package openapi

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/doodlesbykumbi/conjur-in-go/api"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/audit"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/authenticator"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/authenticator/authn_jwt"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
)

// jwtStoreAdapter adapts server stores to authn_jwt.Store interface
type jwtStoreAdapter struct {
	secretsStore   store.SecretsStore
	resourcesStore store.ResourcesStore
}

func (a *jwtStoreAdapter) FetchSecret(resourceID string) (string, error) {
	secret, err := a.secretsStore.FetchSecret(resourceID, "")
	if err != nil {
		return "", err
	}
	return string(secret.Value), nil
}

func (a *jwtStoreAdapter) RoleExists(roleID string) bool {
	return a.resourcesStore.RoleExists(roleID)
}

// Login implements api.ServerInterface
func (s *APIServer) Login(w http.ResponseWriter, r *http.Request, account api.Account) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Conjur"`)
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		return
	}

	roleId := roleIdFromLogin(account, username)

	credential, err := s.authStore.GetCredential(roleId)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !s.authStore.ValidateAPIKey(credential, []byte(password)) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(password))
}

// Authenticate implements api.ServerInterface
func (s *APIServer) Authenticate(w http.ResponseWriter, r *http.Request, account api.Account, login api.Login) {
	requestApiKey, err := io.ReadAll(r.Body)
	defer func() { _ = r.Body.Close() }()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var base64Encoding bool
	for _, curEnc := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		curEnc = strings.TrimSpace(curEnc)
		if curEnc == "base64" {
			base64Encoding = true
			break
		}
	}

	roleId := roleIdFromLogin(account, login)
	clientIP := getClientIP(r)

	credential, err := s.authStore.GetCredential(roleId)
	if err != nil {
		audit.Log(audit.AuthenticateEvent{
			RoleID:            roleId,
			ClientIP:          clientIP,
			AuthenticatorName: "authn",
			Success:           false,
			ErrorMessage:      "role not found",
		})
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !s.authStore.ValidateAPIKey(credential, requestApiKey) {
		audit.Log(audit.AuthenticateEvent{
			RoleID:            roleId,
			ClientIP:          clientIP,
			AuthenticatorName: "authn",
			Success:           false,
			ErrorMessage:      "invalid credentials",
		})
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !credential.IsOriginAllowed(clientIP) {
		audit.Log(audit.AuthenticateEvent{
			RoleID:            roleId,
			ClientIP:          clientIP,
			AuthenticatorName: "authn",
			Success:           false,
			ErrorMessage:      "origin is not in the list of allowed IP addresses",
		})
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	audit.Log(audit.AuthenticateEvent{
		RoleID:            roleId,
		ClientIP:          clientIP,
		AuthenticatorName: "authn",
		Success:           true,
	})

	token, err := s.generateToken(account, login)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if base64Encoding {
		w.Header().Add("Content-Encoding", "base64")
		_, _ = base64.NewEncoder(base64.StdEncoding.Strict(), w).Write(token)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, _ = w.Write(token)
}

// AuthenticateJwt implements api.ServerInterface
func (s *APIServer) AuthenticateJwt(w http.ResponseWriter, r *http.Request, serviceId api.ServiceId, account api.Account) {
	// Read JWT token from request body (form-encoded with jwt=<token>)
	body, err := io.ReadAll(r.Body)
	defer func() { _ = r.Body.Close() }()
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Parse as URL-encoded form data
	values, err := url.ParseQuery(string(body))
	if err != nil {
		http.Error(w, "Failed to parse request body", http.StatusBadRequest)
		return
	}

	jwtToken := strings.TrimSpace(values.Get("jwt"))
	if jwtToken == "" {
		http.Error(w, "Missing request param: jwt", http.StatusBadRequest)
		return
	}

	// Check if this authenticator is enabled via config
	authName := "authn-jwt/" + serviceId
	if !s.config.IsAuthenticatorEnabled(authName) {
		http.Error(w, "JWT authenticator not enabled", http.StatusForbidden)
		return
	}

	// Check if the authenticator is actually configured (has webservice in policy)
	webserviceID := account + ":webservice:conjur/authn-jwt/" + serviceId
	webserviceIDWithSlash := webserviceID + "/"
	if !s.resourcesStore.ResourceExists(webserviceID) && !s.resourcesStore.ResourceExists(webserviceIDWithSlash) {
		http.Error(w, "JWT authenticator not configured", http.StatusNotFound)
		return
	}

	// Create JWT authenticator on-demand
	jwtStore := &jwtStoreAdapter{
		secretsStore:   s.secretsStore,
		resourcesStore: s.resourcesStore,
	}
	auth := authn_jwt.NewFromStore(jwtStore, serviceId, account)

	clientIP := getClientIP(r)

	// Authenticate
	input := authenticator.AuthenticatorInput{
		Account:     account,
		ServiceID:   serviceId,
		Login:       "", // No login from URL in this endpoint
		Credentials: []byte(jwtToken),
		ClientIP:    clientIP,
		Request:     r,
	}

	roleID, err := auth.Authenticate(r.Context(), input)
	if err != nil {
		audit.Log(audit.AuthenticateEvent{
			RoleID:            roleID,
			ClientIP:          clientIP,
			AuthenticatorName: authName,
			Success:           false,
			ErrorMessage:      err.Error(),
		})
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
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
	tokenLogin := ""
	if len(parts) == 3 {
		tokenLogin = parts[1] + "/" + parts[2]
	}

	// Detect the encoding to use
	var base64Encoding bool
	for _, curEnc := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		curEnc = strings.TrimSpace(curEnc)
		if curEnc == "base64" {
			base64Encoding = true
			break
		}
	}

	token, err := s.generateToken(account, tokenLogin)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if base64Encoding {
		w.Header().Add("Content-Encoding", "base64")
		_, _ = base64.NewEncoder(base64.StdEncoding.Strict(), w).Write(token)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, _ = w.Write(token)
}

// RotateApiKey implements api.ServerInterface
func (s *APIServer) RotateApiKey(w http.ResponseWriter, r *http.Request, account api.Account, params api.RotateApiKeyParams) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Conjur"`)
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		return
	}

	authRoleId := roleIdFromLogin(account, username)

	credential, err := s.authStore.GetCredential(authRoleId)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !s.authStore.ValidateAPIKey(credential, []byte(password)) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Determine target role
	targetRoleId := authRoleId
	if params.Role != nil && *params.Role != "" {
		targetRoleId = *params.Role
		// Check if user has permission to rotate this role's key
		if targetRoleId != authRoleId {
			// Must be admin or have update permission on the role
			if !s.authzStore.IsRoleAllowedTo(authRoleId, "update", targetRoleId) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
	}

	newApiKey, err := s.authStore.RotateAPIKey(targetRoleId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(newApiKey))
}

// ChangePassword implements api.ServerInterface
func (s *APIServer) ChangePassword(w http.ResponseWriter, r *http.Request, account api.Account) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Conjur"`)
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		return
	}

	// Hosts cannot change passwords
	if strings.HasPrefix(username, "host/") {
		http.Error(w, "Hosts cannot change passwords", http.StatusForbidden)
		return
	}

	roleId := roleIdFromLogin(account, username)

	credential, err := s.authStore.GetCredential(roleId)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !s.authStore.ValidateAPIKey(credential, []byte(password)) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	newPassword, err := io.ReadAll(r.Body)
	defer func() { _ = r.Body.Close() }()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.authStore.UpdatePassword(roleId, newPassword); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
