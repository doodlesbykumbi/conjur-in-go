package endpoints

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/audit"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/config"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
	slstore "github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo/store"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/utils"
)

const acceptEncoding string = "Accept-Encoding"

func roleIdFromLogin(account string, login string) string {
	tokens := strings.SplitN(login, "/", 2)
	if len(tokens) == 1 {
		tokens = []string{"user", tokens[0]}
	}
	tokens = append([]string{account}, tokens...)
	return strings.Join(tokens, ":")
}

func RegisterAuthenticateEndpoint(srv *server.Server) {
	authStore := srv.AuthenticateStore
	authzStore := srv.AuthzStore
	keystore := srv.Keystore
	router := srv.Router

	// GET /authn/{account}/login - Login with Basic Auth, returns API key
	router.HandleFunc(
		"/authn/{account}/login",
		handleLogin(authStore),
	).Methods("GET")

	// PUT /authn/{account}/api_key - Rotate API key
	router.HandleFunc(
		"/authn/{account}/api_key",
		handleRotateAPIKey(authStore, authzStore),
	).Methods("PUT")

	// PUT /authn/{account}/password - Update password
	router.HandleFunc(
		"/authn/{account}/password",
		handleUpdatePassword(authStore),
	).Methods("PUT")

	// POST /authn/{account}/{login}/authenticate - Authenticate with API key, returns JWT
	router.HandleFunc(
		"/authn/{account}/{login}/authenticate",
		handleAuthenticate(authStore, keystore),
	).Methods("POST")
}

func handleLogin(authStore store.AuthenticateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]

		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Conjur"`)
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}

		roleId := roleIdFromLogin(account, username)

		credential, err := authStore.GetCredential(roleId)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		if !authStore.ValidateAPIKey(credential, []byte(password)) {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(password))
	}
}

func handleRotateAPIKey(authStore store.AuthenticateStore, authzStore store.AuthzStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]

		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Conjur"`)
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}

		targetRole := r.URL.Query().Get("role")
		authenticatedRoleId := roleIdFromLogin(account, username)

		var roleId string
		if targetRole != "" {
			roleId = roleIdFromLogin(account, targetRole)
		} else {
			roleId = authenticatedRoleId
		}

		credential, err := authStore.GetCredential(authenticatedRoleId)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		if !authStore.ValidateAPIKey(credential, []byte(password)) {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		if targetRole != "" && roleId != authenticatedRoleId {
			if !authzStore.IsRoleAllowedTo(authenticatedRoleId, "update", roleId) {
				http.Error(w, "Insufficient privilege", http.StatusForbidden)
				return
			}
		}

		_, err = authStore.GetCredential(roleId)
		if err != nil {
			http.Error(w, "Role not found or has no credentials", http.StatusNotFound)
			return
		}

		newApiKey, err := authStore.RotateAPIKey(roleId)
		if err != nil {
			http.Error(w, "Failed to rotate API key", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(newApiKey)
	}
}

func handleUpdatePassword(authStore store.AuthenticateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]

		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Conjur"`)
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}

		if strings.HasPrefix(username, "host/") {
			http.Error(w, "Hosts cannot change passwords", http.StatusForbidden)
			return
		}

		roleId := roleIdFromLogin(account, username)

		credential, err := authStore.GetCredential(roleId)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		if !authStore.ValidateAPIKey(credential, []byte(password)) {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		newPassword, err := io.ReadAll(r.Body)
		defer func() { _ = r.Body.Close() }()
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		if len(newPassword) == 0 {
			http.Error(w, "New password is required", http.StatusBadRequest)
			return
		}

		if err := authStore.UpdatePassword(roleId, newPassword); err != nil {
			http.Error(w, "Failed to update password", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func handleAuthenticate(authStore store.AuthenticateStore, keystore *slstore.KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestApiKey, err := io.ReadAll(r.Body)
		defer func() { _ = r.Body.Close() }()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		vars := mux.Vars(r)
		account := vars["account"]
		login, err := url.PathUnescape(vars["login"])
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var base64Encoding bool
		for _, curEnc := range strings.Split(r.Header.Get(acceptEncoding), ",") {
			curEnc = strings.TrimSpace(curEnc)
			if curEnc == "base64" {
				base64Encoding = true
				break
			}
		}

		roleId := roleIdFromLogin(account, login)
		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		credential, err := authStore.GetCredential(roleId)
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

		if !authStore.ValidateAPIKey(credential, requestApiKey) {
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

		cfg := config.Get()
		var tokenTTL time.Duration
		if strings.HasPrefix(login, "host/") {
			tokenTTL = cfg.HostTokenTTL()
		} else {
			tokenTTL = cfg.UserTokenTTL()
		}

		now := time.Now()
		newclaimsMap := map[string]interface{}{
			"iat": now.Unix(),
			"exp": now.Add(tokenTTL).Unix(),
			"sub": login,
		}
		key, err := keystore.ByAccount(account)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error on key by account: %s", err.Error()), http.StatusBadRequest)
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

		newsignature, signErr := key.Sign(
			[]byte(stringToSign),
			newsalt,
		)
		if signErr != nil {
			http.Error(w, fmt.Sprintf("Error signing token: %s", signErr.Error()), http.StatusInternalServerError)
			return
		}
		newjwt := map[string]string{
			"protected": base64.URLEncoding.EncodeToString([]byte(newheader)),
			"payload":   base64.URLEncoding.EncodeToString([]byte(newclaims)),
			"signature": base64.URLEncoding.EncodeToString(newsignature),
		}

		newjwtJSON := []byte(utils.ToJson(newjwt))

		if base64Encoding {
			w.Header().Add("Content-Encoding", "base64")
			_, _ = base64.NewEncoder(base64.StdEncoding.Strict(), w).Write(newjwtJSON)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		_, _ = w.Write(newjwtJSON)
	}
}
