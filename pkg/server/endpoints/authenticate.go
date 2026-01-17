package endpoints

import (
	"crypto/subtle"
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
	"github.com/doodlesbykumbi/conjur-in-go/pkg/model"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
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

func RegisterAuthenticateEndpoint(server *server.Server) {
	keystore := server.Keystore
	router := server.Router
	db := server.DB

	// GET /authn/{account}/login - Login with Basic Auth, returns API key
	router.HandleFunc(
		"/authn/{account}/login",
		func(writer http.ResponseWriter, request *http.Request) {
			vars := mux.Vars(request)
			account := vars["account"]

			// Parse Basic Auth
			username, password, ok := request.BasicAuth()
			if !ok {
				writer.Header().Set("WWW-Authenticate", `Basic realm="Conjur"`)
				http.Error(writer, "Authorization required", http.StatusUnauthorized)
				return
			}

			// Build role ID from username
			roleId := roleIdFromLogin(account, username)

			// Validate credentials
			credential := model.Credential{}
			tx := db.Where(&struct{ RoleId string }{RoleId: roleId}).First(&credential)
			if tx.Error != nil {
				http.Error(writer, "Invalid credentials", http.StatusUnauthorized)
				return
			}

			// Compare password (API key) with stored credential
			if ok := subtle.ConstantTimeCompare(credential.ApiKey, []byte(password)); ok != 1 {
				http.Error(writer, "Invalid credentials", http.StatusUnauthorized)
				return
			}

			// Return the API key (same as password for API key auth)
			writer.Header().Set("Content-Type", "text/plain")
			_, _ = writer.Write([]byte(password))
		},
	).Methods("GET")

	// PUT /authn/{account}/api_key - Rotate API key (requires Basic Auth with current API key)
	router.HandleFunc(
		"/authn/{account}/api_key",
		func(writer http.ResponseWriter, request *http.Request) {
			vars := mux.Vars(request)
			account := vars["account"]

			// Parse Basic Auth - user must authenticate with current API key
			username, password, ok := request.BasicAuth()
			if !ok {
				writer.Header().Set("WWW-Authenticate", `Basic realm="Conjur"`)
				http.Error(writer, "Authorization required", http.StatusUnauthorized)
				return
			}

			// Check for ?role= parameter to rotate another user's key
			targetRole := request.URL.Query().Get("role")
			var roleId string
			var authenticatedRoleId string

			authenticatedRoleId = roleIdFromLogin(account, username)

			if targetRole != "" {
				// Rotating another role's API key - need update permission
				roleId = roleIdFromLogin(account, targetRole)
			} else {
				// Rotating own API key
				roleId = authenticatedRoleId
			}

			// Validate current credentials
			credential := model.Credential{}
			tx := db.Where(&struct{ RoleId string }{RoleId: authenticatedRoleId}).First(&credential)
			if tx.Error != nil {
				http.Error(writer, "Invalid credentials", http.StatusUnauthorized)
				return
			}

			// Compare password (API key) with stored credential
			if ok := subtle.ConstantTimeCompare(credential.ApiKey, []byte(password)); ok != 1 {
				http.Error(writer, "Invalid credentials", http.StatusUnauthorized)
				return
			}

			// If rotating another role's key, check update permission
			if targetRole != "" && roleId != authenticatedRoleId {
				resourceId := roleId // The role is also a resource
				if !isRoleAllowedTo(db, authenticatedRoleId, "update", resourceId) {
					http.Error(writer, "Insufficient privilege", http.StatusForbidden)
					return
				}
			}

			// Get the target credential
			targetCredential := model.Credential{}
			tx = db.Where(&struct{ RoleId string }{RoleId: roleId}).First(&targetCredential)
			if tx.Error != nil {
				http.Error(writer, "Role not found or has no credentials", http.StatusNotFound)
				return
			}

			// Generate new API key
			newApiKey, err := model.GenerateAPIKey()
			if err != nil {
				http.Error(writer, "Failed to generate API key", http.StatusInternalServerError)
				return
			}

			// Encrypt the new API key
			encryptedKey, err := server.Cipher.Encrypt([]byte(roleId), newApiKey)
			if err != nil {
				http.Error(writer, "Failed to encrypt API key", http.StatusInternalServerError)
				return
			}

			// Update the credential
			tx = db.Model(&model.Credential{}).Where("role_id = ?", roleId).Updates(map[string]interface{}{
				"api_key":        encryptedKey,
				"encrypted_hash": encryptedKey, // Same as api_key for compatibility
			})
			if tx.Error != nil {
				http.Error(writer, "Failed to update API key", http.StatusInternalServerError)
				return
			}

			// Return the new API key
			writer.Header().Set("Content-Type", "text/plain")
			_, _ = writer.Write(newApiKey)
		},
	).Methods("PUT")

	// PUT /authn/{account}/password - Update password (requires Basic Auth)
	router.HandleFunc(
		"/authn/{account}/password",
		func(writer http.ResponseWriter, request *http.Request) {
			vars := mux.Vars(request)
			account := vars["account"]

			// Parse Basic Auth - user must authenticate with current API key
			username, password, ok := request.BasicAuth()
			if !ok {
				writer.Header().Set("WWW-Authenticate", `Basic realm="Conjur"`)
				http.Error(writer, "Authorization required", http.StatusUnauthorized)
				return
			}

			// Hosts cannot change passwords
			if strings.HasPrefix(username, "host/") {
				http.Error(writer, "Hosts cannot change passwords", http.StatusForbidden)
				return
			}

			roleId := roleIdFromLogin(account, username)

			// Validate current credentials
			credential := model.Credential{}
			tx := db.Where(&struct{ RoleId string }{RoleId: roleId}).First(&credential)
			if tx.Error != nil {
				http.Error(writer, "Invalid credentials", http.StatusUnauthorized)
				return
			}

			// Compare password (API key) with stored credential
			if ok := subtle.ConstantTimeCompare(credential.ApiKey, []byte(password)); ok != 1 {
				http.Error(writer, "Invalid credentials", http.StatusUnauthorized)
				return
			}

			// Read new password from body
			newPassword, err := io.ReadAll(request.Body)
			defer func() { _ = request.Body.Close() }()
			if err != nil {
				http.Error(writer, "Failed to read request body", http.StatusBadRequest)
				return
			}

			if len(newPassword) == 0 {
				http.Error(writer, "New password is required", http.StatusBadRequest)
				return
			}

			// Encrypt the new password as the API key
			encryptedKey, err := server.Cipher.Encrypt([]byte(roleId), newPassword)
			if err != nil {
				http.Error(writer, "Failed to encrypt password", http.StatusInternalServerError)
				return
			}

			// Update the credential
			tx = db.Model(&model.Credential{}).Where("role_id = ?", roleId).Updates(map[string]interface{}{
				"api_key":        encryptedKey,
				"encrypted_hash": encryptedKey,
			})
			if tx.Error != nil {
				http.Error(writer, "Failed to update password", http.StatusInternalServerError)
				return
			}

			writer.WriteHeader(http.StatusNoContent)
		},
	).Methods("PUT")

	// POST /authn/{account}/{login}/authenticate - Authenticate with API key, returns JWT
	router.HandleFunc(
		"/authn/{account}/{login}/authenticate",
		func(writer http.ResponseWriter, request *http.Request) {
			requestApiKey, err := io.ReadAll(request.Body)
			defer func() { _ = request.Body.Close() }()
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			vars := mux.Vars(request)
			account := vars["account"]
			login, err := url.PathUnescape(vars["login"])
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			// Detect the encoding to use
			var base64Encoding bool
			for _, curEnc := range strings.Split(request.Header.Get(acceptEncoding), ",") {
				curEnc = strings.TrimSpace(curEnc)
				if curEnc == "base64" {
					base64Encoding = true
					break
				}
			}

			roleId := roleIdFromLogin(account, login)
			clientIP := request.RemoteAddr
			if forwarded := request.Header.Get("X-Forwarded-For"); forwarded != "" {
				clientIP = forwarded
			}

			// Validate API key
			credential := model.Credential{}
			tx := db.Where(&struct{ RoleId string }{RoleId: roleId}).First(&credential)
			err = tx.Error
			if err != nil {
				audit.Log(audit.AuthenticateEvent{
					RoleID:            roleId,
					ClientIP:          clientIP,
					AuthenticatorName: "authn",
					Success:           false,
					ErrorMessage:      "role not found",
				})
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}

			if ok := subtle.ConstantTimeCompare(credential.ApiKey, requestApiKey); ok != 1 {
				audit.Log(audit.AuthenticateEvent{
					RoleID:            roleId,
					ClientIP:          clientIP,
					AuthenticatorName: "authn",
					Success:           false,
					ErrorMessage:      "invalid credentials",
				})
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Check CIDR restrictions
			if !credential.IsOriginAllowed(clientIP) {
				audit.Log(audit.AuthenticateEvent{
					RoleID:            roleId,
					ClientIP:          clientIP,
					AuthenticatorName: "authn",
					Success:           false,
					ErrorMessage:      "origin is not in the list of allowed IP addresses",
				})
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Log successful authentication
			audit.Log(audit.AuthenticateEvent{
				RoleID:            roleId,
				ClientIP:          clientIP,
				AuthenticatorName: "authn",
				Success:           true,
			})

			// Get token TTL from config based on role type
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
				// TODO: Generally this needs to be hidden from the response and should probably be logged
				//
				// Errors like: Error on key by account: cipher: message authentication failed
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

			// Conjur in ruby forces the thing being signed to be encoded in ASCII-8BIT
			// https://github.com/cyberark/slosilo/blob/master/lib/slosilo/key.rb#L198-L202
			//
			// Go uses UTF-8 as the standard encoding.
			// TODO: confirm if these are altogether compatible, and there are no edge cases where a token signed by Ruby
			// can't be verified by Go and vice-versa
			newsignature, signErr := key.Sign(
				[]byte(
					stringToSign,
				),
				newsalt,
			)
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
		},
	).Methods("POST")
}
