package middleware

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"

	"conjur-in-go/pkg/slosilo"
	"conjur-in-go/pkg/slosilo/store"
)

var tokenRegex = regexp.MustCompile(`^Token token="(.*)"`)

// JWTAuthenticator is middleware that validates JWT tokens
type JWTAuthenticator struct {
	Keystore *store.KeyStore
}

// NewJWTAuthenticator creates a new JWT authenticator middleware
func NewJWTAuthenticator(keystore *store.KeyStore) *JWTAuthenticator {
	return &JWTAuthenticator{Keystore: keystore}
}

// RoleID constructs a role ID from account and login
func RoleID(account string, login string) string {
	tokens := strings.Split(login, "/")
	if len(tokens) == 1 {
		tokens = []string{"user", login}
	}

	return strings.Join(
		[]string{
			account, tokens[0], strings.Join(tokens[1:], "/"),
		},
		":",
	)
}

// Middleware returns an HTTP middleware that validates JWT tokens
func (j *JWTAuthenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if len(authHeader) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Authorization missing"))
			return
		}

		tokenMatches := tokenRegex.FindStringSubmatch(authHeader)

		if len(tokenMatches) != 2 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Malformed authorization header"))
			return
		}

		tokenStr, err := base64.URLEncoding.DecodeString(tokenMatches[1])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Malformed authorization token"))
			return
		}

		authToken, err := slosilo.NewParsedToken(tokenStr)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Malformed authorization token"))
			return
		}

		if authToken.Expired() {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Token expired"))
			return
		}

		account, verified := authToken.Verify(func(kid string, protected, payload, signature []byte) (string, bool) {
			stringToSign := strings.Join(
				[]string{
					base64.URLEncoding.EncodeToString(protected),
					base64.URLEncoding.EncodeToString(payload),
				},
				".",
			)

			key, err := j.Keystore.ByFingerprint(kid)
			if err != nil {
				return "", false
			}
			err = key.Verify([]byte(stringToSign), signature)
			if err != nil {
				return "", false
			}

			return key.Account(), true
		})

		if !verified {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Invalid signature"))
			return
		}

		roleId := RoleID(account, authToken.Sub())
		ctx := r.Context()
		ctx = context.WithValue(ctx, "roleId", roleId)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
