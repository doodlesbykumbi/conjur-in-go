package openapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/doodlesbykumbi/conjur-in-go/api"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/config"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/policy/loader"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
	slstore "github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo/store"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/utils"
)

// APIServer implements api.ServerInterface
type APIServer struct {
	authStore      store.AuthenticateStore
	authzStore     store.AuthzStore
	secretsStore   store.SecretsStore
	resourcesStore store.ResourcesStore
	policyStore    store.PolicyStore
	healthStore    store.HealthStore
	rolesStore     store.RolesStore
	accountsStore  store.AccountsStore
	loaderStore    loader.Store
	keystore       *slstore.KeyStore
	config         *config.ConjurConfig
}

// NewAPIServer creates a new APIServer instance
func NewAPIServer(
	authStore store.AuthenticateStore,
	authzStore store.AuthzStore,
	secretsStore store.SecretsStore,
	resourcesStore store.ResourcesStore,
	policyStore store.PolicyStore,
	healthStore store.HealthStore,
	rolesStore store.RolesStore,
	accountsStore store.AccountsStore,
	loaderStore loader.Store,
	keystore *slstore.KeyStore,
	cfg *config.ConjurConfig,
) *APIServer {
	return &APIServer{
		authStore:      authStore,
		authzStore:     authzStore,
		secretsStore:   secretsStore,
		resourcesStore: resourcesStore,
		policyStore:    policyStore,
		healthStore:    healthStore,
		rolesStore:     rolesStore,
		accountsStore:  accountsStore,
		loaderStore:    loaderStore,
		keystore:       keystore,
		config:         cfg,
	}
}

// Helper functions

func (s *APIServer) generateToken(account, login string) ([]byte, error) {
	var tokenTTL time.Duration
	if strings.HasPrefix(login, "host/") {
		tokenTTL = s.config.HostTokenTTL()
	} else {
		tokenTTL = s.config.UserTokenTTL()
	}

	now := time.Now()
	newclaimsMap := map[string]interface{}{
		"iat": now.Unix(),
		"exp": now.Add(tokenTTL).Unix(),
		"sub": login,
	}

	key, err := s.keystore.ByAccount(account)
	if err != nil {
		return nil, fmt.Errorf("error on key by account: %w", err)
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

	newsignature, err := key.Sign([]byte(stringToSign), newsalt)
	if err != nil {
		return nil, fmt.Errorf("error signing token: %w", err)
	}

	newjwt := map[string]string{
		"protected": base64.URLEncoding.EncodeToString([]byte(newheader)),
		"payload":   base64.URLEncoding.EncodeToString([]byte(newclaims)),
		"signature": base64.URLEncoding.EncodeToString(newsignature),
	}

	return []byte(utils.ToJson(newjwt)), nil
}

func getClientIP(r *http.Request) string {
	clientIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = forwarded
	}
	return clientIP
}

func respondWithError(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func roleIdFromLogin(account, login string) string {
	if strings.HasPrefix(login, "host/") {
		return account + ":host:" + strings.TrimPrefix(login, "host/")
	}
	return account + ":user:" + login
}

// Ensure APIServer implements api.ServerInterface
var _ api.ServerInterface = (*APIServer)(nil)
