package authn_jwt

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/authenticator"
)

// mockStore implements Store for testing
type mockStore struct {
	secrets map[string]string
	roles   map[string]bool
}

func newMockStore() *mockStore {
	return &mockStore{
		secrets: make(map[string]string),
		roles:   make(map[string]bool),
	}
}

func (m *mockStore) FetchSecret(resourceID string) (string, error) {
	if val, ok := m.secrets[resourceID]; ok {
		return val, nil
	}
	return "", nil
}

func (m *mockStore) RoleExists(roleID string) bool {
	return m.roles[roleID]
}

func TestAuthenticator_Name(t *testing.T) {
	store := newMockStore()

	tests := []struct {
		name      string
		serviceID string
		expected  string
	}{
		{
			name:      "without service ID",
			serviceID: "",
			expected:  "authn-jwt",
		},
		{
			name:      "with service ID",
			serviceID: "my-service",
			expected:  "authn-jwt/my-service",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewJWTAuthenticator(store, Config{ServiceID: tt.serviceID})
			assert.Equal(t, tt.expected, auth.Name())
		})
	}
}

func TestConfig_Validation(t *testing.T) {
	store := newMockStore()

	config := Config{
		ServiceID:        "test-service",
		ProviderURI:      "https://accounts.google.com",
		Issuer:           "https://accounts.google.com",
		TokenAppProperty: "email",
		Audience:         "my-app",
	}

	auth := NewJWTAuthenticator(store, config)

	assert.Equal(t, "test-service", auth.config.ServiceID)
	assert.Equal(t, "https://accounts.google.com", auth.config.ProviderURI)
	assert.Equal(t, "https://accounts.google.com", auth.config.Issuer)
	assert.Equal(t, "email", auth.config.TokenAppProperty)
	assert.Equal(t, "my-app", auth.config.Audience)
}

func TestParseRSAPublicKey(t *testing.T) {
	n := "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	e := "AQAB"

	key, err := parseRSAPublicKey(n, e)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, 65537, key.E)
}

func TestParseRSAPublicKey_InvalidN(t *testing.T) {
	_, err := parseRSAPublicKey("invalid!!!", "AQAB")
	assert.Error(t, err)
}

func TestParseRSAPublicKey_InvalidE(t *testing.T) {
	n := "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	_, err := parseRSAPublicKey(n, "invalid!!!")
	assert.Error(t, err)
}

func TestLoadInlinePublicKeys(t *testing.T) {
	store := newMockStore()

	// Valid inline JWKS
	publicKeys := `{"type":"jwks","value":{"keys":[{"kty":"RSA","kid":"test-key","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}]}}`

	auth := NewJWTAuthenticator(store, Config{
		ServiceID:  "test",
		PublicKeys: publicKeys,
		Issuer:     "test-issuer",
	})

	err := auth.loadInlinePublicKeys()
	assert.NoError(t, err)

	// Verify key was loaded
	auth.jwksCache.mu.RLock()
	_, ok := auth.jwksCache.keys["test-key"]
	auth.jwksCache.mu.RUnlock()
	assert.True(t, ok, "key should be loaded into cache")
}

func TestLoadInlinePublicKeys_InvalidType(t *testing.T) {
	store := newMockStore()

	publicKeys := `{"type":"pem","value":"-----BEGIN PUBLIC KEY-----"}`

	auth := NewJWTAuthenticator(store, Config{
		ServiceID:  "test",
		PublicKeys: publicKeys,
	})

	err := auth.loadInlinePublicKeys()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported public-keys type")
}

func TestLoadInlinePublicKeys_InvalidJSON(t *testing.T) {
	store := newMockStore()

	auth := NewJWTAuthenticator(store, Config{
		ServiceID:  "test",
		PublicKeys: "not valid json",
	})

	err := auth.loadInlinePublicKeys()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse public-keys")
}

func TestAuthenticate_EmptyToken(t *testing.T) {
	store := newMockStore()

	auth := NewJWTAuthenticator(store, Config{ServiceID: "test"})

	_, err := auth.Authenticate(context.Background(), authenticator.AuthenticatorInput{
		Account:     "myorg",
		Credentials: []byte(""),
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWT token is required")
}

func TestExtractIdentity_TokenAppProperty(t *testing.T) {
	store := newMockStore()

	auth := NewJWTAuthenticator(store, Config{
		ServiceID:        "test",
		TokenAppProperty: "email",
	})

	token := &jwt.Token{
		Claims: jwt.MapClaims{
			"sub":   "user123",
			"email": "user@example.com",
		},
	}

	identity, err := auth.extractIdentity(token, "")
	assert.NoError(t, err)
	assert.Equal(t, "user@example.com", identity)
}

func TestExtractIdentity_TokenAppPropertyMissing(t *testing.T) {
	store := newMockStore()

	auth := NewJWTAuthenticator(store, Config{
		ServiceID:        "test",
		TokenAppProperty: "email",
	})

	token := &jwt.Token{
		Claims: jwt.MapClaims{
			"sub": "user123",
		},
	}

	_, err := auth.extractIdentity(token, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "claim email not found")
}

func TestExtractIdentity_LoginFromURL(t *testing.T) {
	store := newMockStore()

	auth := NewJWTAuthenticator(store, Config{ServiceID: "test"})

	token := &jwt.Token{
		Claims: jwt.MapClaims{
			"sub": "user123",
		},
	}

	identity, err := auth.extractIdentity(token, "host/myapp")
	assert.NoError(t, err)
	assert.Equal(t, "host/myapp", identity)
}

func TestExtractIdentity_SubClaim(t *testing.T) {
	store := newMockStore()

	auth := NewJWTAuthenticator(store, Config{ServiceID: "test"})

	token := &jwt.Token{
		Claims: jwt.MapClaims{
			"sub": "user123",
		},
	}

	identity, err := auth.extractIdentity(token, "")
	assert.NoError(t, err)
	assert.Equal(t, "user123", identity)
}

func TestExtractIdentity_NoIdentity(t *testing.T) {
	store := newMockStore()

	auth := NewJWTAuthenticator(store, Config{ServiceID: "test"})

	token := &jwt.Token{
		Claims: jwt.MapClaims{
			"iss": "test-issuer",
		},
	}

	_, err := auth.extractIdentity(token, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no identity found")
}

func TestNewFromStore(t *testing.T) {
	store := newMockStore()

	auth := NewFromStore(store, "my-service", "myorg")

	assert.Equal(t, "authn-jwt/my-service", auth.Name())
	assert.Equal(t, "myorg", auth.account)
	assert.Equal(t, "my-service", auth.config.ServiceID)
}

func TestParseJWKSBody_EmptyKeys(t *testing.T) {
	store := newMockStore()

	auth := NewJWTAuthenticator(store, Config{ServiceID: "test"})

	err := auth.parseJWKSBody([]byte(`{"keys":[]}`))
	assert.NoError(t, err)

	auth.jwksCache.mu.RLock()
	assert.Empty(t, auth.jwksCache.keys)
	auth.jwksCache.mu.RUnlock()
}

func TestParseJWKSBody_InvalidJSON(t *testing.T) {
	store := newMockStore()

	auth := NewJWTAuthenticator(store, Config{ServiceID: "test"})

	err := auth.parseJWKSBody([]byte(`not json`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JWKS")
}

func TestParseJWKSBody_NonRSAKey(t *testing.T) {
	store := newMockStore()

	auth := NewJWTAuthenticator(store, Config{ServiceID: "test"})

	// EC key should be skipped
	err := auth.parseJWKSBody([]byte(`{"keys":[{"kty":"EC","kid":"ec-key","crv":"P-256","x":"abc","y":"def"}]}`))
	assert.NoError(t, err)

	auth.jwksCache.mu.RLock()
	_, ok := auth.jwksCache.keys["ec-key"]
	auth.jwksCache.mu.RUnlock()
	assert.False(t, ok, "EC key should not be loaded")
}

func TestRefreshJWKSIfNeeded_NotExpired(t *testing.T) {
	store := newMockStore()

	auth := NewJWTAuthenticator(store, Config{
		ServiceID:  "test",
		PublicKeys: `{"type":"jwks","value":{"keys":[]}}`,
	})

	// Pre-populate cache with future expiry
	auth.jwksCache.mu.Lock()
	auth.jwksCache.expiresAt = time.Now().Add(10 * time.Minute)
	auth.jwksCache.mu.Unlock()

	// Should not refresh
	err := auth.refreshJWKSIfNeeded(context.Background())
	assert.NoError(t, err)
}

func TestStatus(t *testing.T) {
	store := newMockStore()

	auth := NewJWTAuthenticator(store, Config{
		ServiceID:  "test",
		PublicKeys: `{"type":"jwks","value":{"keys":[]}}`,
	})

	err := auth.Status(context.Background(), "myorg", "test")
	assert.NoError(t, err)
}
