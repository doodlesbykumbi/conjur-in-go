package token

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create a valid token JSON
func createTokenJSON(t *testing.T, sub string, iat int64, kid string) []byte {
	header := map[string]interface{}{"kid": kid, "alg": "conjur.org/slosilo/v2"}
	claims := map[string]interface{}{"sub": sub, "iat": float64(iat)}

	headerBytes, _ := json.Marshal(header)
	claimsBytes, _ := json.Marshal(claims)

	tokenMap := map[string]string{
		"protected": base64.URLEncoding.EncodeToString(headerBytes),
		"payload":   base64.URLEncoding.EncodeToString(claimsBytes),
		"signature": base64.URLEncoding.EncodeToString([]byte("fake-signature")),
	}

	tokenBytes, err := json.Marshal(tokenMap)
	require.NoError(t, err)
	return tokenBytes
}

func TestParse_ValidToken(t *testing.T) {
	now := time.Now().Unix()
	tokenBytes := createTokenJSON(t, "alice", now, "key-123")

	parsed, err := Parse(tokenBytes)
	require.NoError(t, err)
	require.NotNil(t, parsed)

	assert.Equal(t, "alice", parsed.Sub())
	assert.Equal(t, "key-123", parsed.Kid())
	assert.WithinDuration(t, time.Unix(now, 0), parsed.IAT(), time.Second)
}

func TestParse_MalformedJSON(t *testing.T) {
	_, err := Parse([]byte("not json"))
	assert.ErrorIs(t, err, ErrMalformed)
}

func TestParse_MissingFields(t *testing.T) {
	tests := []struct {
		name  string
		token map[string]string
	}{
		{
			name:  "missing signature",
			token: map[string]string{"protected": "eyJ0ZXN0IjoidmFsdWUifQ==", "payload": "eyJ0ZXN0IjoidmFsdWUifQ=="},
		},
		{
			name:  "missing protected",
			token: map[string]string{"signature": "c2lnbmF0dXJl", "payload": "eyJ0ZXN0IjoidmFsdWUifQ=="},
		},
		{
			name:  "missing payload",
			token: map[string]string{"signature": "c2lnbmF0dXJl", "protected": "eyJ0ZXN0IjoidmFsdWUifQ=="},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenBytes, _ := json.Marshal(tt.token)
			_, err := Parse(tokenBytes)
			assert.ErrorIs(t, err, ErrInvalid)
		})
	}
}

func TestParse_InvalidBase64(t *testing.T) {
	tokenMap := map[string]string{
		"protected": "not-valid-base64!!!",
		"payload":   "eyJ0ZXN0IjoidmFsdWUifQ==",
		"signature": "c2lnbmF0dXJl",
	}
	tokenBytes, _ := json.Marshal(tokenMap)

	_, err := Parse(tokenBytes)
	assert.ErrorIs(t, err, ErrMalformed)
}

func TestParsed_Expired(t *testing.T) {
	tests := []struct {
		name     string
		iat      int64
		expected bool
	}{
		{
			name:     "not expired - issued now",
			iat:      time.Now().Unix(),
			expected: false,
		},
		{
			name:     "not expired - issued 7 minutes ago",
			iat:      time.Now().Add(-7 * time.Minute).Unix(),
			expected: false,
		},
		{
			name:     "expired - issued 9 minutes ago",
			iat:      time.Now().Add(-9 * time.Minute).Unix(),
			expected: true,
		},
		{
			name:     "expired - issued 1 hour ago",
			iat:      time.Now().Add(-1 * time.Hour).Unix(),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenBytes := createTokenJSON(t, "alice", tt.iat, "key-123")
			parsed, err := Parse(tokenBytes)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, parsed.Expired())
		})
	}
}

func TestParsed_Expired_MissingIAT(t *testing.T) {
	// Token without iat claim should be considered expired
	header := map[string]interface{}{"kid": "key-123"}
	claims := map[string]interface{}{"sub": "alice"} // no iat

	headerBytes, _ := json.Marshal(header)
	claimsBytes, _ := json.Marshal(claims)

	tokenMap := map[string]string{
		"protected": base64.URLEncoding.EncodeToString(headerBytes),
		"payload":   base64.URLEncoding.EncodeToString(claimsBytes),
		"signature": base64.URLEncoding.EncodeToString([]byte("sig")),
	}
	tokenBytes, _ := json.Marshal(tokenMap)

	parsed, err := Parse(tokenBytes)
	require.NoError(t, err)

	assert.True(t, parsed.Expired(), "token without iat should be expired")
}

func TestParsed_Verify(t *testing.T) {
	tokenBytes := createTokenJSON(t, "alice", time.Now().Unix(), "key-123")
	parsed, err := Parse(tokenBytes)
	require.NoError(t, err)

	t.Run("verification succeeds", func(t *testing.T) {
		verifier := func(kid string, protected, payload, signature []byte) (string, bool) {
			assert.Equal(t, "key-123", kid)
			assert.NotEmpty(t, protected)
			assert.NotEmpty(t, payload)
			assert.NotEmpty(t, signature)
			return "myaccount", true
		}

		account, ok := parsed.Verify(verifier)
		assert.True(t, ok)
		assert.Equal(t, "myaccount", account)
	})

	t.Run("verification fails", func(t *testing.T) {
		verifier := func(kid string, protected, payload, signature []byte) (string, bool) {
			return "", false
		}

		account, ok := parsed.Verify(verifier)
		assert.False(t, ok)
		assert.Empty(t, account)
	})
}

func TestParsed_Exp(t *testing.T) {
	t.Run("with explicit exp claim", func(t *testing.T) {
		now := time.Now()
		expTime := now.Add(1 * time.Hour)

		header := map[string]interface{}{"kid": "key-123"}
		claims := map[string]interface{}{
			"sub": "alice",
			"iat": float64(now.Unix()),
			"exp": float64(expTime.Unix()),
		}

		headerBytes, _ := json.Marshal(header)
		claimsBytes, _ := json.Marshal(claims)

		tokenMap := map[string]string{
			"protected": base64.URLEncoding.EncodeToString(headerBytes),
			"payload":   base64.URLEncoding.EncodeToString(claimsBytes),
			"signature": base64.URLEncoding.EncodeToString([]byte("sig")),
		}
		tokenBytes, _ := json.Marshal(tokenMap)

		parsed, err := Parse(tokenBytes)
		require.NoError(t, err)

		assert.WithinDuration(t, expTime, parsed.Exp(), time.Second)
	})

	t.Run("without exp claim falls back to iat + 8 minutes", func(t *testing.T) {
		now := time.Now()
		tokenBytes := createTokenJSON(t, "alice", now.Unix(), "key-123")

		parsed, err := Parse(tokenBytes)
		require.NoError(t, err)

		expectedExp := now.Add(8 * time.Minute)
		assert.WithinDuration(t, expectedExp, parsed.Exp(), time.Second)
	})
}

func TestParsed_Sub_Missing(t *testing.T) {
	header := map[string]interface{}{"kid": "key-123"}
	claims := map[string]interface{}{"iat": float64(time.Now().Unix())} // no sub

	headerBytes, _ := json.Marshal(header)
	claimsBytes, _ := json.Marshal(claims)

	tokenMap := map[string]string{
		"protected": base64.URLEncoding.EncodeToString(headerBytes),
		"payload":   base64.URLEncoding.EncodeToString(claimsBytes),
		"signature": base64.URLEncoding.EncodeToString([]byte("sig")),
	}
	tokenBytes, _ := json.Marshal(tokenMap)

	parsed, err := Parse(tokenBytes)
	require.NoError(t, err)

	assert.Empty(t, parsed.Sub())
}

func TestParsed_Kid_Missing(t *testing.T) {
	header := map[string]interface{}{} // no kid
	claims := map[string]interface{}{"sub": "alice", "iat": float64(time.Now().Unix())}

	headerBytes, _ := json.Marshal(header)
	claimsBytes, _ := json.Marshal(claims)

	tokenMap := map[string]string{
		"protected": base64.URLEncoding.EncodeToString(headerBytes),
		"payload":   base64.URLEncoding.EncodeToString(claimsBytes),
		"signature": base64.URLEncoding.EncodeToString([]byte("sig")),
	}
	tokenBytes, _ := json.Marshal(tokenMap)

	parsed, err := Parse(tokenBytes)
	require.NoError(t, err)

	assert.Empty(t, parsed.Kid())
}
