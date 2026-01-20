package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// Parsed represents a parsed Conjur authentication token.
type Parsed struct {
	protected []byte
	payload   []byte
	signature []byte
	header    map[string]interface{}
	claims    map[string]interface{}
}

// ErrMalformed indicates the token structure is invalid.
var ErrMalformed = errors.New("Malformed token")

// ErrInvalid indicates the token is missing required fields.
// Error message copied from:
// https://github.com/cyberark/conjur-rack/blob/master/lib/conjur/rack/authenticator.rb#L103
var ErrInvalid = errors.New("Invalid token")

func unmarshallJsonFromB64(rawB64 string) ([]byte, map[string]interface{}, error) {
	raw, err := base64.URLEncoding.DecodeString(rawB64)
	if err != nil {
		return nil, nil, err
	}

	var res map[string]interface{}
	err = json.Unmarshal(raw, &res)
	if err != nil {
		return nil, nil, err
	}

	return raw, res, nil
}

// Parse parses a raw token and returns a Parsed token.
func Parse(raw []byte) (*Parsed, error) {
	var tmpToken map[string]string
	err := json.Unmarshal(raw, &tmpToken)
	if err != nil {
		return nil, ErrMalformed
	}

	requiredFields := []string{"signature", "protected", "payload"}
	for _, field := range requiredFields {
		if len(tmpToken[field]) == 0 {
			return nil, ErrInvalid
		}
	}

	signature, err := base64.URLEncoding.DecodeString(tmpToken["signature"])
	if err != nil {
		return nil, ErrMalformed
	}
	protected, header, err := unmarshallJsonFromB64(tmpToken["protected"])
	if err != nil {
		return nil, ErrMalformed
	}
	payload, claims, err := unmarshallJsonFromB64(tmpToken["payload"])
	if err != nil {
		return nil, ErrMalformed
	}

	return &Parsed{
		protected: protected,
		payload:   payload,
		signature: signature,
		claims:    claims,
		header:    header,
	}, nil
}

// Verifier is a function that verifies a token signature.
// It receives the key ID, protected header, payload, and signature.
// It returns the account name and whether verification succeeded.
type Verifier func(kid string, protected, payload, signature []byte) (account string, ok bool)

// Verify verifies the token using the provided verifier function.
func (p Parsed) Verify(verifier Verifier) (string, bool) {
	return verifier(p.Kid(), p.protected, p.payload, p.signature)
}

// Expired returns true if the token has expired.
func (p Parsed) Expired() bool {
	iat, ok := p.claims["iat"].(float64)
	if !ok {
		return true
	}

	return time.Unix(int64(iat), 0).Add(8 * time.Minute).Before(time.Now())
}

// Sub returns the subject claim (login).
func (p Parsed) Sub() string {
	sub, _ := p.claims["sub"].(string)
	return sub
}

// Kid returns the key ID from the header.
func (p Parsed) Kid() string {
	kid, _ := p.header["kid"].(string)
	return kid
}

// IAT returns the issued-at time.
func (p Parsed) IAT() time.Time {
	iat, ok := p.claims["iat"].(float64)
	if !ok {
		return time.Time{}
	}
	return time.Unix(int64(iat), 0)
}

// Exp returns the expiration time.
func (p Parsed) Exp() time.Time {
	exp, ok := p.claims["exp"].(float64)
	if !ok {
		// Fall back to iat + 8 minutes if no exp claim
		return p.IAT().Add(8 * time.Minute)
	}
	return time.Unix(int64(exp), 0)
}
