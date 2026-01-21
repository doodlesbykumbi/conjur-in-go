package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	jwtPrivateKey *rsa.PrivateKey
	jwtServiceID  string
)

// iSetAuthnJWTVariableWithTestJWKS generates a test RSA key pair and sets the public-keys variable
func (s *StepsContext) iSetAuthnJWTVariableWithTestJWKS(serviceID, variableName string) error {
	jwtServiceID = serviceID

	// Generate RSA key pair for testing
	var err error
	jwtPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	nBytes := jwtPrivateKey.N.Bytes()
	eBytes := big.NewInt(int64(jwtPrivateKey.E)).Bytes()

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{"kty": "RSA", "kid": "test-key-1", "n": base64.RawURLEncoding.EncodeToString(nBytes), "e": base64.RawURLEncoding.EncodeToString(eBytes)},
		},
	}
	jwksJSON, _ := json.Marshal(jwks)
	publicKeys := fmt.Sprintf(`{"type":"jwks","value":%s}`, string(jwksJSON))

	// Set the variable via API
	return s.setVariableValue("conjur/authn-jwt/"+serviceID+"/"+variableName, publicKeys)
}

// iSetAuthnJWTVariableTo sets a JWT authenticator variable to a specific value
func (s *StepsContext) iSetAuthnJWTVariableTo(serviceID, variableName, value string) error {
	return s.setVariableValue("conjur/authn-jwt/"+serviceID+"/"+variableName, value)
}

// setVariableValue sets a variable value via the secrets API
func (s *StepsContext) setVariableValue(variableID, value string) error {
	url := fmt.Sprintf("%s/secrets/%s/variable/%s", s.serverURL, s.account, variableID)
	req, err := http.NewRequest("POST", url, strings.NewReader(value))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", `Token token="`+s.authToken+`"`)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := s.tc.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to set variable %s: status %d: %s", variableID, resp.StatusCode, string(body))
	}
	return nil
}

func (s *StepsContext) iAuthenticateViaAuthnJWTWithValidTokenForHost(hostID string) error {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "test-issuer", "sub": s.account + ":host:" + hostID, "exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "test-key-1"
	tokenString, _ := token.SignedString(jwtPrivateKey)

	url := fmt.Sprintf("%s/authn-jwt/%s/%s/authenticate", s.serverURL, jwtServiceID, s.account)
	req, _ := http.NewRequest("POST", url, strings.NewReader("jwt="+tokenString))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var err error
	s.response, err = s.tc.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	s.responseBody, _ = io.ReadAll(s.response.Body)
	_ = s.response.Body.Close()
	return nil
}

func (s *StepsContext) iAuthenticateViaAuthnJWTWithInvalidTokenForHost(hostID string) error {
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "test-issuer", "sub": s.account + ":host:" + hostID, "exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "test-key-1"
	tokenString, _ := token.SignedString(wrongKey)

	url := fmt.Sprintf("%s/authn-jwt/%s/%s/authenticate", s.serverURL, jwtServiceID, s.account)
	req, _ := http.NewRequest("POST", url, strings.NewReader("jwt="+tokenString))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var err error
	s.response, err = s.tc.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	s.responseBody, _ = io.ReadAll(s.response.Body)
	_ = s.response.Body.Close()
	return nil
}

func (s *StepsContext) theResponseShouldContainConjurAccessToken() error {
	if len(s.responseBody) < 50 {
		return fmt.Errorf("response too short: %s", string(s.responseBody))
	}
	return nil
}

func (s *StepsContext) iAuthenticateViaAuthnJWTWithService(serviceID string) error {
	url := fmt.Sprintf("%s/authn-jwt/%s/%s/authenticate", s.serverURL, serviceID, s.account)
	req, _ := http.NewRequest("POST", url, strings.NewReader("jwt=dummy"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var err error
	s.response, err = s.tc.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	s.responseBody, _ = io.ReadAll(s.response.Body)
	_ = s.response.Body.Close()
	return nil
}
