package slosilo

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

type ParsedToken struct {
	protected []byte
	payload []byte
	signature []byte
	header map[string]interface{}
	claims map[string]interface{}
}

var malformedToken = errors.New("malformed token")
var invalidToken = errors.New("invalid token")

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

	return raw, res,  nil
}

func NewParsedToken(raw []byte) (*ParsedToken, error)  {
	var tmpToken map[string]string
	err := json.Unmarshal(raw, &tmpToken)
	if err != nil {
		return nil, malformedToken
	}

	requiredFields := []string{"signature", "protected", "payload"}
	for _, field := range requiredFields {
		if len(tmpToken[field]) == 0 {
			return nil, invalidToken
		}
	}

	signature, err := base64.URLEncoding.DecodeString(tmpToken["signature"])
	if err != nil {
		return nil, malformedToken
	}
	protected, header, err := unmarshallJsonFromB64(tmpToken["protected"])
	if err != nil {
		return nil, malformedToken
	}
	payload, claims, err := unmarshallJsonFromB64(tmpToken["payload"])
	if err != nil {
		return nil, malformedToken
	}

	return &ParsedToken{
		protected: protected,
		payload:   payload,
		signature: signature,
		claims: claims,
		header: header,
	}, nil
}

// TODO: this needs to be more sophisticated
//  Conjur in ruby forces the thing being signed to be encoded in ASCII-8BIT
//  https://github.com/cyberark/slosilo/blob/master/lib/slosilo/key.rb#L198-L202
func (p ParsedToken) Verify(verifier func(kid string, protected, payload, signature[]byte) (string, bool)) (string, bool) {
	return verifier(p.Kid(), p.protected, p.payload, p.signature)
}

func (p ParsedToken) Expired() bool {
	iat, ok := p.claims["iat"].(float64)
	if !ok {
		return true
	}

	return time.Unix(int64(iat), 0).Add(8 * time.Minute).Before(time.Now())
}

func (p ParsedToken) Sub() string {
	sub, _ := p.claims["sub"].(string)
	return sub
}

func (p ParsedToken) Kid() string {
	kid, _ := p.header["kid"].(string)
	return kid
}
