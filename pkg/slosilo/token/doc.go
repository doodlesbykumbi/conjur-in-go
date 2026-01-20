// Package token provides parsing and validation for Conjur authentication tokens.
//
// Conjur tokens are JSON structures containing a protected header, payload,
// and signature. This package handles parsing these tokens and extracting
// claims like subject (login), issued-at time, and expiration.
//
// # Basic Usage
//
//	tok, err := token.Parse(rawTokenBytes)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if tok.Expired() {
//	    log.Fatal("token expired")
//	}
//
//	account, ok := tok.Verify(myVerifier)
//	if !ok {
//	    log.Fatal("invalid signature")
//	}
//
//	login := tok.Sub()
package token
