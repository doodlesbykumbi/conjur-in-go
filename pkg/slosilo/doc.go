// Package slosilo provides cryptographic operations for Conjur.
//
// This package implements the core cryptographic functionality required by Conjur,
// including RSA key management, symmetric encryption, and token signing. The name
// "slosilo" comes from the original Ruby implementation.
//
// # Key Management
//
// RSA keys are used for signing authentication tokens:
//
//	key, err := slosilo.GenerateKey()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Get the public key in PEM format
//	publicPEM := key.PublicPem()
//
//	// Sign data
//	signature, err := key.Sign(data)
//
// # Symmetric Encryption
//
// The SymmetricCipher interface provides AES-256-GCM encryption for secrets:
//
//	cipher, err := slosilo.NewSymmetric(dataKey)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Encrypt with associated data for authentication
//	ciphertext, err := cipher.Encrypt([]byte("role-id"), []byte("secret"))
//
//	// Decrypt
//	plaintext, err := cipher.Decrypt([]byte("role-id"), ciphertext)
//
// # Token Generation
//
// Authentication tokens are signed JWTs containing role identity:
//
//	token, err := key.SignedToken(claims)
package slosilo
