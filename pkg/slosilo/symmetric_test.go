package slosilo

import (
	"bytes"
	"testing"
)

func TestNewSymmetric(t *testing.T) {
	// Valid 32-byte key
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i)
	}

	cipher, err := NewSymmetric(validKey)
	if err != nil {
		t.Fatalf("unexpected error with valid key: %v", err)
	}
	if cipher == nil {
		t.Fatal("expected non-nil cipher")
	}

	// Invalid key size (AES requires 16, 24, or 32 bytes)
	invalidKey := make([]byte, 15)
	_, err = NewSymmetric(invalidKey)
	if err == nil {
		t.Error("expected error with invalid key size")
	}
}

func TestSymmetricEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	cipher, err := NewSymmetric(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	tests := []struct {
		name      string
		aad       []byte
		plaintext []byte
	}{
		{
			name:      "simple message",
			aad:       []byte("context"),
			plaintext: []byte("hello world"),
		},
		{
			name:      "empty plaintext",
			aad:       []byte("context"),
			plaintext: []byte(""),
		},
		{
			name:      "long message",
			aad:       []byte("long-context-data"),
			plaintext: bytes.Repeat([]byte("x"), 10000),
		},
		{
			name:      "binary data",
			aad:       []byte("binary"),
			plaintext: []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := cipher.Encrypt(tt.aad, tt.plaintext)
			if err != nil {
				t.Fatalf("encryption failed: %v", err)
			}

			// Ciphertext should be different from plaintext (unless empty)
			if len(tt.plaintext) > 0 && bytes.Equal(ciphertext, tt.plaintext) {
				t.Error("ciphertext should differ from plaintext")
			}

			// Decrypt
			decrypted, err := cipher.Decrypt(tt.aad, ciphertext)
			if err != nil {
				t.Fatalf("decryption failed: %v", err)
			}

			// Should match original
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("decrypted doesn't match original: got %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestSymmetricDecryptWithWrongAAD(t *testing.T) {
	key := make([]byte, 32)
	cipher, _ := NewSymmetric(key)

	plaintext := []byte("secret data")
	aad := []byte("correct-context")

	ciphertext, err := cipher.Encrypt(aad, plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Try to decrypt with wrong AAD
	wrongAAD := []byte("wrong-context")
	_, err = cipher.Decrypt(wrongAAD, ciphertext)
	if err == nil {
		t.Error("expected decryption to fail with wrong AAD")
	}
}

func TestSymmetricDecryptWithCorruptedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	cipher, _ := NewSymmetric(key)

	plaintext := []byte("secret data")
	aad := []byte("context")

	ciphertext, err := cipher.Encrypt(aad, plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Corrupt the ciphertext
	if len(ciphertext) > 0 {
		ciphertext[len(ciphertext)-1] ^= 0xff
	}

	_, err = cipher.Decrypt(aad, ciphertext)
	if err == nil {
		t.Error("expected decryption to fail with corrupted ciphertext")
	}
}

func TestSymmetricEncryptionIsNonDeterministic(t *testing.T) {
	key := make([]byte, 32)
	cipher, _ := NewSymmetric(key)

	plaintext := []byte("same message")
	aad := []byte("context")

	// Encrypt the same message twice
	ciphertext1, _ := cipher.Encrypt(aad, plaintext)
	ciphertext2, _ := cipher.Encrypt(aad, plaintext)

	// Ciphertexts should be different (due to random nonce)
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("encrypting same plaintext twice should produce different ciphertexts")
	}

	// But both should decrypt to the same plaintext
	decrypted1, _ := cipher.Decrypt(aad, ciphertext1)
	decrypted2, _ := cipher.Decrypt(aad, ciphertext2)

	if !bytes.Equal(decrypted1, plaintext) || !bytes.Equal(decrypted2, plaintext) {
		t.Error("both ciphertexts should decrypt to original plaintext")
	}
}
