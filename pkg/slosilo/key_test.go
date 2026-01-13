package slosilo

import (
	"bytes"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if key == nil {
		t.Fatal("expected non-nil key")
	}

	// Check that fingerprint is generated
	fingerprint := key.Fingerprint()
	if fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}

	// Fingerprint should be hex-encoded SHA256 (64 chars)
	if len(fingerprint) != 64 {
		t.Errorf("expected fingerprint length 64, got %d", len(fingerprint))
	}
}

func TestKeySerializeAndRestore(t *testing.T) {
	// Generate a key
	original, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Serialize it
	serialized, err := original.Serialize()
	if err != nil {
		t.Fatalf("failed to serialize key: %v", err)
	}

	if len(serialized) == 0 {
		t.Fatal("expected non-empty serialized key")
	}

	// Restore it
	restored, err := NewKey(serialized)
	if err != nil {
		t.Fatalf("failed to restore key: %v", err)
	}

	// Fingerprints should match
	if original.Fingerprint() != restored.Fingerprint() {
		t.Errorf("fingerprints don't match: %s != %s", original.Fingerprint(), restored.Fingerprint())
	}
}

func TestKeySignAndVerify(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	message := []byte("hello world")
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}

	// Sign the message
	signature, err := key.Sign(message, salt)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("expected non-empty signature")
	}

	// Verify the signature
	err = key.Verify(message, signature)
	if err != nil {
		t.Errorf("verification failed: %v", err)
	}

	// Verify with wrong message should fail
	err = key.Verify([]byte("wrong message"), signature)
	if err == nil {
		t.Error("expected verification to fail with wrong message")
	}
}

func TestKeyPemExport(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Test private key PEM
	privatePem := key.PrivateRSAPem()
	if len(privatePem) == 0 {
		t.Error("expected non-empty private PEM")
	}
	if !bytes.Contains(privatePem, []byte("RSA PRIVATE KEY")) {
		t.Error("private PEM should contain RSA PRIVATE KEY")
	}

	// Test public key PEM
	publicPem := key.PublicPem()
	if len(publicPem) == 0 {
		t.Error("expected non-empty public PEM")
	}
	if !bytes.Contains(publicPem, []byte("PUBLIC KEY")) {
		t.Error("public PEM should contain PUBLIC KEY")
	}

	// Test RSA public key PEM
	rsaPublicPem := key.PublicRSAPem()
	if len(rsaPublicPem) == 0 {
		t.Error("expected non-empty RSA public PEM")
	}
	if !bytes.Contains(rsaPublicPem, []byte("RSA PUBLIC KEY")) {
		t.Error("RSA public PEM should contain RSA PUBLIC KEY")
	}
}

func TestFingerprintConsistency(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Fingerprint should be consistent across multiple calls
	fp1 := key.Fingerprint()
	fp2 := key.Fingerprint()

	if fp1 != fp2 {
		t.Errorf("fingerprint not consistent: %s != %s", fp1, fp2)
	}
}

func TestDifferentKeysHaveDifferentFingerprints(t *testing.T) {
	key1, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key1: %v", err)
	}

	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key2: %v", err)
	}

	if key1.Fingerprint() == key2.Fingerprint() {
		t.Error("different keys should have different fingerprints")
	}
}
