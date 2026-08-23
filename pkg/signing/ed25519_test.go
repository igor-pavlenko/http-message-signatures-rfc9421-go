package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

// TestEd25519_ID tests that the algorithm returns the correct ID.
func TestEd25519_ID(t *testing.T) {
	alg := &ed25519Algorithm{}
	if got := alg.ID(); got != "ed25519" {
		t.Errorf("expected ID %q, got %q", "ed25519", got)
	}
}

// TestEd25519_SignVerify tests basic signing and verification.
func TestEd25519_SignVerify(t *testing.T) {
	// Generate test key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	alg := &ed25519Algorithm{}
	signatureBase := []byte("test signature base for Ed25519")

	// Sign
	signature, err := alg.Sign(signatureBase, privKey)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("signature is empty")
	}

	// Ed25519 signatures are always 64 bytes
	if len(signature) != ed25519.SignatureSize {
		t.Errorf("expected signature size %d bytes, got %d bytes", ed25519.SignatureSize, len(signature))
	}

	// Verify with public key
	err = alg.Verify(signatureBase, signature, pubKey)
	if err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}
}

// TestEd25519_VerifyTamperedSignature tests that tampered signatures are rejected.
func TestEd25519_VerifyTamperedSignature(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	alg := &ed25519Algorithm{}
	signatureBase := []byte("original message")

	signature, _ := alg.Sign(signatureBase, privKey)

	// Tamper with signature
	if len(signature) > 0 {
		signature[0] ^= 0xFF
	}

	err := alg.Verify(signatureBase, signature, pubKey)
	if err == nil {
		t.Fatal("expected verification to fail for tampered signature")
	}

	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("expected error about verification failure, got: %v", err)
	}
}

// TestEd25519_VerifyTamperedMessage tests that modified messages are rejected.
func TestEd25519_VerifyTamperedMessage(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	alg := &ed25519Algorithm{}
	signatureBase := []byte("original message")

	signature, _ := alg.Sign(signatureBase, privKey)

	// Modify the message
	tamperedBase := []byte("tampered message")

	err := alg.Verify(tamperedBase, signature, pubKey)
	if err == nil {
		t.Fatal("expected verification to fail for tampered message")
	}
}

// TestEd25519_VerifyWrongKey tests that signatures from different keys are rejected.
func TestEd25519_VerifyWrongKey(t *testing.T) {
	pubKey1, privKey1, _ := ed25519.GenerateKey(rand.Reader)
	pubKey2, _, _ := ed25519.GenerateKey(rand.Reader)

	alg := &ed25519Algorithm{}
	signatureBase := []byte("test message")

	// Sign with key 1
	signature, _ := alg.Sign(signatureBase, privKey1)

	// Verify with correct key (should pass)
	err := alg.Verify(signatureBase, signature, pubKey1)
	if err != nil {
		t.Fatalf("verification with correct key failed: %v", err)
	}

	// Try to verify with key 2's public key (should fail)
	err = alg.Verify(signatureBase, signature, pubKey2)
	if err == nil {
		t.Fatal("expected verification to fail with wrong public key")
	}
}

// TestEd25519_SignEmptyBase tests that signing empty signature base returns error.
func TestEd25519_SignEmptyBase(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	alg := &ed25519Algorithm{}

	_, err := alg.Sign([]byte{}, privKey)
	if err == nil {
		t.Fatal("expected error for empty signature base")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error about empty base, got: %v", err)
	}
}

// TestEd25519_VerifyEmptyBase tests that verifying empty signature base returns error.
func TestEd25519_VerifyEmptyBase(t *testing.T) {
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	alg := &ed25519Algorithm{}

	err := alg.Verify([]byte{}, []byte("signature"), pubKey)
	if err == nil {
		t.Fatal("expected error for empty signature base")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error about empty base, got: %v", err)
	}
}

// TestEd25519_VerifyEmptySignature tests that verifying empty signature returns error.
func TestEd25519_VerifyEmptySignature(t *testing.T) {
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	alg := &ed25519Algorithm{}

	err := alg.Verify([]byte("test"), []byte{}, pubKey)
	if err == nil {
		t.Fatal("expected error for empty signature")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error about empty signature, got: %v", err)
	}
}

// TestEd25519_SignWrongKeyType tests that signing with wrong key type returns error.
func TestEd25519_SignWrongKeyType(t *testing.T) {
	alg := &ed25519Algorithm{}

	tests := []struct {
		name string
		key  any
	}{
		{"nil", nil},
		{"empty slice", ed25519.PrivateKey{}},
		{"string", "not a key"},
		{"int", 42},
		{"rsa key", &rsa.PrivateKey{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := alg.Sign([]byte("test"), tt.key)
			if err == nil {
				t.Fatalf("expected error for key type %T", tt.key)
			}
		})
	}
}

// TestEd25519_VerifyWrongKeyType tests that verifying with wrong key type returns error.
func TestEd25519_VerifyWrongKeyType(t *testing.T) {
	alg := &ed25519Algorithm{}

	tests := []struct {
		name string
		key  any
	}{
		{"nil", nil},
		{"empty slice", ed25519.PublicKey{}},
		{"string", "not a key"},
		{"int", 42},
		{"rsa key", &rsa.PublicKey{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a dummy 64-byte signature
			signature := make([]byte, ed25519.SignatureSize)
			err := alg.Verify([]byte("test"), signature, tt.key)
			if err == nil {
				t.Fatalf("expected error for key type %T", tt.key)
			}
		})
	}
}

// TestEd25519_KeySizeValidation tests that invalid key sizes are rejected (T044).
func TestEd25519_KeySizeValidation(t *testing.T) {
	alg := &ed25519Algorithm{}

	// Test private key size validation
	t.Run("private key too short", func(t *testing.T) {
		shortPrivKey := ed25519.PrivateKey(make([]byte, 32)) // Should be 64 bytes
		_, err := alg.Sign([]byte("test"), shortPrivKey)
		if err == nil {
			t.Fatal("expected error for short private key")
		}
		if !strings.Contains(err.Error(), "64 bytes") {
			t.Errorf("expected error about 64 bytes, got: %v", err)
		}
	})

	t.Run("private key too long", func(t *testing.T) {
		longPrivKey := ed25519.PrivateKey(make([]byte, 128)) // Should be 64 bytes
		_, err := alg.Sign([]byte("test"), longPrivKey)
		if err == nil {
			t.Fatal("expected error for long private key")
		}
		if !strings.Contains(err.Error(), "64 bytes") {
			t.Errorf("expected error about 64 bytes, got: %v", err)
		}
	})

	// Test public key size validation
	t.Run("public key too short", func(t *testing.T) {
		shortPubKey := ed25519.PublicKey(make([]byte, 16)) // Should be 32 bytes
		signature := make([]byte, ed25519.SignatureSize)
		err := alg.Verify([]byte("test"), signature, shortPubKey)
		if err == nil {
			t.Fatal("expected error for short public key")
		}
		if !strings.Contains(err.Error(), "32 bytes") {
			t.Errorf("expected error about 32 bytes, got: %v", err)
		}
	})

	t.Run("public key too long", func(t *testing.T) {
		longPubKey := ed25519.PublicKey(make([]byte, 64)) // Should be 32 bytes
		signature := make([]byte, ed25519.SignatureSize)
		err := alg.Verify([]byte("test"), signature, longPubKey)
		if err == nil {
			t.Fatal("expected error for long public key")
		}
		if !strings.Contains(err.Error(), "32 bytes") {
			t.Errorf("expected error about 32 bytes, got: %v", err)
		}
	})

	// Test signature size validation
	t.Run("signature wrong size", func(t *testing.T) {
		pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
		shortSignature := make([]byte, 32) // Should be 64 bytes
		err := alg.Verify([]byte("test"), shortSignature, pubKey)
		if err == nil {
			t.Fatal("expected error for wrong signature size")
		}
		if !strings.Contains(err.Error(), "64 bytes") {
			t.Errorf("expected error about 64 bytes, got: %v", err)
		}
	})
}

// TestEd25519_Deterministic tests that Ed25519 produces identical signatures (T048).
//
// RFC 8032 Section 5.1.6: Ed25519 is deterministic - same message and key
// always produce the exact same signature.
func TestEd25519_Deterministic(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	alg := &ed25519Algorithm{}
	signatureBase := []byte("deterministic test message")

	// Sign the same message 10 times
	signatures := make([][]byte, 10)
	for i := range 10 {
		sig, err := alg.Sign(signatureBase, privKey)
		if err != nil {
			t.Fatalf("Sign() #%d failed: %v", i, err)
		}
		signatures[i] = sig
	}

	// All signatures must be identical
	for i := 1; i < len(signatures); i++ {
		if string(signatures[i]) != string(signatures[0]) {
			t.Errorf("signature #%d differs from signature #0", i)
			t.Logf("Sig 0: %x", signatures[0][:8])
			t.Logf("Sig %d: %x", i, signatures[i][:8])
		}
	}

	// All should verify successfully
	for i, sig := range signatures {
		err := alg.Verify(signatureBase, sig, pubKey)
		if err != nil {
			t.Errorf("signature #%d failed verification: %v", i, err)
		}
	}

	t.Logf("✓ Ed25519 determinism verified: all 10 signatures identical")
}

// TestEd25519_RFC8032_TestVector tests Ed25519 against RFC 8032 test vector (T047).
//
// RFC 8032 Section 7.1: Test vector 2 (with non-empty message)
func TestEd25519_RFC8032_TestVector(t *testing.T) {
	// RFC 8032 Section 7.1 Test 2
	// SECRET KEY (32-byte seed)
	secretKeySeed := []byte{
		0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
		0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
		0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
		0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
	}

	// PUBLIC KEY (32 bytes)
	publicKey := ed25519.PublicKey([]byte{
		0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
		0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
		0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
		0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
	})

	// MESSAGE (1 byte: 0x72)
	message := []byte{0x72}

	// EXPECTED SIGNATURE (64 bytes)
	expectedSignature := []byte{
		0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8,
		0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
		0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f,
		0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
		0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e,
		0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
		0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
		0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00,
	}

	// Create private key from seed
	privateKey := ed25519.NewKeyFromSeed(secretKeySeed)

	alg := &ed25519Algorithm{}

	// Sign the message
	signature, err := alg.Sign(message, privateKey)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Verify signature matches RFC test vector
	if string(signature) != string(expectedSignature) {
		t.Error("signature does not match RFC 8032 test vector")
		t.Logf("Expected: %x", expectedSignature)
		t.Logf("Got:      %x", signature)
	}

	// Verify the signature
	err = alg.Verify(message, signature, publicKey)
	if err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}

	// Also test with stdlib verify to double-check
	if !ed25519.Verify(publicKey, message, signature) {
		t.Fatal("stdlib Ed25519 verification failed")
	}

	t.Log("✓ RFC 8032 Ed25519 test vector passed")
}

// TestEd25519_RegisteredInRegistry tests that the algorithm is registered.
func TestEd25519_RegisteredInRegistry(t *testing.T) {
	alg, err := GetAlgorithm("ed25519")
	if err != nil {
		t.Fatalf("ed25519 not registered: %v", err)
	}

	if alg.ID() != "ed25519" {
		t.Errorf("expected ID %q, got %q", "ed25519", alg.ID())
	}
}

// TestEd25519_LongSignatureBase tests signing and verifying long signature bases.
func TestEd25519_LongSignatureBase(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	alg := &ed25519Algorithm{}

	// Create a 100KB signature base
	longBase := make([]byte, 100*1024)
	for i := range longBase {
		longBase[i] = byte(i % 256)
	}

	signature, err := alg.Sign(longBase, privKey)
	if err != nil {
		t.Fatalf("failed to sign long base: %v", err)
	}

	err = alg.Verify(longBase, signature, pubKey)
	if err != nil {
		t.Fatalf("failed to verify long base: %v", err)
	}

	t.Logf("Successfully signed and verified 100KB signature base")
}
