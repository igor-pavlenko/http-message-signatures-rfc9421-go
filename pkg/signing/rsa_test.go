package signing

import (
	"crypto/rand"
	"crypto/rsa"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestRSAPSS_ID tests that the algorithm ID is correct.
func TestRSAPSS_ID(t *testing.T) {
	alg := &rsaPSSAlgorithm{}
	if alg.ID() != "rsa-pss-sha512" {
		t.Errorf("expected ID 'rsa-pss-sha512', got %q", alg.ID())
	}
}

// TestRSAPSS_SignVerify tests basic signing and verification.
func TestRSAPSS_SignVerify(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPSSAlgorithm{}
	signatureBase := []byte("test signature base")

	// Sign
	signature, err := alg.Sign(signatureBase, privateKey)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("signature is empty")
	}

	// Verify with correct key
	err = alg.Verify(signatureBase, signature, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}
}

// TestRSAPSS_VerifyTamperedSignature tests that tampered signatures are rejected.
func TestRSAPSS_VerifyTamperedSignature(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPSSAlgorithm{}
	signatureBase := []byte("test signature base")

	// Sign
	signature, err := alg.Sign(signatureBase, privateKey)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Tamper with signature
	signature[0] ^= 0xFF

	// Verify should fail
	err = alg.Verify(signatureBase, signature, &privateKey.PublicKey)
	if err == nil {
		t.Fatal("expected verification to fail for tampered signature, got nil")
	}

	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("expected error about verification failure, got: %v", err)
	}
}

// TestRSAPSS_VerifyTamperedMessage tests that signatures fail for modified messages.
func TestRSAPSS_VerifyTamperedMessage(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPSSAlgorithm{}
	signatureBase := []byte("test signature base")

	// Sign
	signature, err := alg.Sign(signatureBase, privateKey)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Modify message
	tamperedBase := []byte("modified signature base")

	// Verify should fail
	err = alg.Verify(tamperedBase, signature, &privateKey.PublicKey)
	if err == nil {
		t.Fatal("expected verification to fail for tampered message, got nil")
	}
}

// TestRSAPSS_VerifyWrongKey tests that signatures fail with incorrect public key.
func TestRSAPSS_VerifyWrongKey(t *testing.T) {
	// Generate two different RSA keys
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key 1: %v", err)
	}

	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key 2: %v", err)
	}

	alg := &rsaPSSAlgorithm{}
	signatureBase := []byte("test signature base")

	// Sign with key 1
	signature, err := alg.Sign(signatureBase, privateKey1)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Verify with key 2 (wrong key)
	err = alg.Verify(signatureBase, signature, &privateKey2.PublicKey)
	if err == nil {
		t.Fatal("expected verification to fail with wrong key, got nil")
	}
}

// TestRSAPSS_SignEmptyBase tests that signing empty signature base returns error.
func TestRSAPSS_SignEmptyBase(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPSSAlgorithm{}

	_, err = alg.Sign([]byte{}, privateKey)
	if err == nil {
		t.Fatal("expected error for empty signature base, got nil")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error about empty signature base, got: %v", err)
	}
}

// TestRSAPSS_VerifyEmptyBase tests that verifying empty signature base returns error.
func TestRSAPSS_VerifyEmptyBase(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPSSAlgorithm{}
	signature := []byte("dummy-signature")

	err = alg.Verify([]byte{}, signature, &privateKey.PublicKey)
	if err == nil {
		t.Fatal("expected error for empty signature base, got nil")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error about empty signature base, got: %v", err)
	}
}

// TestRSAPSS_VerifyEmptySignature tests that verifying empty signature returns error.
func TestRSAPSS_VerifyEmptySignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPSSAlgorithm{}
	signatureBase := []byte("test signature base")

	err = alg.Verify(signatureBase, []byte{}, &privateKey.PublicKey)
	if err == nil {
		t.Fatal("expected error for empty signature, got nil")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error about empty signature, got: %v", err)
	}
}

// TestRSAPSS_SignWrongKeyType tests that signing with wrong key type returns error.
func TestRSAPSS_SignWrongKeyType(t *testing.T) {
	alg := &rsaPSSAlgorithm{}
	signatureBase := []byte("test signature base")

	wrongKeys := []struct {
		name string
		key  any
	}{
		{"nil", nil},
		{"string", "not a key"},
		{"int", 42},
		{"slice", []byte("key")},
	}

	for _, tt := range wrongKeys {
		t.Run(tt.name, func(t *testing.T) {
			_, err := alg.Sign(signatureBase, tt.key)
			if err == nil {
				t.Fatalf("expected error for key type %s, got nil", tt.name)
			}

			if !strings.Contains(err.Error(), "invalid key type") {
				t.Errorf("expected error about invalid key type, got: %v", err)
			}
		})
	}
}

// TestRSAPSS_VerifyWrongKeyType tests that verifying with wrong key type returns error.
func TestRSAPSS_VerifyWrongKeyType(t *testing.T) {
	alg := &rsaPSSAlgorithm{}
	signatureBase := []byte("test signature base")
	signature := []byte("dummy-signature")

	wrongKeys := []struct {
		name string
		key  any
	}{
		{"nil", nil},
		{"string", "not a key"},
		{"int", 42},
		{"slice", []byte("key")},
	}

	for _, tt := range wrongKeys {
		t.Run(tt.name, func(t *testing.T) {
			err := alg.Verify(signatureBase, signature, tt.key)
			if err == nil {
				t.Fatalf("expected error for key type %s, got nil", tt.name)
			}

			if !strings.Contains(err.Error(), "invalid key type") {
				t.Errorf("expected error about invalid key type, got: %v", err)
			}
		})
	}
}

// TestRSAPSS_KeySizeValidation tests that keys < 2048 bits are rejected.
func TestRSAPSS_KeySizeValidation(t *testing.T) {
	// Generate 1024-bit key (too small)
	//nolint:gosec // G403: Intentionally small key to test rejection
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPSSAlgorithm{}
	signatureBase := []byte("test signature base")

	// Sign should fail
	_, err = alg.Sign(signatureBase, privateKey)
	if err == nil {
		t.Fatal("expected error for 1024-bit key, got nil")
	}

	if !strings.Contains(err.Error(), "too small") && !strings.Contains(err.Error(), "2048") {
		t.Errorf("expected error about key size, got: %v", err)
	}

	// Verify should also fail
	signature := []byte("dummy-signature")
	err = alg.Verify(signatureBase, signature, &privateKey.PublicKey)
	if err == nil {
		t.Fatal("expected error for 1024-bit key in verification, got nil")
	}

	if !strings.Contains(err.Error(), "too small") && !strings.Contains(err.Error(), "2048") {
		t.Errorf("expected error about key size, got: %v", err)
	}
}

// TestRSAPSS_DifferentKeySizes tests that various valid key sizes work.
func TestRSAPSS_DifferentKeySizes(t *testing.T) {
	keySizes := []int{2048, 3072, 4096}

	for _, keySize := range keySizes {
		t.Run(strconv.Itoa(keySize), func(t *testing.T) {
			privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
			if err != nil {
				t.Fatalf("failed to generate %d-bit RSA key: %v", keySize, err)
			}

			alg := &rsaPSSAlgorithm{}
			signatureBase := []byte("test signature base")

			// Sign
			signature, err := alg.Sign(signatureBase, privateKey)
			if err != nil {
				t.Fatalf("Sign() failed for %d-bit key: %v", keySize, err)
			}

			// Verify
			err = alg.Verify(signatureBase, signature, &privateKey.PublicKey)
			if err != nil {
				t.Fatalf("Verify() failed for %d-bit key: %v", keySize, err)
			}
		})
	}
}

// TestRSAPSS_RegisteredInRegistry tests that RSA-PSS is registered in the global registry.
func TestRSAPSS_RegisteredInRegistry(t *testing.T) {
	alg, err := GetAlgorithm("rsa-pss-sha512")
	if err != nil {
		t.Fatalf("failed to get rsa-pss-sha512 from registry: %v", err)
	}

	if alg.ID() != "rsa-pss-sha512" {
		t.Errorf("expected algorithm ID 'rsa-pss-sha512', got %q", alg.ID())
	}

	// Verify it's in the supported algorithms list
	supported := SupportedAlgorithms()
	found := slices.Contains(supported, "rsa-pss-sha512")

	if !found {
		t.Errorf("rsa-pss-sha512 not found in SupportedAlgorithms(): %v", supported)
	}
}

// TestRSAPSS_NonDeterministic tests that RSA-PSS produces different signatures each time.
// This is because RSA-PSS uses a random salt.
func TestRSAPSS_NonDeterministic(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPSSAlgorithm{}
	signatureBase := []byte("test signature base")

	// Sign the same message twice
	sig1, err := alg.Sign(signatureBase, privateKey)
	if err != nil {
		t.Fatalf("Sign() 1 failed: %v", err)
	}

	sig2, err := alg.Sign(signatureBase, privateKey)
	if err != nil {
		t.Fatalf("Sign() 2 failed: %v", err)
	}

	// Signatures should be different (probabilistic due to random salt)
	if len(sig1) == len(sig2) {
		allSame := true
		for i := range sig1 {
			if sig1[i] != sig2[i] {
				allSame = false
				break
			}
		}
		if allSame {
			t.Error("RSA-PSS signatures are identical, expected different (due to random salt)")
		}
	}

	// But both should verify correctly
	if err := alg.Verify(signatureBase, sig1, &privateKey.PublicKey); err != nil {
		t.Errorf("signature 1 verification failed: %v", err)
	}

	if err := alg.Verify(signatureBase, sig2, &privateKey.PublicKey); err != nil {
		t.Errorf("signature 2 verification failed: %v", err)
	}
}

// TestRSAPSS_LongSignatureBase tests signing and verifying a long signature base.
func TestRSAPSS_LongSignatureBase(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPSSAlgorithm{}

	// Create a long signature base (typical HTTP signature base)
	longBase := strings.Repeat("\"content-type\": application/json\n", 100)
	signatureBase := []byte(longBase)

	// Sign
	signature, err := alg.Sign(signatureBase, privateKey)
	if err != nil {
		t.Fatalf("Sign() failed for long base: %v", err)
	}

	// Verify
	err = alg.Verify(signatureBase, signature, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Verify() failed for long base: %v", err)
	}
}

// ============================================================================
// RSA-PKCS1-v1_5-SHA256 Tests (DEPRECATED ALGORITHM)
// ============================================================================

// TestRSAPKCS1v15_ID tests that the algorithm ID is correct.
func TestRSAPKCS1v15_ID(t *testing.T) {
	alg := &rsaPKCS1v15Algorithm{}
	if alg.ID() != "rsa-v1_5-sha256" {
		t.Errorf("expected ID 'rsa-v1_5-sha256', got %q", alg.ID())
	}
}

// TestRSAPKCS1v15_SignVerify tests basic signing and verification.
func TestRSAPKCS1v15_SignVerify(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPKCS1v15Algorithm{}
	signatureBase := []byte("test signature base")

	// Sign
	signature, err := alg.Sign(signatureBase, privateKey)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("signature is empty")
	}

	// Verify with correct key
	err = alg.Verify(signatureBase, signature, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}
}

// TestRSAPKCS1v15_VerifyTamperedSignature tests that tampered signatures are rejected.
func TestRSAPKCS1v15_VerifyTamperedSignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPKCS1v15Algorithm{}
	signatureBase := []byte("test signature base")

	signature, err := alg.Sign(signatureBase, privateKey)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Tamper with signature
	signature[0] ^= 0xFF

	// Verify should fail
	err = alg.Verify(signatureBase, signature, &privateKey.PublicKey)
	if err == nil {
		t.Fatal("expected verification to fail for tampered signature, got nil")
	}

	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("expected error about verification failure, got: %v", err)
	}
}

// TestRSAPKCS1v15_VerifyTamperedMessage tests that signatures fail for modified messages.
func TestRSAPKCS1v15_VerifyTamperedMessage(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPKCS1v15Algorithm{}
	signatureBase := []byte("test signature base")

	signature, err := alg.Sign(signatureBase, privateKey)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Modify message
	tamperedBase := []byte("modified signature base")

	// Verify should fail
	err = alg.Verify(tamperedBase, signature, &privateKey.PublicKey)
	if err == nil {
		t.Fatal("expected verification to fail for tampered message, got nil")
	}
}

// TestRSAPKCS1v15_VerifyWrongKey tests that signatures fail with incorrect public key.
func TestRSAPKCS1v15_VerifyWrongKey(t *testing.T) {
	// Generate two different RSA keys
	privateKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key 1: %v", err)
	}

	privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key 2: %v", err)
	}

	alg := &rsaPKCS1v15Algorithm{}
	signatureBase := []byte("test signature base")

	// Sign with key 1
	signature, err := alg.Sign(signatureBase, privateKey1)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Verify with key 2 (wrong key)
	err = alg.Verify(signatureBase, signature, &privateKey2.PublicKey)
	if err == nil {
		t.Fatal("expected verification to fail with wrong key, got nil")
	}
}

// TestRSAPKCS1v15_SignEmptyBase tests that signing empty signature base returns error.
func TestRSAPKCS1v15_SignEmptyBase(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPKCS1v15Algorithm{}

	_, err = alg.Sign([]byte{}, privateKey)
	if err == nil {
		t.Fatal("expected error for empty signature base, got nil")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error about empty signature base, got: %v", err)
	}
}

// TestRSAPKCS1v15_VerifyEmptyBase tests that verifying empty signature base returns error.
func TestRSAPKCS1v15_VerifyEmptyBase(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPKCS1v15Algorithm{}
	signature := []byte("dummy-signature")

	err = alg.Verify([]byte{}, signature, &privateKey.PublicKey)
	if err == nil {
		t.Fatal("expected error for empty signature base, got nil")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error about empty signature base, got: %v", err)
	}
}

// TestRSAPKCS1v15_VerifyEmptySignature tests that verifying empty signature returns error.
func TestRSAPKCS1v15_VerifyEmptySignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPKCS1v15Algorithm{}
	signatureBase := []byte("test signature base")

	err = alg.Verify(signatureBase, []byte{}, &privateKey.PublicKey)
	if err == nil {
		t.Fatal("expected error for empty signature, got nil")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error about empty signature, got: %v", err)
	}
}

// TestRSAPKCS1v15_SignWrongKeyType tests that signing with wrong key type returns error.
func TestRSAPKCS1v15_SignWrongKeyType(t *testing.T) {
	alg := &rsaPKCS1v15Algorithm{}
	signatureBase := []byte("test signature base")

	wrongKeys := []struct {
		name string
		key  any
	}{
		{"nil", nil},
		{"string", "not a key"},
		{"int", 42},
		{"slice", []byte("key")},
	}

	for _, tt := range wrongKeys {
		t.Run(tt.name, func(t *testing.T) {
			_, err := alg.Sign(signatureBase, tt.key)
			if err == nil {
				t.Fatalf("expected error for key type %s, got nil", tt.name)
			}

			if !strings.Contains(err.Error(), "invalid key type") {
				t.Errorf("expected error about invalid key type, got: %v", err)
			}
		})
	}
}

// TestRSAPKCS1v15_VerifyWrongKeyType tests that verifying with wrong key type returns error.
func TestRSAPKCS1v15_VerifyWrongKeyType(t *testing.T) {
	alg := &rsaPKCS1v15Algorithm{}
	signatureBase := []byte("test signature base")
	signature := []byte("dummy-signature")

	wrongKeys := []struct {
		name string
		key  any
	}{
		{"nil", nil},
		{"string", "not a key"},
		{"int", 42},
		{"slice", []byte("key")},
	}

	for _, tt := range wrongKeys {
		t.Run(tt.name, func(t *testing.T) {
			err := alg.Verify(signatureBase, signature, tt.key)
			if err == nil {
				t.Fatalf("expected error for key type %s, got nil", tt.name)
			}

			if !strings.Contains(err.Error(), "invalid key type") {
				t.Errorf("expected error about invalid key type, got: %v", err)
			}
		})
	}
}

// TestRSAPKCS1v15_KeySizeValidation tests that keys < 2048 bits are rejected.
func TestRSAPKCS1v15_KeySizeValidation(t *testing.T) {
	// Generate 1024-bit key (too small)
	//nolint:gosec // G403: Intentionally small key to test rejection
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPKCS1v15Algorithm{}
	signatureBase := []byte("test signature base")

	// Sign should fail
	_, err = alg.Sign(signatureBase, privateKey)
	if err == nil {
		t.Fatal("expected error for 1024-bit key, got nil")
	}

	if !strings.Contains(err.Error(), "too small") && !strings.Contains(err.Error(), "2048") {
		t.Errorf("expected error about key size, got: %v", err)
	}

	// Verify should also fail
	signature := []byte("dummy-signature")
	err = alg.Verify(signatureBase, signature, &privateKey.PublicKey)
	if err == nil {
		t.Fatal("expected error for 1024-bit key in verification, got nil")
	}

	if !strings.Contains(err.Error(), "too small") && !strings.Contains(err.Error(), "2048") {
		t.Errorf("expected error about key size, got: %v", err)
	}
}

// TestRSAPKCS1v15_DifferentKeySizes tests that various valid key sizes work.
func TestRSAPKCS1v15_DifferentKeySizes(t *testing.T) {
	keySizes := []int{2048, 3072, 4096}

	for _, keySize := range keySizes {
		t.Run(strconv.Itoa(keySize), func(t *testing.T) {
			privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
			if err != nil {
				t.Fatalf("failed to generate %d-bit RSA key: %v", keySize, err)
			}

			alg := &rsaPKCS1v15Algorithm{}
			signatureBase := []byte("test signature base")

			// Sign
			signature, err := alg.Sign(signatureBase, privateKey)
			if err != nil {
				t.Fatalf("Sign() failed for %d-bit key: %v", keySize, err)
			}

			// Verify
			err = alg.Verify(signatureBase, signature, &privateKey.PublicKey)
			if err != nil {
				t.Fatalf("Verify() failed for %d-bit key: %v", keySize, err)
			}
		})
	}
}

// TestRSAPKCS1v15_RegisteredInRegistry tests that RSA-PKCS1-v1_5 is registered in the global registry.
func TestRSAPKCS1v15_RegisteredInRegistry(t *testing.T) {
	alg, err := GetAlgorithm("rsa-v1_5-sha256")
	if err != nil {
		t.Fatalf("failed to get rsa-v1_5-sha256 from registry: %v", err)
	}

	if alg.ID() != "rsa-v1_5-sha256" {
		t.Errorf("expected algorithm ID 'rsa-v1_5-sha256', got %q", alg.ID())
	}

	// Verify it's in the supported algorithms list
	supported := SupportedAlgorithms()
	found := slices.Contains(supported, "rsa-v1_5-sha256")

	if !found {
		t.Errorf("rsa-v1_5-sha256 not found in SupportedAlgorithms(): %v", supported)
	}
}

// TestRSAPKCS1v15_Deterministic tests that RSA-PKCS1-v1_5 produces identical signatures.
// This is because RSA-PKCS1-v1_5 uses deterministic padding (no random salt).
func TestRSAPKCS1v15_Deterministic(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPKCS1v15Algorithm{}
	signatureBase := []byte("test signature base")

	// Sign the same message 10 times
	signatures := make([][]byte, 10)
	for i := range 10 {
		sig, err := alg.Sign(signatureBase, privateKey)
		if err != nil {
			t.Fatalf("Sign() #%d failed: %v", i, err)
		}
		signatures[i] = sig
	}

	// All signatures must be identical (deterministic padding)
	for i := 1; i < len(signatures); i++ {
		if string(signatures[i]) != string(signatures[0]) {
			t.Errorf("signature #%d differs from signature #0 (expected deterministic)", i)
			t.Logf("Sig 0: %x", signatures[0][:16])
			t.Logf("Sig %d: %x", i, signatures[i][:16])
		}
	}

	// All should verify successfully
	for i, sig := range signatures {
		err := alg.Verify(signatureBase, sig, &privateKey.PublicKey)
		if err != nil {
			t.Errorf("signature #%d failed verification: %v", i, err)
		}
	}

	t.Logf("✓ RSA-PKCS1-v1_5 determinism verified: all 10 signatures identical")
}

// TestRSAPKCS1v15_LongSignatureBase tests signing and verifying a long signature base.
func TestRSAPKCS1v15_LongSignatureBase(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg := &rsaPKCS1v15Algorithm{}

	// Create a long signature base (typical HTTP signature base)
	longBase := strings.Repeat("\"content-type\": application/json\n", 100)
	signatureBase := []byte(longBase)

	// Sign
	signature, err := alg.Sign(signatureBase, privateKey)
	if err != nil {
		t.Fatalf("Sign() failed for long base: %v", err)
	}

	// Verify
	err = alg.Verify(signatureBase, signature, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Verify() failed for long base: %v", err)
	}
}
