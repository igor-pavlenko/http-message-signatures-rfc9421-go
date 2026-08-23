package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

// TestECDSAP256_ID tests that the P-256 algorithm returns the correct ID.
func TestECDSAP256_ID(t *testing.T) {
	alg := &ecdsaP256Algorithm{}
	if got := alg.ID(); got != "ecdsa-p256-sha256" {
		t.Errorf("expected ID %q, got %q", "ecdsa-p256-sha256", got)
	}
}

// TestECDSAP384_ID tests that the P-384 algorithm returns the correct ID.
func TestECDSAP384_ID(t *testing.T) {
	alg := &ecdsaP384Algorithm{}
	if got := alg.ID(); got != "ecdsa-p384-sha384" {
		t.Errorf("expected ID %q, got %q", "ecdsa-p384-sha384", got)
	}
}

// TestECDSAP256_SignVerify tests basic signing and verification with P-256.
func TestECDSAP256_SignVerify(t *testing.T) {
	// Generate test key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P-256 key: %v", err)
	}

	alg := &ecdsaP256Algorithm{}
	signatureBase := []byte("test signature base")

	// Sign
	signature, err := alg.Sign(signatureBase, privKey)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("signature is empty")
	}

	// Verify with public key
	err = alg.Verify(signatureBase, signature, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}
}

// TestECDSAP384_SignVerify tests basic signing and verification with P-384.
func TestECDSAP384_SignVerify(t *testing.T) {
	// Generate test key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P-384 key: %v", err)
	}

	alg := &ecdsaP384Algorithm{}
	signatureBase := []byte("test signature base for P-384")

	// Sign
	signature, err := alg.Sign(signatureBase, privKey)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("signature is empty")
	}

	// Verify with public key
	err = alg.Verify(signatureBase, signature, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}
}

// TestECDSAP256_VerifyTamperedSignature tests that tampered signatures are rejected.
func TestECDSAP256_VerifyTamperedSignature(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	alg := &ecdsaP256Algorithm{}
	signatureBase := []byte("original message")

	signature, _ := alg.Sign(signatureBase, privKey)

	// Tamper with signature
	if len(signature) > 0 {
		signature[0] ^= 0xFF
	}

	err := alg.Verify(signatureBase, signature, &privKey.PublicKey)
	if err == nil {
		t.Fatal("expected verification to fail for tampered signature")
	}

	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("expected error about verification failure, got: %v", err)
	}
}

// TestECDSAP384_VerifyTamperedSignature tests that tampered P-384 signatures are rejected.
func TestECDSAP384_VerifyTamperedSignature(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	alg := &ecdsaP384Algorithm{}
	signatureBase := []byte("original message for P-384")

	signature, _ := alg.Sign(signatureBase, privKey)

	// Tamper with signature
	if len(signature) > 0 {
		signature[len(signature)-1] ^= 0x01
	}

	err := alg.Verify(signatureBase, signature, &privKey.PublicKey)
	if err == nil {
		t.Fatal("expected verification to fail for tampered signature")
	}

	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("expected error about verification failure, got: %v", err)
	}
}

// TestECDSAP256_VerifyTamperedMessage tests that modified messages are rejected.
func TestECDSAP256_VerifyTamperedMessage(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	alg := &ecdsaP256Algorithm{}
	signatureBase := []byte("original message")

	signature, _ := alg.Sign(signatureBase, privKey)

	// Modify the message
	tamperedBase := []byte("tampered message")

	err := alg.Verify(tamperedBase, signature, &privKey.PublicKey)
	if err == nil {
		t.Fatal("expected verification to fail for tampered message")
	}
}

// TestECDSAP384_VerifyTamperedMessage tests that modified P-384 messages are rejected.
func TestECDSAP384_VerifyTamperedMessage(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	alg := &ecdsaP384Algorithm{}
	signatureBase := []byte("original message")

	signature, _ := alg.Sign(signatureBase, privKey)

	// Modify the message
	tamperedBase := []byte("modified message")

	err := alg.Verify(tamperedBase, signature, &privKey.PublicKey)
	if err == nil {
		t.Fatal("expected verification to fail for tampered message")
	}
}

// TestECDSAP256_VerifyWrongKey tests that signatures from different keys are rejected.
func TestECDSAP256_VerifyWrongKey(t *testing.T) {
	privKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	alg := &ecdsaP256Algorithm{}
	signatureBase := []byte("test message")

	// Sign with key 1
	signature, _ := alg.Sign(signatureBase, privKey1)

	// Try to verify with key 2's public key
	err := alg.Verify(signatureBase, signature, &privKey2.PublicKey)
	if err == nil {
		t.Fatal("expected verification to fail with wrong public key")
	}
}

// TestECDSAP384_VerifyWrongKey tests that P-384 signatures from different keys are rejected.
func TestECDSAP384_VerifyWrongKey(t *testing.T) {
	privKey1, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	privKey2, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	alg := &ecdsaP384Algorithm{}
	signatureBase := []byte("test message for P-384")

	// Sign with key 1
	signature, _ := alg.Sign(signatureBase, privKey1)

	// Try to verify with key 2's public key
	err := alg.Verify(signatureBase, signature, &privKey2.PublicKey)
	if err == nil {
		t.Fatal("expected verification to fail with wrong public key")
	}
}

// TestECDSAP256_SignEmptyBase tests that signing empty signature base returns error.
func TestECDSAP256_SignEmptyBase(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	alg := &ecdsaP256Algorithm{}

	_, err := alg.Sign([]byte{}, privKey)
	if err == nil {
		t.Fatal("expected error for empty signature base")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error about empty base, got: %v", err)
	}
}

// TestECDSAP384_SignEmptyBase tests that signing empty signature base returns error.
func TestECDSAP384_SignEmptyBase(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	alg := &ecdsaP384Algorithm{}

	_, err := alg.Sign([]byte{}, privKey)
	if err == nil {
		t.Fatal("expected error for empty signature base")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error about empty base, got: %v", err)
	}
}

// TestECDSAP256_VerifyEmptyBase tests that verifying empty signature base returns error.
func TestECDSAP256_VerifyEmptyBase(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	alg := &ecdsaP256Algorithm{}

	err := alg.Verify([]byte{}, []byte("signature"), &privKey.PublicKey)
	if err == nil {
		t.Fatal("expected error for empty signature base")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error about empty base, got: %v", err)
	}
}

// TestECDSAP384_VerifyEmptyBase tests that verifying empty signature base returns error.
func TestECDSAP384_VerifyEmptyBase(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	alg := &ecdsaP384Algorithm{}

	err := alg.Verify([]byte{}, []byte("signature"), &privKey.PublicKey)
	if err == nil {
		t.Fatal("expected error for empty signature base")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error about empty base, got: %v", err)
	}
}

// TestECDSAP256_VerifyEmptySignature tests that verifying empty signature returns error.
func TestECDSAP256_VerifyEmptySignature(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	alg := &ecdsaP256Algorithm{}

	err := alg.Verify([]byte("test"), []byte{}, &privKey.PublicKey)
	if err == nil {
		t.Fatal("expected error for empty signature")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error about empty signature, got: %v", err)
	}
}

// TestECDSAP384_VerifyEmptySignature tests that verifying empty signature returns error.
func TestECDSAP384_VerifyEmptySignature(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	alg := &ecdsaP384Algorithm{}

	err := alg.Verify([]byte("test"), []byte{}, &privKey.PublicKey)
	if err == nil {
		t.Fatal("expected error for empty signature")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error about empty signature, got: %v", err)
	}
}

// TestECDSAP256_SignWrongKeyType tests that signing with wrong key type returns error.
func TestECDSAP256_SignWrongKeyType(t *testing.T) {
	alg := &ecdsaP256Algorithm{}

	tests := []struct {
		name string
		key  any
	}{
		{"nil", nil},
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

// TestECDSAP384_SignWrongKeyType tests that signing with wrong key type returns error.
func TestECDSAP384_SignWrongKeyType(t *testing.T) {
	alg := &ecdsaP384Algorithm{}

	tests := []struct {
		name string
		key  any
	}{
		{"nil", nil},
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

// TestECDSAP256_VerifyWrongKeyType tests that verifying with wrong key type returns error.
func TestECDSAP256_VerifyWrongKeyType(t *testing.T) {
	alg := &ecdsaP256Algorithm{}

	tests := []struct {
		name string
		key  any
	}{
		{"nil", nil},
		{"string", "not a key"},
		{"int", 42},
		{"rsa key", &rsa.PublicKey{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := alg.Verify([]byte("test"), []byte("sig"), tt.key)
			if err == nil {
				t.Fatalf("expected error for key type %T", tt.key)
			}
		})
	}
}

// TestECDSAP384_VerifyWrongKeyType tests that verifying with wrong key type returns error.
func TestECDSAP384_VerifyWrongKeyType(t *testing.T) {
	alg := &ecdsaP384Algorithm{}

	tests := []struct {
		name string
		key  any
	}{
		{"nil", nil},
		{"string", "not a key"},
		{"int", 42},
		{"rsa key", &rsa.PublicKey{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := alg.Verify([]byte("test"), []byte("sig"), tt.key)
			if err == nil {
				t.Fatalf("expected error for key type %T", tt.key)
			}
		})
	}
}

// TestECDSAP256_CurveMismatch tests that P-256 algorithm rejects non-P-256 keys (T037).
func TestECDSAP256_CurveMismatch(t *testing.T) {
	alg := &ecdsaP256Algorithm{}

	// Generate P-384 key but try to use with P-256 algorithm
	p384Key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	// Should fail to sign with P-384 key
	_, err := alg.Sign([]byte("test"), p384Key)
	if err == nil {
		t.Fatal("expected error when using P-384 key with P-256 algorithm")
	}

	if !strings.Contains(err.Error(), "P-256") {
		t.Errorf("expected error about P-256 curve, got: %v", err)
	}

	// Should fail to verify with P-384 public key
	err = alg.Verify([]byte("test"), []byte("sig"), &p384Key.PublicKey)
	if err == nil {
		t.Fatal("expected error when verifying with P-384 public key")
	}

	if !strings.Contains(err.Error(), "P-256") {
		t.Errorf("expected error about P-256 curve, got: %v", err)
	}
}

// TestECDSAP384_CurveMismatch tests that P-384 algorithm rejects non-P-384 keys (T037).
func TestECDSAP384_CurveMismatch(t *testing.T) {
	alg := &ecdsaP384Algorithm{}

	// Generate P-256 key but try to use with P-384 algorithm
	p256Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Should fail to sign with P-256 key
	_, err := alg.Sign([]byte("test"), p256Key)
	if err == nil {
		t.Fatal("expected error when using P-256 key with P-384 algorithm")
	}

	if !strings.Contains(err.Error(), "P-384") {
		t.Errorf("expected error about P-384 curve, got: %v", err)
	}

	// Should fail to verify with P-256 public key
	err = alg.Verify([]byte("test"), []byte("sig"), &p256Key.PublicKey)
	if err == nil {
		t.Fatal("expected error when verifying with P-256 public key")
	}

	if !strings.Contains(err.Error(), "P-384") {
		t.Errorf("expected error about P-384 curve, got: %v", err)
	}
}

// TestECDSA_NonDeterministic tests that ECDSA produces different signatures (randomized mode, T038).
func TestECDSA_NonDeterministic(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	alg := &ecdsaP256Algorithm{}
	signatureBase := []byte("same message")

	// Sign the same message 5 times
	signatures := make([][]byte, 5)
	for i := range 5 {
		sig, err := alg.Sign(signatureBase, privKey)
		if err != nil {
			t.Fatalf("Sign() #%d failed: %v", i, err)
		}
		signatures[i] = sig
	}

	// At least one signature should be different (randomized ECDSA)
	allSame := true
	for i := 1; i < len(signatures); i++ {
		if string(signatures[i]) != string(signatures[0]) {
			allSame = false
			break
		}
	}

	if allSame {
		t.Error("all signatures are identical - expected randomized ECDSA to produce different signatures")
	}

	// But all should verify successfully
	for i, sig := range signatures {
		err := alg.Verify(signatureBase, sig, &privKey.PublicKey)
		if err != nil {
			t.Errorf("signature #%d failed verification: %v", i, err)
		}
	}

	t.Logf("Generated %d unique signatures for the same message (randomized ECDSA working correctly)", len(signatures))
}

// TestECDSAP256_RegisteredInRegistry tests that the algorithm is registered.
func TestECDSAP256_RegisteredInRegistry(t *testing.T) {
	alg, err := GetAlgorithm("ecdsa-p256-sha256")
	if err != nil {
		t.Fatalf("ecdsa-p256-sha256 not registered: %v", err)
	}

	if alg.ID() != "ecdsa-p256-sha256" {
		t.Errorf("expected ID %q, got %q", "ecdsa-p256-sha256", alg.ID())
	}
}

// TestECDSAP384_RegisteredInRegistry tests that the algorithm is registered.
func TestECDSAP384_RegisteredInRegistry(t *testing.T) {
	alg, err := GetAlgorithm("ecdsa-p384-sha384")
	if err != nil {
		t.Fatalf("ecdsa-p384-sha384 not registered: %v", err)
	}

	if alg.ID() != "ecdsa-p384-sha384" {
		t.Errorf("expected ID %q, got %q", "ecdsa-p384-sha384", alg.ID())
	}
}

// TestECDSA_LongSignatureBase tests signing and verifying long signature bases.
func TestECDSA_LongSignatureBase(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	alg := &ecdsaP256Algorithm{}

	// Create a 10KB signature base
	longBase := make([]byte, 10*1024)
	for i := range longBase {
		longBase[i] = byte(i % 256)
	}

	signature, err := alg.Sign(longBase, privKey)
	if err != nil {
		t.Fatalf("failed to sign long base: %v", err)
	}

	err = alg.Verify(longBase, signature, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to verify long base: %v", err)
	}

	t.Logf("Successfully signed and verified 10KB signature base")
}
