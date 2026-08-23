package signing

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// TestParsePrivateKey_RSA_PKCS1 tests parsing RSA private key in PKCS#1 format.
func TestParsePrivateKey_RSA_PKCS1(t *testing.T) {
	// Generate test RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Encode as PKCS#1 PEM
	derBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derBytes,
	})

	// Parse and verify
	parsed, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("failed to parse PKCS#1 RSA key: %v", err)
	}

	parsedRSA, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
	}

	if parsedRSA.N.Cmp(rsaKey.N) != 0 {
		t.Error("parsed RSA key modulus does not match original")
	}
}

// TestParsePrivateKey_RSA_PKCS8 tests parsing RSA private key in PKCS#8 format.
func TestParsePrivateKey_RSA_PKCS8(t *testing.T) {
	// Generate test RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Encode as PKCS#8 PEM
	derBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("failed to marshal PKCS#8 key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	})

	// Parse and verify
	parsed, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("failed to parse PKCS#8 RSA key: %v", err)
	}

	parsedRSA, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
	}

	if parsedRSA.N.Cmp(rsaKey.N) != 0 {
		t.Error("parsed RSA key modulus does not match original")
	}
}

// TestParsePrivateKey_ECDSA_SEC1 tests parsing ECDSA private key in SEC1 format.
func TestParsePrivateKey_ECDSA_SEC1(t *testing.T) {
	// Generate test ECDSA key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	// Encode as SEC1 PEM
	derBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derBytes,
	})

	// Parse and verify
	parsed, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("failed to parse SEC1 ECDSA key: %v", err)
	}

	parsedEC, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsed)
	}

	if parsedEC.X.Cmp(ecKey.X) != 0 || parsedEC.Y.Cmp(ecKey.Y) != 0 {
		t.Error("parsed ECDSA key does not match original")
	}
}

// TestParsePrivateKey_Ed25519_PKCS8 tests parsing Ed25519 private key in PKCS#8 format.
func TestParsePrivateKey_Ed25519_PKCS8(t *testing.T) {
	// Generate test Ed25519 key
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	// Encode as PKCS#8 PEM
	derBytes, err := x509.MarshalPKCS8PrivateKey(edKey)
	if err != nil {
		t.Fatalf("failed to marshal Ed25519 key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	})

	// Parse and verify
	parsed, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("failed to parse PKCS#8 Ed25519 key: %v", err)
	}

	parsedEd, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey, got %T", parsed)
	}

	if len(parsedEd) != ed25519.PrivateKeySize {
		t.Errorf("expected key size %d, got %d", ed25519.PrivateKeySize, len(parsedEd))
	}
}

// TestParsePrivateKey_Empty tests that empty key data returns error.
func TestParsePrivateKey_Empty(t *testing.T) {
	_, err := ParsePrivateKey([]byte{})
	if err == nil {
		t.Fatal("expected error for empty key data, got nil")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error message about empty data, got: %v", err)
	}
}

// TestParsePrivateKey_Invalid tests that invalid key data returns error.
func TestParsePrivateKey_Invalid(t *testing.T) {
	invalidKeys := []struct {
		name string
		data []byte
	}{
		{"random bytes", []byte("this is not a valid key")},
		{"invalid PEM", []byte("-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----")},
		{"corrupted DER", []byte{0x30, 0x82, 0x01, 0x00}}, // Incomplete ASN.1 structure
	}

	for _, tt := range invalidKeys {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePrivateKey(tt.data)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

// TestParsePrivateKey_RSA_TooSmall tests that RSA keys < 2048 bits are rejected.
func TestParsePrivateKey_RSA_TooSmall(t *testing.T) {
	// Generate 1024-bit RSA key (too small)
	//nolint:gosec // G403: Intentionally small key to test rejection
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Encode as PKCS#8 PEM
	derBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	})

	// Parse should fail due to key size
	_, err = ParsePrivateKey(pemBytes)
	if err == nil {
		t.Fatal("expected error for 1024-bit RSA key, got nil")
	}

	if !strings.Contains(err.Error(), "too small") && !strings.Contains(err.Error(), "2048") {
		t.Errorf("expected error about key size, got: %v", err)
	}
}

// TestParsePublicKey_RSA_PKIX tests parsing RSA public key in PKIX format.
func TestParsePublicKey_RSA_PKIX(t *testing.T) {
	// Generate test RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Encode public key as PKIX PEM
	derBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})

	// Parse and verify
	parsed, err := ParsePublicKey(pemBytes)
	if err != nil {
		t.Fatalf("failed to parse PKIX RSA public key: %v", err)
	}

	parsedRSA, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", parsed)
	}

	if parsedRSA.N.Cmp(rsaKey.PublicKey.N) != 0 {
		t.Error("parsed RSA public key modulus does not match original")
	}
}

// TestParsePublicKey_ECDSA_PKIX tests parsing ECDSA public key in PKIX format.
func TestParsePublicKey_ECDSA_PKIX(t *testing.T) {
	// Generate test ECDSA key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	// Encode public key as PKIX PEM
	derBytes, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})

	// Parse and verify
	parsed, err := ParsePublicKey(pemBytes)
	if err != nil {
		t.Fatalf("failed to parse PKIX ECDSA public key: %v", err)
	}

	parsedEC, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", parsed)
	}

	if parsedEC.X.Cmp(ecKey.PublicKey.X) != 0 || parsedEC.Y.Cmp(ecKey.PublicKey.Y) != 0 {
		t.Error("parsed ECDSA public key does not match original")
	}
}

// TestParsePublicKey_Empty tests that empty key data returns error.
func TestParsePublicKey_Empty(t *testing.T) {
	_, err := ParsePublicKey([]byte{})
	if err == nil {
		t.Fatal("expected error for empty key data, got nil")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected error message about empty data, got: %v", err)
	}
}

// =============================================================================
// Strict Parsing Function Tests
// =============================================================================

// TestParsePKCS1PrivateKey tests the strict PKCS#1 private key parser.
func TestParsePKCS1PrivateKey(t *testing.T) {
	// Generate test RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Test with correct format (PKCS#1)
	t.Run("valid PKCS#1", func(t *testing.T) {
		derBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: derBytes,
		})

		parsed, err := ParsePKCS1PrivateKey(pemBytes)
		if err != nil {
			t.Fatalf("failed to parse PKCS#1 key: %v", err)
		}

		if parsed.N.Cmp(rsaKey.N) != 0 {
			t.Error("parsed RSA key modulus does not match original")
		}
	})

	// Test with DER format
	t.Run("valid PKCS#1 DER", func(t *testing.T) {
		derBytes := x509.MarshalPKCS1PrivateKey(rsaKey)

		parsed, err := ParsePKCS1PrivateKey(derBytes)
		if err != nil {
			t.Fatalf("failed to parse PKCS#1 DER key: %v", err)
		}

		if parsed.N.Cmp(rsaKey.N) != 0 {
			t.Error("parsed RSA key modulus does not match original")
		}
	})

	// Test rejection of PKCS#8 format
	t.Run("rejects PKCS#8", func(t *testing.T) {
		derBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		if err != nil {
			t.Fatalf("failed to marshal PKCS#8 key: %v", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: derBytes,
		})

		_, err = ParsePKCS1PrivateKey(pemBytes)
		if err == nil {
			t.Fatal("expected error when parsing PKCS#8 key with PKCS#1 parser")
		}
		if !strings.Contains(err.Error(), "PKCS#1") {
			t.Errorf("error should mention PKCS#1, got: %v", err)
		}
	})

	// Test empty data
	t.Run("empty data", func(t *testing.T) {
		_, err := ParsePKCS1PrivateKey([]byte{})
		if err == nil {
			t.Fatal("expected error for empty data")
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("expected error about empty data, got: %v", err)
		}
	})

	// Test RSA key too small
	t.Run("rejects small RSA key", func(t *testing.T) {
		//nolint:gosec // G403: Intentionally small key to test rejection
		smallKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("failed to generate small RSA key: %v", err)
		}
		derBytes := x509.MarshalPKCS1PrivateKey(smallKey)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: derBytes,
		})

		_, err = ParsePKCS1PrivateKey(pemBytes)
		if err == nil {
			t.Fatal("expected error for small RSA key")
		}
		if !strings.Contains(err.Error(), "2048") {
			t.Errorf("expected error about minimum size, got: %v", err)
		}
	})
}

// TestParsePKCS8PrivateKey tests the strict PKCS#8 private key parser.
func TestParsePKCS8PrivateKey(t *testing.T) {
	// Test with RSA key
	t.Run("valid PKCS#8 RSA", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		derBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		if err != nil {
			t.Fatalf("failed to marshal PKCS#8 key: %v", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: derBytes,
		})

		parsed, err := ParsePKCS8PrivateKey(pemBytes)
		if err != nil {
			t.Fatalf("failed to parse PKCS#8 RSA key: %v", err)
		}

		parsedRSA, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
		}
		if parsedRSA.N.Cmp(rsaKey.N) != 0 {
			t.Error("parsed RSA key modulus does not match original")
		}
	})

	// Test with ECDSA key
	t.Run("valid PKCS#8 ECDSA", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		derBytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
		if err != nil {
			t.Fatalf("failed to marshal PKCS#8 key: %v", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: derBytes,
		})

		parsed, err := ParsePKCS8PrivateKey(pemBytes)
		if err != nil {
			t.Fatalf("failed to parse PKCS#8 ECDSA key: %v", err)
		}

		_, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsed)
		}
	})

	// Test with Ed25519 key
	t.Run("valid PKCS#8 Ed25519", func(t *testing.T) {
		_, edKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate Ed25519 key: %v", err)
		}

		derBytes, err := x509.MarshalPKCS8PrivateKey(edKey)
		if err != nil {
			t.Fatalf("failed to marshal PKCS#8 key: %v", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: derBytes,
		})

		parsed, err := ParsePKCS8PrivateKey(pemBytes)
		if err != nil {
			t.Fatalf("failed to parse PKCS#8 Ed25519 key: %v", err)
		}

		_, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			t.Fatalf("expected ed25519.PrivateKey, got %T", parsed)
		}
	})

	// Test rejection of PKCS#1 format
	t.Run("rejects PKCS#1", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		derBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: derBytes,
		})

		_, err = ParsePKCS8PrivateKey(pemBytes)
		if err == nil {
			t.Fatal("expected error when parsing PKCS#1 key with PKCS#8 parser")
		}
		if !strings.Contains(err.Error(), "PKCS#8") {
			t.Errorf("error should mention PKCS#8, got: %v", err)
		}
	})

	// Test rejection of SEC1 format
	t.Run("rejects SEC1", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		derBytes, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			t.Fatalf("failed to marshal SEC1 key: %v", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: derBytes,
		})

		_, err = ParsePKCS8PrivateKey(pemBytes)
		if err == nil {
			t.Fatal("expected error when parsing SEC1 key with PKCS#8 parser")
		}
		if !strings.Contains(err.Error(), "PKCS#8") {
			t.Errorf("error should mention PKCS#8, got: %v", err)
		}
	})

	// Test empty data
	t.Run("empty data", func(t *testing.T) {
		_, err := ParsePKCS8PrivateKey([]byte{})
		if err == nil {
			t.Fatal("expected error for empty data")
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("expected error about empty data, got: %v", err)
		}
	})
}

// TestParseSEC1PrivateKey tests the strict SEC1 private key parser.
func TestParseSEC1PrivateKey(t *testing.T) {
	// Generate test ECDSA key
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	// Test with correct format (SEC1)
	t.Run("valid SEC1", func(t *testing.T) {
		derBytes, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			t.Fatalf("failed to marshal SEC1 key: %v", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: derBytes,
		})

		parsed, err := ParseSEC1PrivateKey(pemBytes)
		if err != nil {
			t.Fatalf("failed to parse SEC1 key: %v", err)
		}

		if parsed.X.Cmp(ecKey.X) != 0 || parsed.Y.Cmp(ecKey.Y) != 0 {
			t.Error("parsed ECDSA key does not match original")
		}
	})

	// Test with DER format
	t.Run("valid SEC1 DER", func(t *testing.T) {
		derBytes, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			t.Fatalf("failed to marshal SEC1 key: %v", err)
		}

		parsed, err := ParseSEC1PrivateKey(derBytes)
		if err != nil {
			t.Fatalf("failed to parse SEC1 DER key: %v", err)
		}

		if parsed.X.Cmp(ecKey.X) != 0 || parsed.Y.Cmp(ecKey.Y) != 0 {
			t.Error("parsed ECDSA key does not match original")
		}
	})

	// Test rejection of PKCS#8 format
	t.Run("rejects PKCS#8", func(t *testing.T) {
		derBytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
		if err != nil {
			t.Fatalf("failed to marshal PKCS#8 key: %v", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: derBytes,
		})

		_, err = ParseSEC1PrivateKey(pemBytes)
		if err == nil {
			t.Fatal("expected error when parsing PKCS#8 key with SEC1 parser")
		}
		if !strings.Contains(err.Error(), "SEC1") {
			t.Errorf("error should mention SEC1, got: %v", err)
		}
	})

	// Test rejection of PKCS#1 RSA format
	t.Run("rejects PKCS#1 RSA", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		derBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: derBytes,
		})

		_, err = ParseSEC1PrivateKey(pemBytes)
		if err == nil {
			t.Fatal("expected error when parsing PKCS#1 key with SEC1 parser")
		}
		if !strings.Contains(err.Error(), "SEC1") {
			t.Errorf("error should mention SEC1, got: %v", err)
		}
	})

	// Test empty data
	t.Run("empty data", func(t *testing.T) {
		_, err := ParseSEC1PrivateKey([]byte{})
		if err == nil {
			t.Fatal("expected error for empty data")
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("expected error about empty data, got: %v", err)
		}
	})
}

// TestParsePKIXPublicKey tests the strict PKIX public key parser.
func TestParsePKIXPublicKey(t *testing.T) {
	// Test with RSA key
	t.Run("valid PKIX RSA", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		derBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		if err != nil {
			t.Fatalf("failed to marshal PKIX key: %v", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derBytes,
		})

		parsed, err := ParsePKIXPublicKey(pemBytes)
		if err != nil {
			t.Fatalf("failed to parse PKIX RSA key: %v", err)
		}

		parsedRSA, ok := parsed.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("expected *rsa.PublicKey, got %T", parsed)
		}
		if parsedRSA.N.Cmp(rsaKey.PublicKey.N) != 0 {
			t.Error("parsed RSA key modulus does not match original")
		}
	})

	// Test with ECDSA key
	t.Run("valid PKIX ECDSA", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		derBytes, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
		if err != nil {
			t.Fatalf("failed to marshal PKIX key: %v", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derBytes,
		})

		parsed, err := ParsePKIXPublicKey(pemBytes)
		if err != nil {
			t.Fatalf("failed to parse PKIX ECDSA key: %v", err)
		}

		_, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("expected *ecdsa.PublicKey, got %T", parsed)
		}
	})

	// Test with Ed25519 key
	t.Run("valid PKIX Ed25519", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate Ed25519 key: %v", err)
		}

		derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			t.Fatalf("failed to marshal PKIX key: %v", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derBytes,
		})

		parsed, err := ParsePKIXPublicKey(pemBytes)
		if err != nil {
			t.Fatalf("failed to parse PKIX Ed25519 key: %v", err)
		}

		_, ok := parsed.(ed25519.PublicKey)
		if !ok {
			t.Fatalf("expected ed25519.PublicKey, got %T", parsed)
		}
	})

	// Test rejection of PKCS#1 RSA format
	t.Run("rejects PKCS#1 RSA", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		derBytes := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: derBytes,
		})

		_, err = ParsePKIXPublicKey(pemBytes)
		if err == nil {
			t.Fatal("expected error when parsing PKCS#1 key with PKIX parser")
		}
		if !strings.Contains(err.Error(), "PKIX") {
			t.Errorf("error should mention PKIX, got: %v", err)
		}
	})

	// Test empty data
	t.Run("empty data", func(t *testing.T) {
		_, err := ParsePKIXPublicKey([]byte{})
		if err == nil {
			t.Fatal("expected error for empty data")
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("expected error about empty data, got: %v", err)
		}
	})

	// Test RSA key too small
	t.Run("rejects small RSA key", func(t *testing.T) {
		//nolint:gosec // G403: Intentionally small key to test rejection
		smallKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("failed to generate small RSA key: %v", err)
		}
		derBytes, err := x509.MarshalPKIXPublicKey(&smallKey.PublicKey)
		if err != nil {
			t.Fatalf("failed to marshal PKIX key: %v", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derBytes,
		})

		_, err = ParsePKIXPublicKey(pemBytes)
		if err == nil {
			t.Fatal("expected error for small RSA key")
		}
		if !strings.Contains(err.Error(), "2048") {
			t.Errorf("expected error about minimum size, got: %v", err)
		}
	})
}

// TestParsePKCS1PublicKey tests the strict PKCS#1 public key parser.
func TestParsePKCS1PublicKey(t *testing.T) {
	// Generate test RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Test with correct format (PKCS#1)
	t.Run("valid PKCS#1", func(t *testing.T) {
		derBytes := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: derBytes,
		})

		parsed, err := ParsePKCS1PublicKey(pemBytes)
		if err != nil {
			t.Fatalf("failed to parse PKCS#1 public key: %v", err)
		}

		if parsed.N.Cmp(rsaKey.PublicKey.N) != 0 {
			t.Error("parsed RSA public key modulus does not match original")
		}
	})

	// Test with DER format
	t.Run("valid PKCS#1 DER", func(t *testing.T) {
		derBytes := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)

		parsed, err := ParsePKCS1PublicKey(derBytes)
		if err != nil {
			t.Fatalf("failed to parse PKCS#1 DER public key: %v", err)
		}

		if parsed.N.Cmp(rsaKey.PublicKey.N) != 0 {
			t.Error("parsed RSA public key modulus does not match original")
		}
	})

	// Test rejection of PKIX format
	t.Run("rejects PKIX", func(t *testing.T) {
		derBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		if err != nil {
			t.Fatalf("failed to marshal PKIX key: %v", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derBytes,
		})

		_, err = ParsePKCS1PublicKey(pemBytes)
		if err == nil {
			t.Fatal("expected error when parsing PKIX key with PKCS#1 parser")
		}
		if !strings.Contains(err.Error(), "PKCS#1") {
			t.Errorf("error should mention PKCS#1, got: %v", err)
		}
	})

	// Test empty data
	t.Run("empty data", func(t *testing.T) {
		_, err := ParsePKCS1PublicKey([]byte{})
		if err == nil {
			t.Fatal("expected error for empty data")
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("expected error about empty data, got: %v", err)
		}
	})

	// Test RSA key too small
	t.Run("rejects small RSA key", func(t *testing.T) {
		//nolint:gosec // G403: Intentionally small key to test rejection
		smallKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("failed to generate small RSA key: %v", err)
		}
		derBytes := x509.MarshalPKCS1PublicKey(&smallKey.PublicKey)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: derBytes,
		})

		_, err = ParsePKCS1PublicKey(pemBytes)
		if err == nil {
			t.Fatal("expected error for small RSA key")
		}
		if !strings.Contains(err.Error(), "2048") {
			t.Errorf("expected error about minimum size, got: %v", err)
		}
	})
}
