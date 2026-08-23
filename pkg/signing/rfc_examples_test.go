package signing

// RFC 9421 Appendix B.2 Test Cases
//
// These tests implement the exact test vectors from RFC 9421 Appendix B.2.
// Keys are loaded from test-assets/ directory (extracted from RFC Appendix B.1).
//
// Reference: https://www.rfc-editor.org/rfc/rfc9421.html#appendix-B.2

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testAssetsDir is the path to test-assets/ relative to this package.
const testAssetsDir = "../../tests"

// =============================================================================
// Helper Functions
// =============================================================================

// loadTestFile loads a file from test-assets directory.
func loadTestFile(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testAssetsDir, filename)) //nolint:gosec // test assets from known directory
	if err != nil {
		t.Fatalf("failed to load test file %s: %v", filename, err)
	}
	return data
}

// loadPrivateKey loads and parses a private key from test-assets.
func loadPrivateKey(t *testing.T, filename string) any {
	t.Helper()
	data := loadTestFile(t, filename)
	key, err := ParsePrivateKey(data)
	if err != nil {
		t.Fatalf("failed to parse private key %s: %v", filename, err)
	}
	return key
}

// loadPublicKey loads and parses a public key from test-assets.
func loadPublicKey(t *testing.T, filename string) any {
	t.Helper()
	data := loadTestFile(t, filename)
	key, err := ParsePublicKey(data)
	if err != nil {
		t.Fatalf("failed to parse public key %s: %v", filename, err)
	}
	return key
}

// loadSharedSecret loads the HMAC shared secret from test-assets.
func loadSharedSecret(t *testing.T) []byte {
	t.Helper()
	data := loadTestFile(t, "test-shared-secret")
	// Remove any trailing newline
	secretB64 := strings.TrimSpace(string(data))
	secret, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		t.Fatalf("failed to decode shared secret: %v", err)
	}
	return secret
}

// ecdsaFixedToASN1 converts RFC 9421's fixed r||s ECDSA signature format to ASN.1 DER.
// RFC 9421 Section 3.3.4 specifies: "The signature output is encoded as the two integers
// r and s, each left-padded to n/2 octets if necessary, concatenated together."
// Go's crypto/ecdsa uses ASN.1 DER encoding, so we need to convert.
func ecdsaFixedToASN1(sig []byte) ([]byte, error) {
	if len(sig) != 64 {
		return nil, asn1.StructuralError{Msg: "ECDSA P-256 signature must be 64 bytes (r||s format)"}
	}

	// Split into r and s (32 bytes each for P-256)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	// Encode as ASN.1 DER SEQUENCE { r INTEGER, s INTEGER }
	return asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
}

// =============================================================================
// RFC 9421 Appendix B.2 Signature Bases
// =============================================================================
//
// NOTE: Line wrapping in the RFC uses "\" per RFC 8792. The signature bases
// below are the unwrapped versions exactly as they should appear.

// signatureBaseB21 is the signature base for B.2.1 Minimal Signature.
// RFC 9421 B.2.1: Empty covered components, only @signature-params.
const signatureBaseB21 = `"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`

// signatureBaseB22 is the signature base for B.2.2 Selective Covered Components.
// RFC 9421 B.2.2: Covers @authority, content-digest, @query-param;name="Pet".
const signatureBaseB22 = `"@authority": example.com
"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"@query-param";name="Pet": dog
"@signature-params": ("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"`

// signatureBaseB23 is the signature base for B.2.3 Full Coverage.
// RFC 9421 B.2.3: Covers date, @method, @path, @query, @authority,
// content-type, content-digest, content-length.
const signatureBaseB23 = `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@query": ?param=Value&Pet=dog
"@authority": example.com
"content-type": application/json
"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`

// signatureBaseB24 is the signature base for B.2.4 Signing a Response.
// RFC 9421 B.2.4: Response message, covers @status, content-type,
// content-digest, content-length.
const signatureBaseB24 = `"@status": 200
"content-type": application/json
"content-digest": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:
"content-length": 23
"@signature-params": ("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"`

// signatureBaseB25 is the signature base for B.2.5 Signing with HMAC.
// RFC 9421 B.2.5: Covers date, @authority, content-type.
const signatureBaseB25 = `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@authority": example.com
"content-type": application/json
"@signature-params": ("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`

// signatureBaseB26 is the signature base for B.2.6 Signing with Ed25519.
// RFC 9421 B.2.6: Covers date, @method, @path, @authority, content-type, content-length.
const signatureBaseB26 = `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@authority": example.com
"content-type": application/json
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`

// =============================================================================
// RFC 9421 Appendix B.2 Expected Signatures
// =============================================================================
//
// NOTE: These are the base64-encoded signatures from the RFC.
// Non-deterministic algorithms (RSA-PSS, ECDSA) produce different signatures
// each time. ECDSA B.2.4 signature is kept because it can be verified after
// converting from RFC's r||s format to Go's ASN.1 DER format.

// expectedSignatureB24 is the RFC example signature for B.2.4.
// Algorithm: ecdsa-p256-sha256 (non-deterministic, but verifiable)
const expectedSignatureB24 = "wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw=="

// expectedSignatureB25 is the RFC example signature for B.2.5.
// Algorithm: hmac-sha256 (DETERMINISTIC - must match exactly)
const expectedSignatureB25 = "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8="

// expectedSignatureB26 is the RFC example signature for B.2.6.
// Algorithm: ed25519 (DETERMINISTIC - must match exactly)
const expectedSignatureB26 = "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=="

// =============================================================================
// Test Cases
// =============================================================================

// TestRFC9421_B2_1_MinimalSignature tests minimal RSA-PSS signature.
//
// RFC 9421 Appendix B.2.1: Minimal Signature Using rsa-pss-sha512
//
// This test validates RSA-PSS signature generation with:
//   - Empty covered components list (only @signature-params)
//   - Signature parameters: created=1618884473, keyid="test-key-rsa-pss",
//     nonce="b3k2pp5k7z-50gnwp.yemd"
//
// Key: test-key-rsa-private.pem / test-key-rsa-public.pem
// (Note: RFC's test-key-rsa-pss uses PKCS#8 with RSA-PSS OID not supported by Go stdlib,
// but regular RSA keys work correctly with RSA-PSS algorithm)
// Algorithm: rsa-pss-sha512
// Deterministic: No (RSA-PSS uses random salt)
func TestRFC9421_B2_1_MinimalSignature(t *testing.T) {
	privKey := loadPrivateKey(t, "test-key-rsa-private.pem").(*rsa.PrivateKey)
	pubKey := loadPublicKey(t, "test-key-rsa-public.pem").(*rsa.PublicKey)

	alg, err := GetAlgorithm("rsa-pss-sha512")
	if err != nil {
		t.Fatalf("failed to get algorithm: %v", err)
	}

	signatureBase := []byte(signatureBaseB21)

	// Sign (RSA-PSS is non-deterministic, output differs each time)
	sig, err := alg.Sign(signatureBase, privKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// RSA 2048-bit key produces 256-byte signature
	if len(sig) != 256 {
		t.Errorf("expected signature length 256, got %d", len(sig))
	}

	// Verify our generated signature
	if err := alg.Verify(signatureBase, sig, pubKey); err != nil {
		t.Fatalf("failed to verify our signature: %v", err)
	}

	// Note: We cannot verify the RFC example signature because it was created with
	// test-key-rsa-pss (PKCS#8 with RSA-PSS OID) which Go stdlib doesn't support.
	// Our test proves the algorithm works correctly with the standard RSA key.

	t.Logf("B.2.1: Generated signature length: %d bytes", len(sig))
	t.Logf("B.2.1: Sign and verify successful with RSA-PSS algorithm")
}

// TestRFC9421_B2_2_SelectiveCoverage tests RSA-PSS with selective components.
//
// RFC 9421 Appendix B.2.2: Selective Covered Components Using rsa-pss-sha512
//
// This test validates RSA-PSS signature generation with selective coverage:
//   - Covered components: @authority, content-digest, @query-param;name="Pet"
//   - Signature parameters: created=1618884473, keyid="test-key-rsa-pss",
//     tag="header-example"
//
// Key: test-key-rsa-private.pem / test-key-rsa-public.pem
// (Note: RFC's test-key-rsa-pss uses PKCS#8 with RSA-PSS OID not supported by Go stdlib)
// Algorithm: rsa-pss-sha512
// Deterministic: No (RSA-PSS uses random salt)
func TestRFC9421_B2_2_SelectiveCoverage(t *testing.T) {
	privKey := loadPrivateKey(t, "test-key-rsa-private.pem").(*rsa.PrivateKey)
	pubKey := loadPublicKey(t, "test-key-rsa-public.pem").(*rsa.PublicKey)

	alg, err := GetAlgorithm("rsa-pss-sha512")
	if err != nil {
		t.Fatalf("failed to get algorithm: %v", err)
	}

	signatureBase := []byte(signatureBaseB22)

	// Sign
	sig, err := alg.Sign(signatureBase, privKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Verify our generated signature
	if err := alg.Verify(signatureBase, sig, pubKey); err != nil {
		t.Fatalf("failed to verify our signature: %v", err)
	}

	// Note: We cannot verify the RFC example signature because it was created with
	// test-key-rsa-pss (PKCS#8 with RSA-PSS OID) which Go stdlib doesn't support.

	t.Logf("B.2.2: Generated signature length: %d bytes", len(sig))
	t.Logf("B.2.2: Sign and verify successful with RSA-PSS algorithm")
}

// TestRFC9421_B2_3_FullCoverage tests RSA-PSS with full component coverage.
//
// RFC 9421 Appendix B.2.3: Full Coverage Using rsa-pss-sha512
//
// This test validates RSA-PSS signature generation with full coverage:
//   - Covered components: date, @method, @path, @query, @authority,
//     content-type, content-digest, content-length
//   - Signature parameters: created=1618884473, keyid="test-key-rsa-pss"
//   - Note: Host header is NOT covered (using @authority instead)
//
// Key: test-key-rsa-private.pem / test-key-rsa-public.pem
// (Note: RFC's test-key-rsa-pss uses PKCS#8 with RSA-PSS OID not supported by Go stdlib)
// Algorithm: rsa-pss-sha512
// Deterministic: No (RSA-PSS uses random salt)
func TestRFC9421_B2_3_FullCoverage(t *testing.T) {
	privKey := loadPrivateKey(t, "test-key-rsa-private.pem").(*rsa.PrivateKey)
	pubKey := loadPublicKey(t, "test-key-rsa-public.pem").(*rsa.PublicKey)

	alg, err := GetAlgorithm("rsa-pss-sha512")
	if err != nil {
		t.Fatalf("failed to get algorithm: %v", err)
	}

	signatureBase := []byte(signatureBaseB23)

	// Sign
	sig, err := alg.Sign(signatureBase, privKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Verify our generated signature
	if err := alg.Verify(signatureBase, sig, pubKey); err != nil {
		t.Fatalf("failed to verify our signature: %v", err)
	}

	// Note: We cannot verify the RFC example signature because it was created with
	// test-key-rsa-pss (PKCS#8 with RSA-PSS OID) which Go stdlib doesn't support.

	t.Logf("B.2.3: Generated signature length: %d bytes", len(sig))
	t.Logf("B.2.3: Sign and verify successful with RSA-PSS algorithm")
}

// TestRFC9421_B2_4_SigningResponse tests ECDSA P-256 on a response message.
//
// RFC 9421 Appendix B.2.4: Signing a Response Using ecdsa-p256-sha256
//
// This test validates ECDSA signature generation on an HTTP response:
// - Covered components: @status, content-type, content-digest, content-length
// - Signature parameters: created=1618884473, keyid="test-key-ecc-p256"
// - Uses test-response message (HTTP 200 OK)
//
// Key: test-key-ecc-p256-private.pem / test-key-ecc-p256-public.pem
// Algorithm: ecdsa-p256-sha256
// Deterministic: No (ECDSA uses random k value)
func TestRFC9421_B2_4_SigningResponse(t *testing.T) {
	privKey := loadPrivateKey(t, "test-key-ecc-p256-private.pem").(*ecdsa.PrivateKey)
	pubKey := loadPublicKey(t, "test-key-ecc-p256-public.pem").(*ecdsa.PublicKey)

	alg, err := GetAlgorithm("ecdsa-p256-sha256")
	if err != nil {
		t.Fatalf("failed to get algorithm: %v", err)
	}

	signatureBase := []byte(signatureBaseB24)

	// Sign
	sig, err := alg.Sign(signatureBase, privKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// ECDSA P-256 signatures are DER-encoded, typically 70-72 bytes
	if len(sig) < 64 || len(sig) > 80 {
		t.Errorf("unexpected ECDSA signature length: %d", len(sig))
	}

	// Verify our generated signature
	if err := alg.Verify(signatureBase, sig, pubKey); err != nil {
		t.Fatalf("failed to verify our signature: %v", err)
	}

	// Verify RFC example signature
	// RFC 9421 uses fixed 64-byte r||s format, but Go uses ASN.1 DER encoding.
	// Convert the RFC signature from r||s to ASN.1 DER format.
	rfcSigRaw, err := base64.StdEncoding.DecodeString(expectedSignatureB24)
	if err != nil {
		t.Fatalf("failed to decode RFC signature: %v", err)
	}
	rfcSigDER, err := ecdsaFixedToASN1(rfcSigRaw)
	if err != nil {
		t.Fatalf("failed to convert RFC signature to ASN.1: %v", err)
	}
	if err := alg.Verify(signatureBase, rfcSigDER, pubKey); err != nil {
		t.Fatalf("failed to verify RFC example signature: %v", err)
	}

	t.Logf("B.2.4: Generated signature length: %d bytes (DER)", len(sig))
	t.Logf("B.2.4: RFC example signature verified (converted from r||s to DER)")
}

// TestRFC9421_B2_5_SigningRequest_HMAC tests HMAC-SHA256 signature.
//
// RFC 9421 Appendix B.2.5: Signing a Request Using hmac-sha256
//
// This test validates HMAC signature generation:
// - Covered components: date, @authority, content-type
// - Signature parameters: created=1618884473, keyid="test-shared-secret"
// - DETERMINISTIC: Same input always produces same output
//
// Key: test-shared-secret (64-byte shared secret, base64-encoded)
// Algorithm: hmac-sha256
// Deterministic: Yes
func TestRFC9421_B2_5_SigningRequest_HMAC(t *testing.T) {
	secret := loadSharedSecret(t)

	alg, err := GetAlgorithm("hmac-sha256")
	if err != nil {
		t.Fatalf("failed to get algorithm: %v", err)
	}

	signatureBase := []byte(signatureBaseB25)

	// Sign
	sig, err := alg.Sign(signatureBase, secret)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// HMAC-SHA256 always produces 32-byte signature
	if len(sig) != 32 {
		t.Errorf("expected HMAC signature length 32, got %d", len(sig))
	}

	// HMAC is deterministic - signature MUST match RFC exactly
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	if sigB64 != expectedSignatureB25 {
		t.Errorf("HMAC signature mismatch (deterministic algorithm)\ngot:  %s\nwant: %s",
			sigB64, expectedSignatureB25)
	}

	// Verify
	if err := alg.Verify(signatureBase, sig, secret); err != nil {
		t.Fatalf("failed to verify: %v", err)
	}

	t.Logf("B.2.5: HMAC signature matches RFC example exactly (deterministic)")
}

// TestRFC9421_B2_6_SigningRequest_Ed25519 tests Ed25519 signature.
//
// RFC 9421 Appendix B.2.6: Signing a Request Using ed25519
//
// This test validates Ed25519 signature generation:
//   - Covered components: date, @method, @path, @authority, content-type,
//     content-length
//   - Signature parameters: created=1618884473, keyid="test-key-ed25519"
//   - DETERMINISTIC: Same input always produces same output (RFC 8032)
//
// Key: test-key-ed25519-private.pem / test-key-ed25519-public.pem
// Algorithm: ed25519
// Deterministic: Yes
func TestRFC9421_B2_6_SigningRequest_Ed25519(t *testing.T) {
	privKey := loadPrivateKey(t, "test-key-ed25519-private.pem").(ed25519.PrivateKey)
	pubKey := loadPublicKey(t, "test-key-ed25519-public.pem").(ed25519.PublicKey)

	alg, err := GetAlgorithm("ed25519")
	if err != nil {
		t.Fatalf("failed to get algorithm: %v", err)
	}

	signatureBase := []byte(signatureBaseB26)

	// Sign
	sig, err := alg.Sign(signatureBase, privKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Ed25519 always produces 64-byte signature
	if len(sig) != 64 {
		t.Errorf("expected Ed25519 signature length 64, got %d", len(sig))
	}

	// Ed25519 is deterministic - signature MUST match RFC exactly
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	if sigB64 != expectedSignatureB26 {
		t.Errorf("Ed25519 signature mismatch (deterministic algorithm)\ngot:  %s\nwant: %s",
			sigB64, expectedSignatureB26)
	}

	// Verify
	if err := alg.Verify(signatureBase, sig, pubKey); err != nil {
		t.Fatalf("failed to verify: %v", err)
	}

	t.Logf("B.2.6: Ed25519 signature matches RFC example exactly (deterministic)")
}
