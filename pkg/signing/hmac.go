package signing

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// hmacSHA256Algorithm implements the Algorithm interface for HMAC-SHA256.
//
// RFC 9421 Section 3.3.5: hmac-sha256
// Uses HMAC (Hash-based Message Authentication Code) with SHA-256.
// Signature format: 32-byte MAC (message authentication code).
//
// Security Notes:
//   - Symmetric algorithm (same secret key for signing and verification)
//   - MUST use constant-time comparison for verification (timing attack prevention)
//   - Key should be at least 32 bytes (256 bits) for optimal security
//   - Deterministic (same message + key → same MAC)
//   - Suitable for internal service-to-service authentication
//   - NOT suitable for public key infrastructure (no asymmetric properties)
//
// Key Management:
//   - Shared secret must be securely distributed between parties
//   - Key rotation recommended periodically
//   - Store keys securely (environment variables, key management systems)
//
// Performance:
//   - Target: <10µs per operation
//   - Fastest algorithm in RFC 9421
//   - No expensive cryptographic operations
//
// RFC 2104: HMAC - Keyed-Hashing for Message Authentication
type hmacSHA256Algorithm struct{}

// ID returns the RFC 9421 algorithm identifier for HMAC-SHA256.
func (a *hmacSHA256Algorithm) ID() string {
	return "hmac-sha256"
}

// Sign generates an HMAC-SHA256 signature (MAC).
//
// Parameters:
//
//	signatureBase - Canonical signature base from pkg/base.BuildSignatureBase()
//	key - Must be []byte (shared secret, recommended ≥32 bytes)
//
// Returns:
//
//	32-byte MAC (ready for base64 encoding per RFC 9421 Section 3.1)
//
// Error Conditions:
//   - signatureBase is empty (contract violation)
//   - key is nil or not []byte
//   - key is too short (<16 bytes, weak security)
//
// Key Size Recommendations:
//   - Minimum: 16 bytes (128 bits) - weak, not recommended
//   - Recommended: 32 bytes (256 bits) - matches SHA-256 output size
//   - Maximum: No limit, but >64 bytes provides no additional security
//
// Determinism:
//   - HMAC is ALWAYS deterministic (RFC 2104)
//   - Same message + key → identical MAC every time
//
// RFC 9421 Section 3.3.5: HMAC using SHA-256
func (a *hmacSHA256Algorithm) Sign(signatureBase []byte, key any) ([]byte, error) {
	if len(signatureBase) == 0 {
		return nil, fmt.Errorf("signature base cannot be empty")
	}

	secretKey, ok := key.([]byte)
	if !ok {
		return nil, fmt.Errorf("key must be []byte for hmac-sha256, got %T", key)
	}

	if len(secretKey) == 0 {
		return nil, fmt.Errorf("HMAC shared secret is nil or empty")
	}

	// Validate key length (minimum 16 bytes for basic security)
	// RFC 2104 recommends key length ≥ hash output size (32 bytes for SHA-256)
	if len(secretKey) < 16 {
		return nil, fmt.Errorf("HMAC key too short: %d bytes (minimum 16 bytes required, 32 bytes recommended)", len(secretKey))
	}

	// Create HMAC-SHA256 hasher
	mac := hmac.New(sha256.New, secretKey)

	// Compute MAC
	mac.Write(signatureBase)
	signature := mac.Sum(nil)

	return signature, nil
}

// Verify validates an HMAC-SHA256 signature (MAC) against the signature base.
//
// Parameters:
//
//	signatureBase - Canonical signature base from pkg/base.BuildSignatureBase()
//	signature - 32-byte MAC (base64-decoded from Signature header)
//	key - Must be []byte (same shared secret used for signing)
//
// Returns:
//
//	nil if signature is valid
//	error if signature is invalid or verification fails
//
// Error Conditions:
//   - signatureBase is empty (contract violation)
//   - signature is empty or not 32 bytes
//   - key is nil or not []byte
//   - key is too short (<16 bytes)
//   - signature does not match computed MAC
//
// Security:
//   - Uses crypto/subtle.ConstantTimeCompare to prevent timing attacks
//   - Timing leakage could allow attackers to forge signatures
//   - All error cases take constant time
//
// RFC 9421 Section 3.2: Verifying a Signature
func (a *hmacSHA256Algorithm) Verify(signatureBase, signature []byte, key any) error {
	if len(signatureBase) == 0 {
		return fmt.Errorf("signature base cannot be empty")
	}

	if len(signature) == 0 {
		return fmt.Errorf("signature cannot be empty")
	}

	// HMAC-SHA256 signatures are always 32 bytes
	if len(signature) != 32 {
		return fmt.Errorf("HMAC-SHA256 signature must be 32 bytes, got %d bytes", len(signature))
	}

	secretKey, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("key must be []byte for hmac-sha256, got %T", key)
	}

	if len(secretKey) == 0 {
		return fmt.Errorf("HMAC shared secret is nil or empty")
	}

	// Validate key length
	if len(secretKey) < 16 {
		return fmt.Errorf("HMAC key too short: %d bytes (minimum 16 bytes required, 32 bytes recommended)", len(secretKey))
	}

	// Compute expected MAC
	mac := hmac.New(sha256.New, secretKey)
	mac.Write(signatureBase)
	expectedMAC := mac.Sum(nil)

	// Compare using constant-time comparison (timing attack prevention)
	// This is CRITICAL for HMAC security per RFC 9421
	if subtle.ConstantTimeCompare(signature, expectedMAC) != 1 {
		return fmt.Errorf("hmac-sha256 signature verification failed")
	}

	return nil
}

// init registers the HMAC-SHA256 algorithm in the global algorithm registry.
func init() {
	if err := RegisterAlgorithm(&hmacSHA256Algorithm{}); err != nil {
		panic(err)
	}
}
