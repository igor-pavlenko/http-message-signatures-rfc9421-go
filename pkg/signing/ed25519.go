package signing

import (
	"crypto/ed25519"
	"fmt"
)

// ed25519Algorithm implements the Algorithm interface for Ed25519.
//
// RFC 9421 Section 3.3.6: ed25519
// Uses Edwards-curve Digital Signature Algorithm (EdDSA) with Curve25519.
// Signature format: 64-byte signature (fixed length).
//
// Security Notes:
//   - Deterministic signatures (same message + key → same signature)
//   - No configuration required (hash function built into Ed25519)
//   - Fastest signature algorithm in RFC 9421 (<50µs per operation)
//   - 128-bit security level (equivalent to 3072-bit RSA)
//   - Immune to timing attacks and weak RNG issues
//
// Key Format:
//   - Private key: 64 bytes (32-byte seed + 32-byte public key)
//   - Public key: 32 bytes
//   - Use crypto/ed25519.GenerateKey() to create keys
//
// RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
type ed25519Algorithm struct{}

// ID returns the RFC 9421 algorithm identifier for Ed25519.
func (a *ed25519Algorithm) ID() string {
	return "ed25519"
}

// Sign generates an Ed25519 signature.
//
// Parameters:
//
//	signatureBase - Canonical signature base from pkg/base.BuildSignatureBase()
//	key - Must be ed25519.PrivateKey (64 bytes)
//
// Returns:
//
//	64-byte signature (ready for base64 encoding per RFC 9421 Section 3.1)
//
// Error Conditions:
//   - signatureBase is empty (contract violation)
//   - key is nil or not ed25519.PrivateKey
//   - key length is not 64 bytes (ed25519.PrivateKeySize)
//
// Determinism:
//   - Ed25519 is ALWAYS deterministic (RFC 8032)
//   - Same message + key → identical signature every time
//   - No randomness involved in signing process
//
// Performance:
//   - Target: <50µs per signature
//   - No expensive operations (no modular exponentiation)
//   - Constant-time implementation in stdlib
//
// RFC 9421 Section 3.3.6: Ed25519 Signature Algorithm
func (a *ed25519Algorithm) Sign(signatureBase []byte, key any) ([]byte, error) {
	if len(signatureBase) == 0 {
		return nil, fmt.Errorf("signature base cannot be empty")
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key must be ed25519.PrivateKey for ed25519, got %T", key)
	}

	if len(edKey) == 0 {
		return nil, fmt.Errorf("ed25519 private key is nil or empty")
	}

	// Validate key size (64 bytes per RFC 8032)
	if len(edKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519 private key must be %d bytes, got %d bytes", ed25519.PrivateKeySize, len(edKey))
	}

	// Sign the signature base (deterministic)
	// Ed25519 internally hashes the message with SHA-512
	signature := ed25519.Sign(edKey, signatureBase)

	return signature, nil
}

// Verify validates an Ed25519 signature against the signature base.
//
// Parameters:
//
//	signatureBase - Canonical signature base from pkg/base.BuildSignatureBase()
//	signature - 64-byte signature (base64-decoded from Signature header)
//	key - Must be ed25519.PublicKey (32 bytes)
//
// Returns:
//
//	nil if signature is valid
//	error if signature is invalid or verification fails
//
// Error Conditions:
//   - signatureBase is empty (contract violation)
//   - signature is empty or not 64 bytes
//   - key is nil or not ed25519.PublicKey
//   - key length is not 32 bytes (ed25519.PublicKeySize)
//   - signature is cryptographically invalid
//   - signature does not match signatureBase
//
// Performance:
//   - Target: <50µs per verification
//   - Constant-time verification (timing attack resistant)
//
// RFC 9421 Section 3.2: Verifying a Signature
func (a *ed25519Algorithm) Verify(signatureBase, signature []byte, key any) error {
	if len(signatureBase) == 0 {
		return fmt.Errorf("signature base cannot be empty")
	}

	if len(signature) == 0 {
		return fmt.Errorf("signature cannot be empty")
	}

	// Ed25519 signatures are always 64 bytes
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("ed25519 signature must be %d bytes, got %d bytes", ed25519.SignatureSize, len(signature))
	}

	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("key must be ed25519.PublicKey for ed25519, got %T", key)
	}

	if len(edKey) == 0 {
		return fmt.Errorf("ed25519 public key is nil or empty")
	}

	// Validate key size (32 bytes per RFC 8032)
	if len(edKey) != ed25519.PublicKeySize {
		return fmt.Errorf("ed25519 public key must be %d bytes, got %d bytes", ed25519.PublicKeySize, len(edKey))
	}

	// Verify the signature
	valid := ed25519.Verify(edKey, signatureBase, signature)
	if !valid {
		return fmt.Errorf("ed25519 signature verification failed")
	}

	return nil
}

// init registers the Ed25519 algorithm in the global algorithm registry.
func init() {
	if err := RegisterAlgorithm(&ed25519Algorithm{}); err != nil {
		panic(err)
	}
}
