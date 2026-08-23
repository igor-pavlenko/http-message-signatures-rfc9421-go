// Package signing implements RFC 9421 HTTP Message Signatures cryptographic algorithms.
//
// This package provides signature generation and verification for all six RFC 9421
// algorithms using only the Go standard library crypto packages.
//
// Supported algorithms:
//   - rsa-pss-sha512 (RSA-PSS with SHA-512, recommended)
//   - rsa-v1_5-sha256 (RSA-PKCS1-v1.5 with SHA-256, legacy only)
//   - ecdsa-p256-sha256 (ECDSA P-256 curve with SHA-256)
//   - ecdsa-p384-sha384 (ECDSA P-384 curve with SHA-384)
//   - ed25519 (Ed25519 deterministic signatures)
//   - hmac-sha256 (HMAC with SHA-256)
//
// # Basic Usage
//
// Sign a message with RSA-PSS-SHA512:
//
//	alg, _ := signing.GetAlgorithm("rsa-pss-sha512")
//	signatureBytes, _ := alg.Sign(signatureBase, privateKey)
//	signatureB64 := base64.StdEncoding.EncodeToString(signatureBytes)
//
// Verify a signature:
//
//	alg, _ := signing.GetAlgorithm("rsa-pss-sha512")
//	signatureBytes, _ := base64.StdEncoding.DecodeString(signatureB64)
//	err := alg.Verify(signatureBase, signatureBytes, publicKey)
//	if err != nil {
//	    // Signature invalid
//	}
//
// # Key Management
//
// Load private keys from PEM format:
//
//	keyData, _ := os.ReadFile("private-key.pem")
//	privateKey, _ := signing.ParsePrivateKey(keyData)
//
// Supported formats: PKCS#1, PKCS#8, SEC1 (EC keys), raw bytes (HMAC).
//
// # Security
//
//   - RSA-PSS is recommended over RSA-PKCS1-v1.5 for new deployments
//   - HMAC uses constant-time comparison to prevent timing attacks
//   - ECDSA supports RFC 6979 deterministic nonces
//   - All algorithms use crypto/rand.Reader for secure randomness
//
// # RFC Compliance
//
// Implements RFC 9421 Section 3.3 (HTTP Signature Algorithms):
//   - RFC 8017: PKCS #1 - RSA Cryptography
//   - RFC 6979: Deterministic ECDSA
//   - RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
//   - RFC 2104: HMAC - Keyed-Hashing for Message Authentication
//
// See https://www.rfc-editor.org/rfc/rfc9421.html for the complete specification.
package signing

import (
	"fmt"
	"sync"
)

// Algorithm represents a cryptographic signature algorithm as defined in RFC 9421 Section 3.3.
//
// Each algorithm MUST:
//   - Be stateless (no internal state between operations)
//   - Accept signature base bytes from pkg/base.BuildSignatureBase()
//   - Use only Go standard library crypto packages
//   - Return descriptive errors (never panic)
//
// Implementations:
//   - RSA-PSS-SHA512 (rsa-pss-sha512) - Recommended, uses MGF1 with SHA-512
//   - RSA-PKCS1-v1.5-SHA256 (rsa-v1_5-sha256) - Legacy compatibility only
//   - ECDSA-P256-SHA256 (ecdsa-p256-sha256) - Elliptic curve, P-256 curve
//   - ECDSA-P384-SHA384 (ecdsa-p384-sha384) - Elliptic curve, P-384 curve
//   - Ed25519 (ed25519) - Fast deterministic signatures
//   - HMAC-SHA256 (hmac-sha256) - Symmetric authentication
type Algorithm interface {
	// ID returns the RFC 9421 algorithm identifier.
	//
	// MUST return one of the following exact strings:
	//   - "rsa-pss-sha512"
	//   - "rsa-v1_5-sha256"
	//   - "ecdsa-p256-sha256"
	//   - "ecdsa-p384-sha384"
	//   - "ed25519"
	//   - "hmac-sha256"
	//
	// RFC 9421 Section 3.3: Algorithm identifiers are case-sensitive.
	ID() string

	// Sign generates a cryptographic signature over the signature base.
	//
	// Parameters:
	//   signatureBase - Canonical signature base from pkg/base.BuildSignatureBase()
	//   key - Private key or shared secret (type depends on algorithm)
	//
	// Key Type Requirements:
	//   RSA algorithms:    *rsa.PrivateKey (from crypto/rsa)
	//   ECDSA algorithms:  *ecdsa.PrivateKey (from crypto/ecdsa)
	//   Ed25519:           ed25519.PrivateKey (from crypto/ed25519)
	//   HMAC:              []byte (shared secret, ≥32 bytes recommended)
	//
	// Returns:
	//   Signature bytes (ready for base64 encoding per RFC 9421 Section 3.1)
	//
	// Error Conditions:
	//   - signatureBase is empty (contract violation)
	//   - key is nil or wrong type for algorithm
	//   - key does not meet security requirements (e.g., RSA key <2048 bits)
	//   - cryptographic operation fails (stdlib crypto error)
	//
	// Security Requirements:
	//   - MUST use crypto/rand.Reader for randomness (RSA-PSS, ECDSA)
	//   - ECDSA MAY use RFC 6979 deterministic nonces (pass nil to SignASN1)
	//   - HMAC verification MUST use constant-time comparison
	//
	// RFC 9421 Section 3.1: Creating a Signature
	Sign(signatureBase []byte, key any) ([]byte, error)

	// Verify validates a signature against the signature base.
	//
	// Parameters:
	//   signatureBase - Canonical signature base from pkg/base.BuildSignatureBase()
	//   signature - Raw signature bytes (base64-decoded from Signature header)
	//   key - Public key or shared secret (type depends on algorithm)
	//
	// Key Type Requirements:
	//   RSA algorithms:    *rsa.PublicKey (from crypto/rsa)
	//   ECDSA algorithms:  *ecdsa.PublicKey (from crypto/ecdsa)
	//   Ed25519:           ed25519.PublicKey (from crypto/ed25519)
	//   HMAC:              []byte (same shared secret used for signing)
	//
	// Returns:
	//   nil if signature is valid
	//   error if signature is invalid or verification fails
	//
	// Error Conditions:
	//   - signatureBase is empty (contract violation)
	//   - signature bytes are empty or wrong length
	//   - key is nil or wrong type for algorithm
	//   - signature is cryptographically invalid
	//   - signature does not match signatureBase
	//
	// Security Requirements:
	//   - HMAC MUST use crypto/subtle.ConstantTimeCompare to prevent timing attacks
	//   - MUST NOT return different error types for invalid vs. wrong-key signatures
	//   - Error messages MUST NOT leak cryptographic information
	//
	// RFC 9421 Section 3.2: Verifying a Signature
	Verify(signatureBase, signature []byte, key any) error
}

// algorithmRegistry is the global registry of all supported algorithms.
// Algorithms register themselves in their init() functions.
// Protected by algorithmRegistryMu for concurrent access safety.
var (
	algorithmRegistry   = make(map[string]Algorithm)
	algorithmRegistryMu sync.RWMutex
)

// RegisterAlgorithm registers an algorithm implementation in the global registry.
// This is called by each algorithm's init() function but may also be called
// at runtime to register custom algorithms. This function is safe for concurrent use.
// Returns an error if the algorithm ID is already registered.
func RegisterAlgorithm(alg Algorithm) error {
	id := alg.ID()

	algorithmRegistryMu.Lock()
	defer algorithmRegistryMu.Unlock()

	if _, exists := algorithmRegistry[id]; exists {
		return fmt.Errorf("algorithm %q already registered", id)
	}
	algorithmRegistry[id] = alg
	return nil
}

// GetAlgorithm retrieves an algorithm implementation by its RFC 9421 identifier.
//
// Parameters:
//
//	id - RFC 9421 algorithm identifier (case-sensitive)
//
// Supported Algorithm IDs (RFC 9421 Section 3.3):
//   - "rsa-pss-sha512" - RSA-PSS with SHA-512 and MGF1
//   - "rsa-v1_5-sha256" - RSA PKCS#1 v1.5 with SHA-256 (legacy only)
//   - "ecdsa-p256-sha256" - ECDSA using curve P-256 with SHA-256
//   - "ecdsa-p384-sha384" - ECDSA using curve P-384 with SHA-384
//   - "ed25519" - Ed25519 signature algorithm
//   - "hmac-sha256" - HMAC using SHA-256
//
// Returns:
//
//	Algorithm implementation or error if algorithm ID is unknown
//
// Error Conditions:
//   - id is empty string
//   - id is not registered in the algorithm registry
//
// Example:
//
//	alg, err := signing.GetAlgorithm("rsa-pss-sha512")
//	if err != nil {
//	    return fmt.Errorf("unsupported algorithm: %w", err)
//	}
//	signature, err := alg.Sign(signatureBase, privateKey)
//
// RFC 9421 Section 3.3: HTTP Signature Algorithms Registry
func GetAlgorithm(id string) (Algorithm, error) {
	if id == "" {
		return nil, fmt.Errorf("algorithm ID cannot be empty")
	}

	algorithmRegistryMu.RLock()
	alg, exists := algorithmRegistry[id]
	algorithmRegistryMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("unsupported algorithm: %q", id)
	}

	return alg, nil
}

// SupportedAlgorithms returns a list of all registered algorithm identifiers.
//
// Returns:
//
//	Slice of RFC 9421 algorithm ID strings
//
// Guaranteed to include (as of RFC 9421 Section 3.3):
//   - "ecdsa-p256-sha256"
//   - "ecdsa-p384-sha384"
//   - "ed25519"
//   - "hmac-sha256"
//   - "rsa-pss-sha512"
//   - "rsa-v1_5-sha256"
//
// Example:
//
//	for _, algID := range signing.SupportedAlgorithms() {
//	    fmt.Println("Supported:", algID)
//	}
func SupportedAlgorithms() []string {
	algorithmRegistryMu.RLock()
	defer algorithmRegistryMu.RUnlock()

	algorithms := make([]string, 0, len(algorithmRegistry))
	for id := range algorithmRegistry {
		algorithms = append(algorithms, id)
	}
	return algorithms
}
