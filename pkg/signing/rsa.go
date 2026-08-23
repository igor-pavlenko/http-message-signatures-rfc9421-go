package signing

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

// rsaPSSSignOptions defines the PSS options for signing operations.
// Using PSSSaltLengthEqualsHash (64 bytes for SHA-512) instead of PSSSaltLengthAuto
// reduces random data generation by ~66% while remaining fully RFC 9421 compliant.
// RFC 9421 Section 3.3.1: "The salt length (sLen) MUST be at least 64 octets."
var rsaPSSSignOptions = &rsa.PSSOptions{
	SaltLength: rsa.PSSSaltLengthEqualsHash,
	Hash:       crypto.SHA512,
}

// rsaPSSVerifyOptions defines the PSS options for verification operations.
// Uses PSSSaltLengthAuto to accept signatures with any valid salt length.
var rsaPSSVerifyOptions = &rsa.PSSOptions{
	SaltLength: rsa.PSSSaltLengthAuto,
	Hash:       crypto.SHA512,
}

// rsaPSSAlgorithm implements RSA-PSS-SHA512 signature algorithm per RFC 9421 Section 3.3.1.
//
// RSA-PSS (Probabilistic Signature Scheme) with SHA-512 hash and MGF1 mask generation
// function is the recommended RSA-based signature algorithm in RFC 9421.
//
// Security properties:
//   - Uses SHA-512 for both hashing and MGF1
//   - Salt length equals hash length (64 bytes) per RFC 9421 minimum requirement
//   - Requires minimum 2048-bit RSA keys
//   - Uses crypto/rand.Reader for secure random salt generation
//
// RFC References:
//   - RFC 9421 Section 3.3.1: RSA PSS using SHA-512
//   - RFC 8017: PKCS #1 - RSA Cryptography Specifications
type rsaPSSAlgorithm struct{}

// ID returns the RFC 9421 algorithm identifier for RSA-PSS-SHA512.
func (a *rsaPSSAlgorithm) ID() string {
	return "rsa-pss-sha512"
}

// Sign generates an RSA-PSS signature using SHA-512.
//
// The signature is generated using:
//   - Hash function: SHA-512
//   - Mask generation function: MGF1 with SHA-512
//   - Salt length: PSSSaltLengthAuto (maximum possible for key size)
//   - Random source: crypto/rand.Reader
//
// Parameters:
//
//	signatureBase - The canonical signature base from RFC 9421 Section 2.5
//	key - Must be *rsa.PrivateKey with at least 2048 bits
//
// Returns:
//
//	Signature bytes (not base64-encoded)
//
// Errors:
//   - signatureBase is empty
//   - key is not *rsa.PrivateKey
//   - key size is less than 2048 bits
//   - RSA signing operation fails
func (a *rsaPSSAlgorithm) Sign(signatureBase []byte, key any) ([]byte, error) {
	if len(signatureBase) == 0 {
		return nil, fmt.Errorf("signature base is empty")
	}

	// Validate key type
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type for rsa-pss-sha512: expected *rsa.PrivateKey, got %T", key)
	}

	// Validate key size (RFC 9421 requires minimum 2048 bits)
	keySize := rsaKey.N.BitLen()
	if keySize < 2048 {
		return nil, fmt.Errorf("RSA key size %d bits is too small (minimum 2048 bits required)", keySize)
	}

	// Hash the signature base with SHA-512
	hash := sha512.Sum512(signatureBase)

	// Sign using RSA-PSS with SHA-512, MGF1, and hash-length salt (64 bytes)
	signature, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA512, hash[:], rsaPSSSignOptions)
	if err != nil {
		return nil, fmt.Errorf("RSA-PSS signing failed: %w", err)
	}

	return signature, nil
}

// Verify validates an RSA-PSS signature using SHA-512.
//
// The signature is verified using:
//   - Hash function: SHA-512
//   - Mask generation function: MGF1 with SHA-512
//   - Salt length: PSSSaltLengthAuto (automatically determined from signature)
//
// Parameters:
//
//	signatureBase - The canonical signature base from RFC 9421 Section 2.5
//	signature - Raw signature bytes (base64-decoded)
//	key - Must be *rsa.PublicKey with at least 2048 bits
//
// Returns:
//
//	nil if signature is valid
//	error if signature is invalid or verification fails
//
// Errors:
//   - signatureBase is empty
//   - signature is empty
//   - key is not *rsa.PublicKey
//   - key size is less than 2048 bits
//   - signature is cryptographically invalid
func (a *rsaPSSAlgorithm) Verify(signatureBase, signature []byte, key any) error {
	if len(signatureBase) == 0 {
		return fmt.Errorf("signature base is empty")
	}

	if len(signature) == 0 {
		return fmt.Errorf("signature is empty")
	}

	// Validate key type
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid key type for rsa-pss-sha512: expected *rsa.PublicKey, got %T", key)
	}

	// Validate key size (RFC 9421 requires minimum 2048 bits)
	keySize := rsaKey.N.BitLen()
	if keySize < 2048 {
		return fmt.Errorf("RSA key size %d bits is too small (minimum 2048 bits required)", keySize)
	}

	// Hash the signature base with SHA-512
	hash := sha512.Sum512(signatureBase)

	// Verify using RSA-PSS with SHA-512, MGF1, and auto salt length (accepts any valid salt)
	err := rsa.VerifyPSS(rsaKey, crypto.SHA512, hash[:], signature, rsaPSSVerifyOptions)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// rsaPKCS1v15Algorithm implements RSA-PKCS1-v1_5-SHA256 signature algorithm per RFC 9421 Section 3.3.2.
//
// DEPRECATED: This algorithm is provided for legacy compatibility only.
// RFC 9421 Section 3.3.2 states: "This algorithm is not recommended for new deployments."
// Use rsa-pss-sha512 instead for new implementations.
//
// RSASSA-PKCS1-v1_5 with SHA-256 hash is the legacy RSA signature scheme.
// It lacks the security properties of RSA-PSS (no salt, deterministic padding).
//
// Security properties:
//   - Uses SHA-256 for hashing (weaker than SHA-512)
//   - Deterministic padding (no randomization)
//   - No salt (unlike RSA-PSS)
//   - Requires minimum 2048-bit RSA keys
//   - Vulnerable to certain padding oracle attacks
//
// RFC References:
//   - RFC 9421 Section 3.3.2: RSA v1.5 using SHA-256 (deprecated)
//   - RFC 8017: PKCS #1 - RSA Cryptography Specifications
type rsaPKCS1v15Algorithm struct{}

// ID returns the RFC 9421 algorithm identifier for RSA-PKCS1-v1_5-SHA256.
func (a *rsaPKCS1v15Algorithm) ID() string {
	return "rsa-v1_5-sha256"
}

// Sign generates an RSA-PKCS1-v1_5 signature using SHA-256.
//
// DEPRECATED: This signature scheme is deterministic and lacks the security
// properties of RSA-PSS. Use rsa-pss-sha512 for new deployments.
//
// The signature is generated using:
//   - Hash function: SHA-256
//   - Padding scheme: PKCS#1 v1.5 (deterministic)
//   - No salt (deterministic padding)
//
// Parameters:
//
//	signatureBase - The canonical signature base from RFC 9421 Section 2.5
//	key - Must be *rsa.PrivateKey with at least 2048 bits
//
// Returns:
//
//	Signature bytes (not base64-encoded)
//
// Errors:
//   - signatureBase is empty
//   - key is not *rsa.PrivateKey
//   - key size is less than 2048 bits
//   - RSA signing operation fails
func (a *rsaPKCS1v15Algorithm) Sign(signatureBase []byte, key any) ([]byte, error) {
	if len(signatureBase) == 0 {
		return nil, fmt.Errorf("signature base is empty")
	}

	// Validate key type
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type for rsa-v1_5-sha256: expected *rsa.PrivateKey, got %T", key)
	}

	// Validate key size (RFC 9421 requires minimum 2048 bits)
	keySize := rsaKey.N.BitLen()
	if keySize < 2048 {
		return nil, fmt.Errorf("RSA key size %d bits is too small (minimum 2048 bits required)", keySize)
	}

	// Hash the signature base with SHA-256
	hash := sha256.Sum256(signatureBase)

	// Sign using RSA-PKCS1-v1_5 with SHA-256.
	// SonarQube go:S5542 flags this line: that rule targets RSA *encryption*
	// padding (Bleichenbacher-class oracle attacks on rsa.EncryptPKCS1v15),
	// not RSASSA-PKCS1-v1_5 *signing*, which has no such oracle and is the
	// algorithm RFC 9421 mandates for rsa-v1_5-sha256.
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("RSA-PKCS1-v1_5 signing failed: %w", err)
	}

	return signature, nil
}

// Verify validates an RSA-PKCS1-v1_5 signature using SHA-256.
//
// DEPRECATED: This signature scheme is deterministic and lacks the security
// properties of RSA-PSS. Use rsa-pss-sha512 for new deployments.
//
// The signature is verified using:
//   - Hash function: SHA-256
//   - Padding scheme: PKCS#1 v1.5 (deterministic)
//
// Parameters:
//
//	signatureBase - The canonical signature base from RFC 9421 Section 2.5
//	signature - Raw signature bytes (base64-decoded)
//	key - Must be *rsa.PublicKey with at least 2048 bits
//
// Returns:
//
//	nil if signature is valid
//	error if signature is invalid or verification fails
//
// Errors:
//   - signatureBase is empty
//   - signature is empty
//   - key is not *rsa.PublicKey
//   - key size is less than 2048 bits
//   - signature is cryptographically invalid
func (a *rsaPKCS1v15Algorithm) Verify(signatureBase, signature []byte, key any) error {
	if len(signatureBase) == 0 {
		return fmt.Errorf("signature base is empty")
	}

	if len(signature) == 0 {
		return fmt.Errorf("signature is empty")
	}

	// Validate key type
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid key type for rsa-v1_5-sha256: expected *rsa.PublicKey, got %T", key)
	}

	// Validate key size (RFC 9421 requires minimum 2048 bits)
	keySize := rsaKey.N.BitLen()
	if keySize < 2048 {
		return fmt.Errorf("RSA key size %d bits is too small (minimum 2048 bits required)", keySize)
	}

	// Hash the signature base with SHA-256
	hash := sha256.Sum256(signatureBase)

	// Verify using RSA-PKCS1-v1_5 with SHA-256.
	// See the matching comment in Sign above: go:S5542 targets RSA
	// encryption padding, not RSASSA-PKCS1-v1_5 signature verification.
	err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// init registers both RSA algorithms in the global registry.
func init() {
	if err := RegisterAlgorithm(&rsaPSSAlgorithm{}); err != nil {
		panic(err)
	}
	if err := RegisterAlgorithm(&rsaPKCS1v15Algorithm{}); err != nil {
		panic(err)
	}
}
