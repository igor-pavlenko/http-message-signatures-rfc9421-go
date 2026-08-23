package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

// ecdsaP256Algorithm implements the Algorithm interface for ECDSA P-256 with SHA-256.
//
// RFC 9421 Section 3.3.3: ecdsa-p256-sha256
// Uses NIST P-256 curve (secp256r1) with SHA-256 hash function.
// Signature format: ASN.1 DER encoding of (r, s) values.
//
// Security Notes:
//   - Supports both randomized signatures (default, uses crypto/rand.Reader)
//   - Supports RFC 6979 deterministic signatures (pass nil for random source)
//   - Public key recovery not supported (application must provide public key)
//   - Curve parameters validated during Sign/Verify operations
type ecdsaP256Algorithm struct{}

// ecdsaP384Algorithm implements the Algorithm interface for ECDSA P-384 with SHA-384.
//
// RFC 9421 Section 3.3.4: ecdsa-p384-sha384
// Uses NIST P-384 curve (secp384r1) with SHA-384 hash function.
// Signature format: ASN.1 DER encoding of (r, s) values.
//
// Security Notes:
//   - Higher security level than P-256 (192-bit security vs 128-bit)
//   - Supports both randomized and RFC 6979 deterministic signatures
//   - Slower than P-256 but provides additional security margin
//   - Curve parameters validated during Sign/Verify operations
type ecdsaP384Algorithm struct{}

// ID returns the RFC 9421 algorithm identifier for ECDSA P-256.
func (a *ecdsaP256Algorithm) ID() string {
	return "ecdsa-p256-sha256"
}

// ID returns the RFC 9421 algorithm identifier for ECDSA P-384.
func (a *ecdsaP384Algorithm) ID() string {
	return "ecdsa-p384-sha384"
}

// Sign generates an ECDSA signature using P-256 curve and SHA-256 hash.
//
// Parameters:
//
//	signatureBase - Canonical signature base from pkg/base.BuildSignatureBase()
//	key - Must be *ecdsa.PrivateKey with P-256 curve
//
// Returns:
//
//	ASN.1 DER-encoded signature (ready for base64 encoding per RFC 9421 Section 3.1)
//
// Error Conditions:
//   - signatureBase is empty (contract violation)
//   - key is nil or not *ecdsa.PrivateKey
//   - key curve is not P-256 (secp256r1)
//   - signing operation fails (stdlib crypto error)
//
// Signature Mode:
//   - Default: Randomized signatures using crypto/rand.Reader (FIPS 186-4)
//   - To enable RFC 6979 deterministic mode, modify SignASN1 call to pass nil
//
// RFC 9421 Section 3.3.3: ECDSA using curve P-256 and SHA-256
func (a *ecdsaP256Algorithm) Sign(signatureBase []byte, key any) ([]byte, error) {
	if len(signatureBase) == 0 {
		return nil, fmt.Errorf("signature base cannot be empty")
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key must be *ecdsa.PrivateKey for ecdsa-p256-sha256, got %T", key)
	}

	if ecKey == nil {
		return nil, fmt.Errorf("ECDSA private key is nil")
	}

	// Validate curve is P-256
	if ecKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("ECDSA key must use P-256 curve for ecdsa-p256-sha256, got %s", ecKey.Curve.Params().Name)
	}

	// Hash the signature base with SHA-256
	hash := sha256.Sum256(signatureBase)

	// Sign using ECDSA with randomized mode (crypto/rand.Reader)
	// For RFC 6979 deterministic mode, replace rand.Reader with nil
	signature, err := ecdsa.SignASN1(rand.Reader, ecKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign with ecdsa-p256-sha256: %w", err)
	}

	return signature, nil
}

// Sign generates an ECDSA signature using P-384 curve and SHA-384 hash.
//
// Parameters:
//
//	signatureBase - Canonical signature base from pkg/base.BuildSignatureBase()
//	key - Must be *ecdsa.PrivateKey with P-384 curve
//
// Returns:
//
//	ASN.1 DER-encoded signature (ready for base64 encoding per RFC 9421 Section 3.1)
//
// Error Conditions:
//   - signatureBase is empty (contract violation)
//   - key is nil or not *ecdsa.PrivateKey
//   - key curve is not P-384 (secp384r1)
//   - signing operation fails (stdlib crypto error)
//
// Signature Mode:
//   - Default: Randomized signatures using crypto/rand.Reader (FIPS 186-4)
//   - To enable RFC 6979 deterministic mode, modify SignASN1 call to pass nil
//
// RFC 9421 Section 3.3.4: ECDSA using curve P-384 and SHA-384
func (a *ecdsaP384Algorithm) Sign(signatureBase []byte, key any) ([]byte, error) {
	if len(signatureBase) == 0 {
		return nil, fmt.Errorf("signature base cannot be empty")
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key must be *ecdsa.PrivateKey for ecdsa-p384-sha384, got %T", key)
	}

	if ecKey == nil {
		return nil, fmt.Errorf("ECDSA private key is nil")
	}

	// Validate curve is P-384
	if ecKey.Curve != elliptic.P384() {
		return nil, fmt.Errorf("ECDSA key must use P-384 curve for ecdsa-p384-sha384, got %s", ecKey.Curve.Params().Name)
	}

	// Hash the signature base with SHA-384
	hasher := sha512.New384()
	hasher.Write(signatureBase)
	hash := hasher.Sum(nil)

	// Sign using ECDSA with randomized mode (crypto/rand.Reader)
	// For RFC 6979 deterministic mode, replace rand.Reader with nil
	signature, err := ecdsa.SignASN1(rand.Reader, ecKey, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with ecdsa-p384-sha384: %w", err)
	}

	return signature, nil
}

// Verify validates an ECDSA P-256 signature against the signature base.
//
// Parameters:
//
//	signatureBase - Canonical signature base from pkg/base.BuildSignatureBase()
//	signature - ASN.1 DER-encoded signature bytes (base64-decoded from Signature header)
//	key - Must be *ecdsa.PublicKey with P-256 curve
//
// Returns:
//
//	nil if signature is valid
//	error if signature is invalid or verification fails
//
// Error Conditions:
//   - signatureBase is empty (contract violation)
//   - signature bytes are empty or malformed ASN.1
//   - key is nil or not *ecdsa.PublicKey
//   - key curve is not P-256
//   - signature is cryptographically invalid
//   - signature does not match signatureBase
//
// RFC 9421 Section 3.2: Verifying a Signature
func (a *ecdsaP256Algorithm) Verify(signatureBase, signature []byte, key any) error {
	if len(signatureBase) == 0 {
		return fmt.Errorf("signature base cannot be empty")
	}

	if len(signature) == 0 {
		return fmt.Errorf("signature cannot be empty")
	}

	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("key must be *ecdsa.PublicKey for ecdsa-p256-sha256, got %T", key)
	}

	if ecKey == nil {
		return fmt.Errorf("ECDSA public key is nil")
	}

	// Validate curve is P-256
	if ecKey.Curve != elliptic.P256() {
		return fmt.Errorf("ECDSA key must use P-256 curve for ecdsa-p256-sha256, got %s", ecKey.Curve.Params().Name)
	}

	// Hash the signature base with SHA-256
	hash := sha256.Sum256(signatureBase)

	// Verify the signature
	valid := ecdsa.VerifyASN1(ecKey, hash[:], signature)
	if !valid {
		return fmt.Errorf("ecdsa-p256-sha256 signature verification failed")
	}

	return nil
}

// Verify validates an ECDSA P-384 signature against the signature base.
//
// Parameters:
//
//	signatureBase - Canonical signature base from pkg/base.BuildSignatureBase()
//	signature - ASN.1 DER-encoded signature bytes (base64-decoded from Signature header)
//	key - Must be *ecdsa.PublicKey with P-384 curve
//
// Returns:
//
//	nil if signature is valid
//	error if signature is invalid or verification fails
//
// Error Conditions:
//   - signatureBase is empty (contract violation)
//   - signature bytes are empty or malformed ASN.1
//   - key is nil or not *ecdsa.PublicKey
//   - key curve is not P-384
//   - signature is cryptographically invalid
//   - signature does not match signatureBase
//
// RFC 9421 Section 3.2: Verifying a Signature
func (a *ecdsaP384Algorithm) Verify(signatureBase, signature []byte, key any) error {
	if len(signatureBase) == 0 {
		return fmt.Errorf("signature base cannot be empty")
	}

	if len(signature) == 0 {
		return fmt.Errorf("signature cannot be empty")
	}

	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("key must be *ecdsa.PublicKey for ecdsa-p384-sha384, got %T", key)
	}

	if ecKey == nil {
		return fmt.Errorf("ECDSA public key is nil")
	}

	// Validate curve is P-384
	if ecKey.Curve != elliptic.P384() {
		return fmt.Errorf("ECDSA key must use P-384 curve for ecdsa-p384-sha384, got %s", ecKey.Curve.Params().Name)
	}

	// Hash the signature base with SHA-384
	hasher := sha512.New384()
	hasher.Write(signatureBase)
	hashBytes := hasher.Sum(nil)

	// Verify the signature
	valid := ecdsa.VerifyASN1(ecKey, hashBytes, signature)
	if !valid {
		return fmt.Errorf("ecdsa-p384-sha384 signature verification failed")
	}

	return nil
}

// init registers both ECDSA algorithms in the global algorithm registry.
func init() {
	if err := RegisterAlgorithm(&ecdsaP256Algorithm{}); err != nil {
		panic(err)
	}
	if err := RegisterAlgorithm(&ecdsaP384Algorithm{}); err != nil {
		panic(err)
	}
}
