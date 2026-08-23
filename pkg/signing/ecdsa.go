package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"
)

// ecdsaP256SignatureLen is the fixed signature length for P-256: two
// 32-byte, big-endian, unsigned integers (r and s) concatenated.
const ecdsaP256SignatureLen = 64

// ecdsaP384SignatureLen is the fixed signature length for P-384: two
// 48-byte, big-endian, unsigned integers (r and s) concatenated.
const ecdsaP384SignatureLen = 96

// ecdsaP256Algorithm implements the Algorithm interface for ECDSA P-256 with SHA-256.
//
// RFC 9421 Section 3.3.4: ecdsa-p256-sha256
// Uses NIST P-256 curve (secp256r1) with SHA-256 hash function.
// Signature format: fixed-length concatenation of r and s, each a 32-byte
// big-endian unsigned integer (64 bytes total) — NOT ASN.1 DER.
//
// Security Notes:
//   - Randomized signatures only (FIPS 186-4); Go's crypto/ecdsa has no built-in RFC 6979 mode
//   - Public key recovery not supported (application must provide public key)
//   - Curve parameters validated during Sign/Verify operations
type ecdsaP256Algorithm struct{}

// ecdsaP384Algorithm implements the Algorithm interface for ECDSA P-384 with SHA-384.
//
// RFC 9421 Section 3.3.5: ecdsa-p384-sha384
// Uses NIST P-384 curve (secp384r1) with SHA-384 hash function.
// Signature format: fixed-length concatenation of r and s, each a 48-byte
// big-endian unsigned integer (96 bytes total) — NOT ASN.1 DER.
//
// Security Notes:
//   - Higher security level than P-256 (192-bit security vs 128-bit)
//   - Randomized signatures only (FIPS 186-4); Go's crypto/ecdsa has no built-in RFC 6979 mode
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
//	64-byte signature: r (32 bytes, big-endian) || s (32 bytes, big-endian),
//	ready for base64 encoding per RFC 9421 Section 3.1.
//
// Error Conditions:
//   - signatureBase is empty (contract violation)
//   - key is nil or not *ecdsa.PrivateKey
//   - key curve is not P-256 (secp256r1)
//   - signing operation fails (stdlib crypto error)
//
// Signature Mode:
//   - Randomized signatures using crypto/rand.Reader (FIPS 186-4)
//
// RFC 9421 Section 3.3.4: ECDSA using curve P-256 and SHA-256
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
	r, s, err := ecdsa.Sign(rand.Reader, ecKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign with ecdsa-p256-sha256: %w", err)
	}

	return encodeECDSASignature(r, s, ecdsaP256SignatureLen/2)
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
//	96-byte signature: r (48 bytes, big-endian) || s (48 bytes, big-endian),
//	ready for base64 encoding per RFC 9421 Section 3.1.
//
// Error Conditions:
//   - signatureBase is empty (contract violation)
//   - key is nil or not *ecdsa.PrivateKey
//   - key curve is not P-384 (secp384r1)
//   - signing operation fails (stdlib crypto error)
//
// Signature Mode:
//   - Randomized signatures using crypto/rand.Reader (FIPS 186-4)
//
// RFC 9421 Section 3.3.5: ECDSA using curve P-384 and SHA-384
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
	r, s, err := ecdsa.Sign(rand.Reader, ecKey, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with ecdsa-p384-sha384: %w", err)
	}

	return encodeECDSASignature(r, s, ecdsaP384SignatureLen/2)
}

// Verify validates an ECDSA P-256 signature against the signature base.
//
// Parameters:
//
//	signatureBase - Canonical signature base from pkg/base.BuildSignatureBase()
//	signature - 64-byte r||s signature (base64-decoded from Signature header)
//	key - Must be *ecdsa.PublicKey with P-256 curve
//
// Returns:
//
//	nil if signature is valid
//	error if signature is invalid or verification fails
//
// Error Conditions:
//   - signatureBase is empty (contract violation)
//   - signature is not exactly 64 bytes
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

	r, s, err := decodeECDSASignature(signature, ecdsaP256SignatureLen/2)
	if err != nil {
		return fmt.Errorf("ecdsa-p256-sha256: %w", err)
	}

	// Hash the signature base with SHA-256
	hash := sha256.Sum256(signatureBase)

	// Verify the signature
	if !ecdsa.Verify(ecKey, hash[:], r, s) {
		return fmt.Errorf("ecdsa-p256-sha256 signature verification failed")
	}

	return nil
}

// Verify validates an ECDSA P-384 signature against the signature base.
//
// Parameters:
//
//	signatureBase - Canonical signature base from pkg/base.BuildSignatureBase()
//	signature - 96-byte r||s signature (base64-decoded from Signature header)
//	key - Must be *ecdsa.PublicKey with P-384 curve
//
// Returns:
//
//	nil if signature is valid
//	error if signature is invalid or verification fails
//
// Error Conditions:
//   - signatureBase is empty (contract violation)
//   - signature is not exactly 96 bytes
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

	r, s, err := decodeECDSASignature(signature, ecdsaP384SignatureLen/2)
	if err != nil {
		return fmt.Errorf("ecdsa-p384-sha384: %w", err)
	}

	// Hash the signature base with SHA-384
	hasher := sha512.New384()
	hasher.Write(signatureBase)
	hashBytes := hasher.Sum(nil)

	// Verify the signature
	if !ecdsa.Verify(ecKey, hashBytes, r, s) {
		return fmt.Errorf("ecdsa-p384-sha384 signature verification failed")
	}

	return nil
}

// encodeECDSASignature concatenates r and s as two big-endian, unsigned,
// componentLen-byte integers, per RFC 9421 Sections 3.3.4/3.3.5. r and s are
// always < curve order N (< 2^(8*componentLen) for P-256/P-384), so they
// always fit; the length check guards against a future curve where that
// invariant might not hold rather than any case reachable today.
func encodeECDSASignature(r, s *big.Int, componentLen int) ([]byte, error) {
	if r.BitLen() > 8*componentLen || s.BitLen() > 8*componentLen {
		return nil, fmt.Errorf("signature component too long for %d-byte encoding", componentLen)
	}
	sig := make([]byte, 2*componentLen)
	r.FillBytes(sig[:componentLen])
	s.FillBytes(sig[componentLen:])
	return sig, nil
}

// decodeECDSASignature splits a fixed-length r||s signature into its two
// big-endian unsigned integer components.
func decodeECDSASignature(signature []byte, componentLen int) (r, s *big.Int, err error) {
	if len(signature) != 2*componentLen {
		return nil, nil, fmt.Errorf("signature must be %d bytes, got %d", 2*componentLen, len(signature))
	}
	r = new(big.Int).SetBytes(signature[:componentLen])
	s = new(big.Int).SetBytes(signature[componentLen:])
	return r, s, nil
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
