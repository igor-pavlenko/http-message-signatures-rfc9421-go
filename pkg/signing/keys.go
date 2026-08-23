package signing

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParsePrivateKey parses a PEM or DER-encoded private key.
//
// Supported Formats:
//
//	PEM-encoded:
//	  - PKCS#1 RSA private key (-----BEGIN RSA PRIVATE KEY-----)
//	  - PKCS#8 private key (-----BEGIN PRIVATE KEY-----)
//	  - SEC1 EC private key (-----BEGIN EC PRIVATE KEY-----)
//
//	DER-encoded:
//	  - PKCS#1 RSA private key (binary ASN.1)
//	  - PKCS#8 private key (binary ASN.1)
//	  - SEC1 EC private key (binary ASN.1)
//
// Parameters:
//
//	keyData - Raw bytes of PEM or DER-encoded private key
//
// Returns:
//
//	Parsed private key as interface{} (actual type: *rsa.PrivateKey,
//	*ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Error Conditions:
//   - keyData is empty
//   - PEM decoding fails (invalid PEM format)
//   - DER parsing fails (invalid ASN.1 structure)
//   - Unsupported key type (DSA, etc.)
//   - Key does not meet minimum security requirements
//
// Example:
//
//	keyData, _ := os.ReadFile("private-key.pem")
//	privKey, err := signing.ParsePrivateKey(keyData)
//	if err != nil {
//	    return fmt.Errorf("failed to parse private key: %w", err)
//	}
//
// Uses: crypto/x509.ParsePKCS1PrivateKey, ParsePKCS8PrivateKey, ParseECPrivateKey
func ParsePrivateKey(keyData []byte) (any, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("private key data is empty")
	}

	// Try PEM decoding first
	block, _ := pem.Decode(keyData)
	var derBytes []byte
	if block != nil {
		derBytes = block.Bytes
	} else {
		// Not PEM, assume raw DER
		derBytes = keyData
	}

	// Try parsing as PKCS#8 (most common format, supports all key types)
	if key, err := x509.ParsePKCS8PrivateKey(derBytes); err == nil {
		// Validate the key type and return
		switch k := key.(type) {
		case *rsa.PrivateKey:
			if err := validateRSAPrivateKey(k); err != nil {
				return nil, err
			}
			return k, nil
		case *ecdsa.PrivateKey:
			return k, nil
		case ed25519.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported private key type in PKCS#8: %T", key)
		}
	}

	// Try parsing as PKCS#1 RSA private key
	if rsaKey, err := x509.ParsePKCS1PrivateKey(derBytes); err == nil {
		if err := validateRSAPrivateKey(rsaKey); err != nil {
			return nil, err
		}
		return rsaKey, nil
	}

	// Try parsing as SEC1 EC private key
	if ecKey, err := x509.ParseECPrivateKey(derBytes); err == nil {
		return ecKey, nil
	}

	return nil, fmt.Errorf("failed to parse private key: unsupported format or invalid key data")
}

// ParsePublicKey parses a PEM or DER-encoded public key.
//
// Supported Formats:
//
//	PEM-encoded:
//	  - PKIX public key (-----BEGIN PUBLIC KEY-----)
//	  - RSA public key (-----BEGIN RSA PUBLIC KEY-----)
//
//	DER-encoded:
//	  - PKIX public key (binary ASN.1)
//	  - PKCS#1 RSA public key (binary ASN.1)
//
// Parameters:
//
//	keyData - Raw bytes of PEM or DER-encoded public key
//
// Returns:
//
//	Parsed public key as interface{} (actual type: *rsa.PublicKey,
//	*ecdsa.PublicKey, or ed25519.PublicKey)
//
// Error Conditions:
//   - keyData is empty
//   - PEM decoding fails (invalid PEM format)
//   - DER parsing fails (invalid ASN.1 structure)
//   - Unsupported key type (DSA, etc.)
//
// Example:
//
//	keyData, _ := os.ReadFile("public-key.pem")
//	pubKey, err := signing.ParsePublicKey(keyData)
//	if err != nil {
//	    return fmt.Errorf("failed to parse public key: %w", err)
//	}
//
// Uses: crypto/x509.ParsePKIXPublicKey, ParsePKCS1PublicKey
func ParsePublicKey(keyData []byte) (any, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("public key data is empty")
	}

	// Try PEM decoding first
	block, _ := pem.Decode(keyData)
	var derBytes []byte
	if block != nil {
		derBytes = block.Bytes
	} else {
		// Not PEM, assume raw DER
		derBytes = keyData
	}

	// Try parsing as PKIX (most common format, supports all key types)
	if key, err := x509.ParsePKIXPublicKey(derBytes); err == nil {
		// Validate the key type and return
		switch k := key.(type) {
		case *rsa.PublicKey:
			if err := validateRSAPublicKey(k); err != nil {
				return nil, err
			}
			return k, nil
		case *ecdsa.PublicKey:
			return k, nil
		case ed25519.PublicKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported public key type in PKIX: %T", key)
		}
	}

	// Try parsing as PKCS#1 RSA public key
	if rsaKey, err := x509.ParsePKCS1PublicKey(derBytes); err == nil {
		if err := validateRSAPublicKey(rsaKey); err != nil {
			return nil, err
		}
		return rsaKey, nil
	}

	return nil, fmt.Errorf("failed to parse public key: unsupported format or invalid key data")
}

// validateRSAPrivateKey validates RSA private key meets minimum security requirements.
func validateRSAPrivateKey(key *rsa.PrivateKey) error {
	if key == nil {
		return fmt.Errorf("RSA private key is nil")
	}

	// RFC 9421: Minimum 2048 bits for RSA keys
	bitSize := key.N.BitLen()
	if bitSize < 2048 {
		return fmt.Errorf("RSA key size %d bits is too small (minimum 2048 bits required)", bitSize)
	}

	return nil
}

// validateRSAPublicKey validates RSA public key meets minimum security requirements.
func validateRSAPublicKey(key *rsa.PublicKey) error {
	if key == nil {
		return fmt.Errorf("RSA public key is nil")
	}

	// RFC 9421: Minimum 2048 bits for RSA keys
	bitSize := key.N.BitLen()
	if bitSize < 2048 {
		return fmt.Errorf("RSA key size %d bits is too small (minimum 2048 bits required)", bitSize)
	}

	return nil
}

// =============================================================================
// Strict Parsing Functions
// =============================================================================
//
// The following functions provide explicit format validation for users who
// require strict control over key formats. Unlike ParsePrivateKey/ParsePublicKey
// which try multiple formats, these functions only accept a single specific format.

// ParsePKCS1PrivateKey parses an RSA private key in PKCS#1 format only.
//
// This is a strict parser that rejects keys in other formats (PKCS#8, SEC1).
// Use this when you need explicit format validation and want to ensure
// the key is specifically in PKCS#1 RSA format.
//
// Supported Formats:
//
//	PEM-encoded: -----BEGIN RSA PRIVATE KEY-----
//	DER-encoded: PKCS#1 RSA private key (binary ASN.1)
//
// Returns:
//
//	*rsa.PrivateKey on success
//
// Error Conditions:
//   - keyData is empty
//   - Key is not in PKCS#1 format
//   - Key does not meet minimum security requirements (2048 bits)
func ParsePKCS1PrivateKey(keyData []byte) (*rsa.PrivateKey, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("private key data is empty")
	}

	derBytes := extractDERBytes(keyData)

	rsaKey, err := x509.ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#1 private key: %w", err)
	}

	if err := validateRSAPrivateKey(rsaKey); err != nil {
		return nil, err
	}

	return rsaKey, nil
}

// ParsePKCS8PrivateKey parses a private key in PKCS#8 format only.
//
// This is a strict parser that rejects keys in other formats (PKCS#1, SEC1).
// Use this when you need explicit format validation and want to ensure
// the key is specifically in PKCS#8 format.
//
// Supported Formats:
//
//	PEM-encoded: -----BEGIN PRIVATE KEY-----
//	DER-encoded: PKCS#8 private key (binary ASN.1)
//
// Returns:
//
//	Parsed private key as interface{} (actual type: *rsa.PrivateKey,
//	*ecdsa.PrivateKey, or ed25519.PrivateKey)
//
// Error Conditions:
//   - keyData is empty
//   - Key is not in PKCS#8 format
//   - Unsupported key type (DSA, etc.)
//   - RSA key does not meet minimum security requirements (2048 bits)
func ParsePKCS8PrivateKey(keyData []byte) (any, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("private key data is empty")
	}

	derBytes := extractDERBytes(keyData)

	key, err := x509.ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		if err := validateRSAPrivateKey(k); err != nil {
			return nil, err
		}
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported private key type in PKCS#8: %T", key)
	}
}

// ParseSEC1PrivateKey parses an ECDSA private key in SEC1 format only.
//
// This is a strict parser that rejects keys in other formats (PKCS#1, PKCS#8).
// Use this when you need explicit format validation and want to ensure
// the key is specifically in SEC1 EC format.
//
// Supported Formats:
//
//	PEM-encoded: -----BEGIN EC PRIVATE KEY-----
//	DER-encoded: SEC1 EC private key (binary ASN.1)
//
// Returns:
//
//	*ecdsa.PrivateKey on success
//
// Error Conditions:
//   - keyData is empty
//   - Key is not in SEC1 format
func ParseSEC1PrivateKey(keyData []byte) (*ecdsa.PrivateKey, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("private key data is empty")
	}

	derBytes := extractDERBytes(keyData)

	ecKey, err := x509.ParseECPrivateKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SEC1 private key: %w", err)
	}

	return ecKey, nil
}

// ParsePKIXPublicKey parses a public key in PKIX format only.
//
// This is a strict parser that rejects keys in other formats (PKCS#1 RSA).
// Use this when you need explicit format validation and want to ensure
// the key is specifically in PKIX format.
//
// Supported Formats:
//
//	PEM-encoded: -----BEGIN PUBLIC KEY-----
//	DER-encoded: PKIX public key (binary ASN.1)
//
// Returns:
//
//	Parsed public key as interface{} (actual type: *rsa.PublicKey,
//	*ecdsa.PublicKey, or ed25519.PublicKey)
//
// Error Conditions:
//   - keyData is empty
//   - Key is not in PKIX format
//   - Unsupported key type (DSA, etc.)
//   - RSA key does not meet minimum security requirements (2048 bits)
func ParsePKIXPublicKey(keyData []byte) (any, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("public key data is empty")
	}

	derBytes := extractDERBytes(keyData)

	key, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	switch k := key.(type) {
	case *rsa.PublicKey:
		if err := validateRSAPublicKey(k); err != nil {
			return nil, err
		}
		return k, nil
	case *ecdsa.PublicKey:
		return k, nil
	case ed25519.PublicKey:
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported public key type in PKIX: %T", key)
	}
}

// ParsePKCS1PublicKey parses an RSA public key in PKCS#1 format only.
//
// This is a strict parser that rejects keys in other formats (PKIX).
// Use this when you need explicit format validation and want to ensure
// the key is specifically in PKCS#1 RSA public key format.
//
// Supported Formats:
//
//	PEM-encoded: -----BEGIN RSA PUBLIC KEY-----
//	DER-encoded: PKCS#1 RSA public key (binary ASN.1)
//
// Returns:
//
//	*rsa.PublicKey on success
//
// Error Conditions:
//   - keyData is empty
//   - Key is not in PKCS#1 RSA public key format
//   - Key does not meet minimum security requirements (2048 bits)
func ParsePKCS1PublicKey(keyData []byte) (*rsa.PublicKey, error) {
	if len(keyData) == 0 {
		return nil, fmt.Errorf("public key data is empty")
	}

	derBytes := extractDERBytes(keyData)

	rsaKey, err := x509.ParsePKCS1PublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#1 public key: %w", err)
	}

	if err := validateRSAPublicKey(rsaKey); err != nil {
		return nil, err
	}

	return rsaKey, nil
}

// extractDERBytes extracts DER bytes from PEM or raw DER input.
func extractDERBytes(data []byte) []byte {
	block, _ := pem.Decode(data)
	if block != nil {
		return block.Bytes
	}
	return data
}
