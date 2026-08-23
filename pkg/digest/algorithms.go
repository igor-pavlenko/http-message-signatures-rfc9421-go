// Package digest provides Content-Digest header generation and verification
// using modern cryptographic algorithms (SHA-2, SHA-3, BLAKE2b families).
// Deprecated algorithms (MD5, SHA-1, etc.) are explicitly rejected.
//
// See main repository README for complete documentation and examples.
package digest

import (
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2b"
)

// Algorithm identifiers for modern cryptographic hash functions.
// All deprecated algorithms (md5, sha-1, adler32, crc32c, unixsum, unixcksum)
// are explicitly rejected for security reasons.
const (
	AlgorithmSHA256    = "sha-256"
	AlgorithmSHA512    = "sha-512"
	AlgorithmSHA512256 = "sha-512/256"

	AlgorithmSHA3256 = "sha3-256"
	AlgorithmSHA3512 = "sha3-512"

	AlgorithmBLAKE2b256 = "blake2b-256"
	AlgorithmBLAKE2b512 = "blake2b-512"
)

// SupportedAlgorithms is a set of all modern cryptographic algorithms supported
// by this package. Deprecated algorithms are explicitly excluded.
// Use O(1) lookup: _, ok := SupportedAlgorithms[algorithm].
var SupportedAlgorithms = map[string]struct{}{
	AlgorithmSHA256:     {},
	AlgorithmSHA512:     {},
	AlgorithmSHA512256:  {},
	AlgorithmSHA3256:    {},
	AlgorithmSHA3512:    {},
	AlgorithmBLAKE2b256: {},
	AlgorithmBLAKE2b512: {},
}

// NewDigester creates a hash.Hash instance for streaming digest computation.
// This is the PRIMARY API for memory-efficient operations (O(1) memory).
//
// Supported algorithms: sha-256, sha-512, sha-512/256, sha3-256, sha3-512,
// blake2b-256, blake2b-512.
//
// Deprecated algorithms (md5, sha-1, adler32, crc32c, unixsum, unixcksum)
// are explicitly rejected with descriptive errors.
//
// Returns hash.Hash for incremental computation, or error if algorithm
// is unsupported.
func NewDigester(algorithm string) (hash.Hash, error) {
	switch algorithm {
	case AlgorithmSHA256:
		return sha256.New(), nil
	case AlgorithmSHA512:
		return sha512.New(), nil
	case AlgorithmSHA512256:
		return sha512.New512_256(), nil
	case AlgorithmSHA3256:
		return sha3.New256(), nil
	case AlgorithmSHA3512:
		return sha3.New512(), nil
	case AlgorithmBLAKE2b256:
		h, err := blake2b.New256(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize BLAKE2b-256 hasher: %w", err)
		}
		return h, nil
	case AlgorithmBLAKE2b512:
		h, err := blake2b.New512(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize BLAKE2b-512 hasher: %w", err)
		}
		return h, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}
}
