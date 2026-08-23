package digest

import (
	"fmt"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/sfv"
)

// ParseContentDigest parses a Content-Digest header value (RFC 8941 Dictionary)
// and returns a map of algorithm names to digest bytes.
//
// Format: algorithm=:base64digest:, algorithm2=:base64digest2:
// Example: sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:
//
// Returns error if:
//   - Header syntax is invalid (not RFC 8941 Dictionary)
//   - Algorithm is not supported (deprecated algorithms rejected)
//   - Digest value is not a byte sequence
//   - Digest length doesn't match expected size for algorithm
//   - Base64 decoding fails
func ParseContentDigest(header string) (map[string][]byte, error) {
	if header == "" {
		return nil, fmt.Errorf("header cannot be empty")
	}

	// Parse RFC 8941 Dictionary using pkg/sfv
	parser := sfv.NewParser(header, sfv.DefaultLimits())
	dict, err := parser.ParseDictionary()
	if err != nil {
		return nil, fmt.Errorf("failed to parse Content-Digest header: %w", err)
	}

	if len(dict.Keys) == 0 {
		return nil, fmt.Errorf("Content-Digest header contains no algorithms")
	}

	// Extract and validate digests
	result := make(map[string][]byte, len(dict.Keys))

	for _, algorithm := range dict.Keys {
		value := dict.Values[algorithm]

		// Value must be an Item with ByteSequence
		item, ok := value.(sfv.Item)
		if !ok {
			return nil, fmt.Errorf("algorithm %q: value must be an Item, got %T", algorithm, value)
		}

		// Item value must be []byte (byte sequence)
		digestBytes, ok := item.Value.([]byte)
		if !ok {
			return nil, fmt.Errorf("algorithm %q: value must be byte sequence (RFC 8941 :base64:), got %T", algorithm, item.Value)
		}

		// Validate algorithm is supported
		if !isAlgorithmSupported(algorithm) {
			return nil, fmt.Errorf("unsupported algorithm %q", algorithm)
		}

		// Validate digest length
		expectedLen := getExpectedDigestLength(algorithm)
		if len(digestBytes) != expectedLen {
			return nil, fmt.Errorf("algorithm %q: digest length %d bytes does not match expected %d bytes", algorithm, len(digestBytes), expectedLen)
		}

		result[algorithm] = digestBytes
	}

	return result, nil
}

// isAlgorithmSupported checks if an algorithm is in the supported set (O(1) lookup)
func isAlgorithmSupported(algorithm string) bool {
	_, ok := SupportedAlgorithms[algorithm]
	return ok
}

// getExpectedDigestLength returns the expected digest size in bytes for an algorithm
func getExpectedDigestLength(algorithm string) int {
	switch algorithm {
	case AlgorithmSHA256, AlgorithmSHA512256, AlgorithmSHA3256, AlgorithmBLAKE2b256:
		return 32
	case AlgorithmSHA512, AlgorithmSHA3512, AlgorithmBLAKE2b512:
		return 64
	default:
		return -1 // Unknown
	}
}
