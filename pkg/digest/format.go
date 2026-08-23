package digest

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

// FormatContentDigest formats a map of algorithm->digest pairs into an
// RFC 8941 Structured Field Dictionary suitable for the Content-Digest header.
//
// Format: algorithm=:base64digest:, algorithm2=:base64digest2:
// Algorithms are sorted alphabetically per RFC 8941 Dictionary requirements.
//
// Example:
//
//	digests := map[string][]byte{
//	    "sha-256": digestBytes,
//	    "sha-512": digestBytes2,
//	}
//	header, err := FormatContentDigest(digests)
//	// header: "sha-256=:base64...:, sha-512=:base64...:"
//
// Returns error if:
//   - digests map is nil or empty
//   - any algorithm name is empty
//   - any digest value is nil or empty
func FormatContentDigest(digests map[string][]byte) (string, error) {
	if len(digests) == 0 {
		return "", fmt.Errorf("digests map cannot be nil or empty")
	}

	// Collect and sort algorithm names (RFC 8941 Dictionary requirement)
	algorithms := make([]string, 0, len(digests))
	for alg := range digests {
		if alg == "" {
			return "", fmt.Errorf("algorithm name cannot be empty")
		}
		algorithms = append(algorithms, alg)
	}
	sort.Strings(algorithms)

	// Build RFC 8941 Dictionary
	var parts []string
	for _, alg := range algorithms {
		digest := digests[alg]
		if len(digest) == 0 {
			return "", fmt.Errorf("digest for algorithm %q cannot be nil or empty", alg)
		}

		// RFC 8941 Byte Sequence: :base64:
		b64 := base64.StdEncoding.EncodeToString(digest)
		part := fmt.Sprintf("%s=:%s:", alg, b64)
		parts = append(parts, part)
	}

	return strings.Join(parts, ", "), nil
}
