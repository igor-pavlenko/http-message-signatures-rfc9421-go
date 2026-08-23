package digest

import "fmt"

// ComputeDigest is a convenience function that computes a digest for the
// entire body using the specified algorithm. This is a wrapper around
// NewDigester for cases where the entire body is available in memory.
//
// For memory-efficient streaming operations with large bodies, use
// NewDigester() directly to obtain a hash.Hash instance.
//
// Returns the computed digest bytes, or error if the algorithm is unsupported.
func ComputeDigest(body []byte, algorithm string) ([]byte, error) {
	h, err := NewDigester(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to create digester: %w", err)
	}

	_, err = h.Write(body)
	if err != nil {
		return nil, fmt.Errorf("failed to write body to hasher: %w", err)
	}

	return h.Sum(nil), nil
}
