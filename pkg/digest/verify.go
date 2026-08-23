package digest

import (
	"crypto/subtle"
	"fmt"
	"io"
)

// VerifyContentDigestBytes verifies that a body's digest matches the Content-Digest
// header value for all required algorithms. Uses constant-time comparison via
// crypto/subtle.ConstantTimeCompare for security.
//
// Parameters:
//   - body: The complete message body as bytes
//   - header: The Content-Digest header value (RFC 8941 Dictionary)
//   - requiredAlgorithms: List of algorithms that must be present and verified
//
// Returns error if:
//   - Header cannot be parsed
//   - Any required algorithm is missing from header
//   - Any digest verification fails (mismatch)
//   - Required algorithms list is empty
func VerifyContentDigestBytes(body []byte, header string, requiredAlgorithms []string) error {
	if len(requiredAlgorithms) == 0 {
		return fmt.Errorf("requiredAlgorithms cannot be empty")
	}

	// Parse Content-Digest header
	headerDigests, err := ParseContentDigest(header)
	if err != nil {
		return fmt.Errorf("failed to parse Content-Digest header: %w", err)
	}

	// Verify each required algorithm
	for _, algorithm := range requiredAlgorithms {
		expectedDigest, found := headerDigests[algorithm]
		if !found {
			return fmt.Errorf("required algorithm %q not found in Content-Digest header", algorithm)
		}

		// Compute actual digest
		actualDigest, err := ComputeDigest(body, algorithm)
		if err != nil {
			return fmt.Errorf("failed to compute digest for algorithm %q: %w", algorithm, err)
		}

		// Constant-time comparison (security requirement)
		if subtle.ConstantTimeCompare(actualDigest, expectedDigest) != 1 {
			return fmt.Errorf("digest mismatch for algorithm %q: verification failed", algorithm)
		}
	}

	return nil
}

// VerifyContentDigest verifies that a reader's content matches the Content-Digest
// header value for all required algorithms. This is the streaming API that uses
// O(1) memory regardless of content size.
//
// Parameters:
//   - reader: The message body as an io.Reader
//   - header: The Content-Digest header value (RFC 8941 Dictionary)
//   - requiredAlgorithms: List of algorithms that must be present and verified
//
// Returns error if:
//   - Header cannot be parsed
//   - Any required algorithm is missing from header
//   - Any digest verification fails (mismatch)
//   - Required algorithms list is empty
//   - Reader read fails
//
// Memory guarantee: O(1) - uses io.MultiWriter to compute all digests in single pass
func VerifyContentDigest(reader io.Reader, header string, requiredAlgorithms []string) error {
	if len(requiredAlgorithms) == 0 {
		return fmt.Errorf("requiredAlgorithms cannot be empty")
	}

	// Parse Content-Digest header
	headerDigests, err := ParseContentDigest(header)
	if err != nil {
		return fmt.Errorf("failed to parse Content-Digest header: %w", err)
	}

	// Create hashers for all required algorithms
	hashers := make(map[string]io.Writer, len(requiredAlgorithms))
	for _, algorithm := range requiredAlgorithms {
		// Verify algorithm is in header
		if _, found := headerDigests[algorithm]; !found {
			return fmt.Errorf("required algorithm %q not found in Content-Digest header", algorithm)
		}

		// Create hasher
		h, err := NewDigester(algorithm)
		if err != nil {
			return fmt.Errorf("failed to create digester for algorithm %q: %w", algorithm, err)
		}
		hashers[algorithm] = h
	}

	// Create MultiWriter for all hashers (single-pass streaming)
	writers := make([]io.Writer, 0, len(hashers))
	for _, h := range hashers {
		writers = append(writers, h)
	}
	multiWriter := io.MultiWriter(writers...)

	// Stream content through all hashers simultaneously (O(1) memory)
	_, err = io.Copy(multiWriter, reader)
	if err != nil {
		return fmt.Errorf("failed to read content: %w", err)
	}

	// Verify all digests using constant-time comparison
	for _, algorithm := range requiredAlgorithms {
		expectedDigest := headerDigests[algorithm]
		actualDigest := hashers[algorithm].(interface{ Sum([]byte) []byte }).Sum(nil)

		// Constant-time comparison (security requirement)
		if subtle.ConstantTimeCompare(actualDigest, expectedDigest) != 1 {
			return fmt.Errorf("digest mismatch for algorithm %q: verification failed", algorithm)
		}
	}

	return nil
}
