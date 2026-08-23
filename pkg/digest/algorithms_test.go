package digest

import (
	"encoding/hex"
	"strings"
	"testing"
)

// T005: Test all 7 modern algorithm constants exist
func TestAlgorithmConstants(t *testing.T) {
	algorithms := []string{
		AlgorithmSHA256,
		AlgorithmSHA512,
		AlgorithmSHA512256,
		AlgorithmSHA3256,
		AlgorithmSHA3512,
		AlgorithmBLAKE2b256,
		AlgorithmBLAKE2b512,
	}

	expected := []string{
		"sha-256",
		"sha-512",
		"sha-512/256",
		"sha3-256",
		"sha3-512",
		"blake2b-256",
		"blake2b-512",
	}

	for i, alg := range algorithms {
		if alg != expected[i] {
			t.Errorf("Algorithm constant mismatch: got %q, want %q", alg, expected[i])
		}
	}
}

// T005: Test SupportedAlgorithms contains exactly 7 algorithms
func TestSupportedAlgorithms(t *testing.T) {
	if len(SupportedAlgorithms) != 7 {
		t.Errorf("SupportedAlgorithms length: got %d, want 7", len(SupportedAlgorithms))
	}

	// Verify all constants are in SupportedAlgorithms
	expected := []string{
		AlgorithmSHA256, AlgorithmSHA512, AlgorithmSHA512256,
		AlgorithmSHA3256, AlgorithmSHA3512,
		AlgorithmBLAKE2b256, AlgorithmBLAKE2b512,
	}

	for _, alg := range expected {
		if _, ok := SupportedAlgorithms[alg]; !ok {
			t.Errorf("Algorithm %q not in SupportedAlgorithms", alg)
		}
	}
}

// T006: Test NewDigester creates correct hasher for each algorithm
func TestNewDigester_AllAlgorithms(t *testing.T) {
	tests := []struct {
		algorithm string
		wantSize  int // Expected digest output size
	}{
		{AlgorithmSHA256, 32},
		{AlgorithmSHA512, 64},
		{AlgorithmSHA512256, 32},
		{AlgorithmSHA3256, 32},
		{AlgorithmSHA3512, 64},
		{AlgorithmBLAKE2b256, 32},
		{AlgorithmBLAKE2b512, 64},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			h, err := NewDigester(tt.algorithm)
			if err != nil {
				t.Fatalf("NewDigester(%q) failed: %v", tt.algorithm, err)
			}
			if h == nil {
				t.Fatal("NewDigester returned nil hasher")
			}
			if h.Size() != tt.wantSize {
				t.Errorf("Size() = %d, want %d", h.Size(), tt.wantSize)
			}

			// Verify hash.Hash interface works
			h.Write([]byte("test"))
			digest := h.Sum(nil)
			if len(digest) != tt.wantSize {
				t.Errorf("Sum() returned %d bytes, want %d", len(digest), tt.wantSize)
			}
		})
	}
}

// T006: Test NewDigester rejects unsupported algorithms
func TestNewDigester_UnsupportedAlgorithms(t *testing.T) {
	tests := []string{
		"md5",       // Deprecated
		"sha-1",     // Deprecated
		"sha",       // Deprecated (alias for sha-1)
		"adler",     // Deprecated
		"crc32c",    // Deprecated
		"unixsum",   // Deprecated
		"unixcksum", // Deprecated
		"SHA-256",   // Wrong case
		"blake2b",   // Ambiguous (no size)
		"unknown",   // Unknown
		"",          // Empty
	}

	for _, alg := range tests {
		t.Run(alg, func(t *testing.T) {
			h, err := NewDigester(alg)
			if err == nil {
				t.Errorf("NewDigester(%q) succeeded, want error", alg)
			}
			if h != nil {
				t.Errorf("NewDigester(%q) returned non-nil hasher on error", alg)
			}
			if !strings.Contains(err.Error(), "unsupported algorithm") {
				t.Errorf("Error should contain 'unsupported algorithm': %v", err)
			}
		})
	}
}

// T006: Test NewDigester error messages are descriptive
func TestNewDigester_ErrorMessages(t *testing.T) {
	_, err := NewDigester("md5")
	if err == nil {
		t.Fatal("Expected error for deprecated algorithm")
	}

	// Should mention the algorithm
	errMsg := err.Error()
	if !strings.Contains(errMsg, "md5") {
		t.Errorf("Error should mention algorithm 'md5': %v", err)
	}
	if !strings.Contains(errMsg, "unsupported") {
		t.Errorf("Error should mention 'unsupported': %v", err)
	}
}

// T007: Test empty input vectors for all 7 algorithms
// Test vectors from FIPS 180-4, FIPS 202, RFC 7693
func TestNewDigester_EmptyInputVectors(t *testing.T) {
	tests := []struct {
		algorithm string
		expected  string // hex-encoded digest
	}{
		// SHA-2 family (FIPS 180-4)
		{AlgorithmSHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{AlgorithmSHA512, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
		{AlgorithmSHA512256, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"},
		// SHA-3 family (FIPS 202)
		{AlgorithmSHA3256, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
		{AlgorithmSHA3512, "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"},
		// BLAKE2b family (RFC 7693)
		{AlgorithmBLAKE2b256, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"},
		{AlgorithmBLAKE2b512, "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			h, err := NewDigester(tt.algorithm)
			if err != nil {
				t.Fatalf("NewDigester(%q) failed: %v", tt.algorithm, err)
			}

			// Hash empty input
			digest := h.Sum(nil)
			got := hex.EncodeToString(digest)

			if got != tt.expected {
				t.Errorf("Empty input digest mismatch:\ngot:  %s\nwant: %s", got, tt.expected)
			}
		})
	}
}
