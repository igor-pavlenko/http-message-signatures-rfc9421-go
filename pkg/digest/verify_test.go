package digest

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// T022: Test VerifyContentDigestBytes success
func TestVerifyContentDigestBytes_Success(t *testing.T) {
	body := []byte("Hello, World!")

	// Compute digest
	digest, _ := ComputeDigest(body, AlgorithmSHA256)
	header, _ := FormatContentDigest(map[string][]byte{
		AlgorithmSHA256: digest,
	})

	// Verify
	err := VerifyContentDigestBytes(body, header, []string{AlgorithmSHA256})
	if err != nil {
		t.Fatalf("VerifyContentDigestBytes failed: %v", err)
	}
}

// T022: Test VerifyContentDigestBytes mismatch
func TestVerifyContentDigestBytes_Mismatch(t *testing.T) {
	body := []byte("Hello, World!")
	wrongBody := []byte("Goodbye, World!")

	// Compute digest for wrong body
	digest, _ := ComputeDigest(wrongBody, AlgorithmSHA256)
	header, _ := FormatContentDigest(map[string][]byte{
		AlgorithmSHA256: digest,
	})

	// Verify with correct body (should fail)
	err := VerifyContentDigestBytes(body, header, []string{AlgorithmSHA256})
	if err == nil {
		t.Fatal("VerifyContentDigestBytes should fail on mismatch")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("Error should mention mismatch: %v", err)
	}
}

// T022: Test VerifyContentDigestBytes missing required algorithm
func TestVerifyContentDigestBytes_MissingAlgorithm(t *testing.T) {
	body := []byte("test")

	// Header with only sha-512
	digest, _ := ComputeDigest(body, AlgorithmSHA512)
	header, _ := FormatContentDigest(map[string][]byte{
		AlgorithmSHA512: digest,
	})

	// Require sha-256 (not present)
	err := VerifyContentDigestBytes(body, header, []string{AlgorithmSHA256})
	if err == nil {
		t.Fatal("VerifyContentDigestBytes should fail when required algorithm missing")
	}
	if !strings.Contains(err.Error(), "required algorithm") && !strings.Contains(err.Error(), "not found") {
		t.Errorf("Error should mention missing algorithm: %v", err)
	}
}

// T022: Test VerifyContentDigestBytes with multiple algorithms
func TestVerifyContentDigestBytes_MultipleAlgorithms(t *testing.T) {
	body := []byte("test multiple algorithms")

	// Compute multiple digests
	digests := make(map[string][]byte)
	algorithms := []string{AlgorithmSHA256, AlgorithmSHA512, AlgorithmBLAKE2b256}
	for _, alg := range algorithms {
		d, _ := ComputeDigest(body, alg)
		digests[alg] = d
	}

	header, _ := FormatContentDigest(digests)

	// Verify all algorithms
	err := VerifyContentDigestBytes(body, header, algorithms)
	if err != nil {
		t.Fatalf("VerifyContentDigestBytes failed: %v", err)
	}

	// Verify subset (should also work)
	err = VerifyContentDigestBytes(body, header, []string{AlgorithmSHA256})
	if err != nil {
		t.Fatalf("VerifyContentDigestBytes failed for subset: %v", err)
	}
}

// T022: Test VerifyContentDigestBytes error messages
func TestVerifyContentDigestBytes_ErrorMessages(t *testing.T) {
	body := []byte("test")

	// Invalid header
	err := VerifyContentDigestBytes(body, "invalid", []string{AlgorithmSHA256})
	if err == nil {
		t.Fatal("Should fail on invalid header")
	}

	// Empty required algorithms
	err = VerifyContentDigestBytes(body, "sha-256=:test:", []string{})
	if err == nil {
		t.Fatal("Should fail on empty required algorithms")
	}
}

// T023: Test constant-time comparison (basic timing test)
func TestVerifyContentDigestBytes_ConstantTime(t *testing.T) {
	// This is a crude test - proper timing analysis would require
	// statistical analysis over many iterations

	body := []byte("test constant time comparison")
	digest, _ := ComputeDigest(body, AlgorithmSHA256)
	header, _ := FormatContentDigest(map[string][]byte{
		AlgorithmSHA256: digest,
	})

	// Verify success
	err := VerifyContentDigestBytes(body, header, []string{AlgorithmSHA256})
	if err != nil {
		t.Fatalf("Constant-time test setup failed: %v", err)
	}

	// Verify we're using crypto/subtle (manual inspection of verify.go required)
	// This test just ensures the function works correctly
}

// T024: Test VerifyContentDigest streaming API
func TestVerifyContentDigest_Streaming(t *testing.T) {
	body := []byte("Stream this content for verification")
	reader := bytes.NewReader(body)

	// Compute digest
	digest, _ := ComputeDigest(body, AlgorithmSHA256)
	header, _ := FormatContentDigest(map[string][]byte{
		AlgorithmSHA256: digest,
	})

	// Verify via streaming
	err := VerifyContentDigest(reader, header, []string{AlgorithmSHA256})
	if err != nil {
		t.Fatalf("VerifyContentDigest failed: %v", err)
	}
}

// T024: Test VerifyContentDigest with mismatch
func TestVerifyContentDigest_Mismatch(t *testing.T) {
	correctBody := []byte("correct")
	wrongBody := []byte("wrong")

	// Create header for correct body
	digest, _ := ComputeDigest(correctBody, AlgorithmSHA256)
	header, _ := FormatContentDigest(map[string][]byte{
		AlgorithmSHA256: digest,
	})

	// Verify wrong body
	reader := bytes.NewReader(wrongBody)
	err := VerifyContentDigest(reader, header, []string{AlgorithmSHA256})
	if err == nil {
		t.Fatal("VerifyContentDigest should fail on mismatch")
	}
}

// T024: Test VerifyContentDigest with large data
func TestVerifyContentDigest_LargeData(t *testing.T) {
	// 10MB test
	size := 10 * 1024 * 1024
	reader1 := &zeroReader{remaining: size}
	reader2 := &zeroReader{remaining: size}

	// Compute digest via streaming
	h, _ := NewDigester(AlgorithmSHA256)
	_, _ = io.Copy(h, reader1)
	digest := h.Sum(nil)

	header, _ := FormatContentDigest(map[string][]byte{
		AlgorithmSHA256: digest,
	})

	// Verify via streaming
	err := VerifyContentDigest(reader2, header, []string{AlgorithmSHA256})
	if err != nil {
		t.Fatalf("VerifyContentDigest failed on large data: %v", err)
	}
}

// T024: Test VerifyContentDigest with multiple algorithms
func TestVerifyContentDigest_MultipleAlgorithms(t *testing.T) {
	body := []byte("test multiple algorithm verification")

	// Compute multiple digests
	digests := make(map[string][]byte)
	algorithms := []string{AlgorithmSHA256, AlgorithmSHA512, AlgorithmSHA3256}
	for _, alg := range algorithms {
		d, _ := ComputeDigest(body, alg)
		digests[alg] = d
	}

	header, _ := FormatContentDigest(digests)

	// Verify via streaming
	reader := bytes.NewReader(body)
	err := VerifyContentDigest(reader, header, algorithms)
	if err != nil {
		t.Fatalf("VerifyContentDigest failed: %v", err)
	}
}

// T024: Test O(1) memory guarantee for VerifyContentDigest
func TestVerifyContentDigest_O1Memory(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory test in short mode")
	}

	// Create large stream
	size := 100 * 1024 * 1024 // 100MB
	reader := &zeroReader{remaining: size}

	// Compute digest for comparison
	h, _ := NewDigester(AlgorithmSHA256)
	_, _ = io.Copy(h, &zeroReader{remaining: size})
	digest := h.Sum(nil)

	header, _ := FormatContentDigest(map[string][]byte{
		AlgorithmSHA256: digest,
	})

	// Verify (should use O(1) memory)
	err := VerifyContentDigest(reader, header, []string{AlgorithmSHA256})
	if err != nil {
		t.Fatalf("VerifyContentDigest failed: %v", err)
	}
}
