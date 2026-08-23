package digest

import (
	"bytes"
	"encoding/hex"
	"io"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// getAllSupportedAlgorithms returns all supported algorithms as a slice for tests
func getAllSupportedAlgorithms() []string {
	algs := make([]string, 0, len(SupportedAlgorithms))
	for alg := range SupportedAlgorithms {
		algs = append(algs, alg)
	}
	return algs
}

// T008: Test ComputeDigest basic functionality
func TestComputeDigest_Basic(t *testing.T) {
	tests := []struct {
		name      string
		body      []byte
		algorithm string
		wantHex   string
	}{
		{
			name:      "sha-256 empty",
			body:      []byte{},
			algorithm: AlgorithmSHA256,
			wantHex:   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:      "sha-256 hello",
			body:      []byte("hello world"),
			algorithm: AlgorithmSHA256,
			wantHex:   "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
		{
			name:      "sha-512 empty",
			body:      []byte{},
			algorithm: AlgorithmSHA512,
			wantHex:   "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		},
		{
			name:      "blake2b-256 test",
			body:      []byte("test"),
			algorithm: AlgorithmBLAKE2b256,
			wantHex:   "928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest, err := ComputeDigest(tt.body, tt.algorithm)
			if err != nil {
				t.Fatalf("ComputeDigest() error: %v", err)
			}
			got := hex.EncodeToString(digest)
			if got != tt.wantHex {
				t.Errorf("ComputeDigest() digest mismatch:\ngot:  %s\nwant: %s", got, tt.wantHex)
			}
		})
	}
}

// T008: Test ComputeDigest with unsupported algorithm
func TestComputeDigest_UnsupportedAlgorithm(t *testing.T) {
	_, err := ComputeDigest([]byte("test"), "md5")
	if err == nil {
		t.Fatal("ComputeDigest with md5 should fail")
	}
}

// T008: Test ComputeDigest equivalence with NewDigester
func TestComputeDigest_EquivalenceWithStreaming(t *testing.T) {
	body := []byte("The quick brown fox jumps over the lazy dog")

	for alg := range SupportedAlgorithms {
		t.Run(alg, func(t *testing.T) {
			// Compute using convenience API
			digest1, err := ComputeDigest(body, alg)
			if err != nil {
				t.Fatalf("ComputeDigest failed: %v", err)
			}

			// Compute using streaming API
			h, err := NewDigester(alg)
			if err != nil {
				t.Fatalf("NewDigester failed: %v", err)
			}
			h.Write(body)
			digest2 := h.Sum(nil)

			if !bytes.Equal(digest1, digest2) {
				t.Errorf("Digest mismatch:\nComputeDigest: %x\nNewDigester:   %x", digest1, digest2)
			}
		})
	}
}

// T008: Test ComputeDigest is deterministic
func TestComputeDigest_Deterministic(t *testing.T) {
	body := []byte("deterministic test")
	alg := AlgorithmSHA256

	digest1, _ := ComputeDigest(body, alg)
	digest2, _ := ComputeDigest(body, alg)

	if !bytes.Equal(digest1, digest2) {
		t.Errorf("ComputeDigest not deterministic: %x != %x", digest1, digest2)
	}
}

// T014: Test streaming digest computation
func TestStreaming_IncrementalWrites(t *testing.T) {
	data := []byte("Hello, World!")
	algorithm := AlgorithmSHA256

	// Compute in one go
	h1, _ := NewDigester(algorithm)
	h1.Write(data)
	digest1 := h1.Sum(nil)

	// Compute incrementally
	h2, _ := NewDigester(algorithm)
	h2.Write(data[:5])  // "Hello"
	h2.Write(data[5:7]) // ", "
	h2.Write(data[7:])  // "World!"
	digest2 := h2.Sum(nil)

	if !bytes.Equal(digest1, digest2) {
		t.Errorf("Incremental writes produced different digest:\none go:       %x\nincremental: %x", digest1, digest2)
	}
}

// T014: Test io.Copy integration
func TestStreaming_IOCopyIntegration(t *testing.T) {
	data := []byte("Stream this data through io.Copy")
	reader := bytes.NewReader(data)

	h, err := NewDigester(AlgorithmSHA256)
	if err != nil {
		t.Fatalf("NewDigester failed: %v", err)
	}

	n, err := io.Copy(h, reader)
	if err != nil {
		t.Fatalf("io.Copy failed: %v", err)
	}
	if n != int64(len(data)) {
		t.Errorf("io.Copy copied %d bytes, want %d", n, len(data))
	}

	digest := h.Sum(nil)

	// Verify against direct computation
	expected, _ := ComputeDigest(data, AlgorithmSHA256)
	if !bytes.Equal(digest, expected) {
		t.Errorf("io.Copy digest mismatch:\ngot:  %x\nwant: %x", digest, expected)
	}
}

// T014: Test hasher Reset() for reuse
func TestStreaming_HasherReset(t *testing.T) {
	h, _ := NewDigester(AlgorithmSHA256)

	// First computation
	h.Write([]byte("first"))
	digest1 := h.Sum(nil)

	// Reset and compute again
	h.Reset()
	h.Write([]byte("second"))
	digest2 := h.Sum(nil)

	// Verify digests are different
	if bytes.Equal(digest1, digest2) {
		t.Error("Reset() did not clear hasher state")
	}

	// Verify second computation is correct
	expected, _ := ComputeDigest([]byte("second"), AlgorithmSHA256)
	if !bytes.Equal(digest2, expected) {
		t.Errorf("Reset() hasher produced wrong digest:\ngot:  %x\nwant: %x", digest2, expected)
	}
}

// T015: Test streaming with large mock reader
func TestStreaming_LargeData(t *testing.T) {
	// Create 10MB of data
	size := 10 * 1024 * 1024
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}

	reader := bytes.NewReader(data)
	h, _ := NewDigester(AlgorithmSHA256)

	_, err := io.Copy(h, reader)
	if err != nil {
		t.Fatalf("io.Copy failed on large data: %v", err)
	}

	digest := h.Sum(nil)
	if len(digest) != 32 {
		t.Errorf("Digest size wrong: got %d, want 32", len(digest))
	}

	// Verify consistency with direct computation
	expected, _ := ComputeDigest(data, AlgorithmSHA256)
	if !bytes.Equal(digest, expected) {
		t.Error("Large data streaming produced different digest")
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkComputeDigest_SHA256_1KB(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ComputeDigest(data, AlgorithmSHA256)
	}
}

func BenchmarkComputeDigest_SHA256_10KB(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 10*1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ComputeDigest(data, AlgorithmSHA256)
	}
}

func BenchmarkComputeDigest_SHA256_100KB(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 100*1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ComputeDigest(data, AlgorithmSHA256)
	}
}

func BenchmarkComputeDigest_SHA512_1KB(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ComputeDigest(data, AlgorithmSHA512)
	}
}

func BenchmarkComputeDigest_SHA512_10KB(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 10*1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ComputeDigest(data, AlgorithmSHA512)
	}
}

func BenchmarkComputeDigest_SHA512_100KB(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 100*1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ComputeDigest(data, AlgorithmSHA512)
	}
}

func BenchmarkComputeDigest_BLAKE2b256_1KB(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ComputeDigest(data, AlgorithmBLAKE2b256)
	}
}

func BenchmarkComputeDigest_BLAKE2b256_10KB(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 10*1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ComputeDigest(data, AlgorithmBLAKE2b256)
	}
}

func BenchmarkComputeDigest_BLAKE2b256_100KB(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 100*1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ComputeDigest(data, AlgorithmBLAKE2b256)
	}
}

// Streaming benchmarks
func BenchmarkStreaming_SHA256_1KB(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h, _ := NewDigester(AlgorithmSHA256)
		_, _ = io.Copy(h, bytes.NewReader(data))
		_ = h.Sum(nil)
	}
}

func BenchmarkStreaming_SHA256_10KB(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 10*1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h, _ := NewDigester(AlgorithmSHA256)
		_, _ = io.Copy(h, bytes.NewReader(data))
		_ = h.Sum(nil)
	}
}

func BenchmarkStreaming_SHA256_100KB(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 100*1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h, _ := NewDigester(AlgorithmSHA256)
		_, _ = io.Copy(h, bytes.NewReader(data))
		_ = h.Sum(nil)
	}
}

type repeatReader struct {
	chunk     []byte
	remaining int64
	offset    int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n := 0
	for n < len(p) {
		avail := min(len(r.chunk)-r.offset, len(p)-n)
		copy(p[n:n+avail], r.chunk[r.offset:r.offset+avail])
		n += avail
		r.offset += avail
		if r.offset == len(r.chunk) {
			r.offset = 0
		}
	}
	r.remaining -= int64(n)
	return n, nil
}

func BenchmarkStreaming_SHA256_10MB(b *testing.B) {
	const size = 10 * 1024 * 1024
	chunk := bytes.Repeat([]byte("a"), 32*1024)
	buf := make([]byte, 32*1024)
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h, _ := NewDigester(AlgorithmSHA256)
		reader := &repeatReader{chunk: chunk, remaining: size}
		_, _ = io.CopyBuffer(h, reader, buf)
		_ = h.Sum(nil)
	}
}

// Verification benchmarks
func BenchmarkVerifyContentDigestBytes_SHA256_1KB(b *testing.B) {
	body := bytes.Repeat([]byte("a"), 1024)
	digest, _ := ComputeDigest(body, AlgorithmSHA256)
	header, _ := FormatContentDigest(map[string][]byte{AlgorithmSHA256: digest})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifyContentDigestBytes(body, header, []string{AlgorithmSHA256})
	}
}

func BenchmarkVerifyContentDigestBytes_SHA256_10KB(b *testing.B) {
	body := bytes.Repeat([]byte("a"), 10*1024)
	digest, _ := ComputeDigest(body, AlgorithmSHA256)
	header, _ := FormatContentDigest(map[string][]byte{AlgorithmSHA256: digest})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifyContentDigestBytes(body, header, []string{AlgorithmSHA256})
	}
}

func BenchmarkVerifyContentDigestBytes_MultipleAlgorithms_1KB(b *testing.B) {
	body := bytes.Repeat([]byte("a"), 1024)
	algorithms := []string{AlgorithmSHA256, AlgorithmSHA512, AlgorithmBLAKE2b256}

	digests := make(map[string][]byte)
	for _, alg := range algorithms {
		d, _ := ComputeDigest(body, alg)
		digests[alg] = d
	}
	header, _ := FormatContentDigest(digests)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifyContentDigestBytes(body, header, algorithms)
	}
}

// Format/Parse benchmarks
func BenchmarkFormatContentDigest_SingleAlgorithm(b *testing.B) {
	digest := bytes.Repeat([]byte{0x01}, 32)
	digests := map[string][]byte{AlgorithmSHA256: digest}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = FormatContentDigest(digests)
	}
}

func BenchmarkFormatContentDigest_MultipleAlgorithms(b *testing.B) {
	digests := map[string][]byte{
		AlgorithmSHA256:     bytes.Repeat([]byte{0x01}, 32),
		AlgorithmSHA512:     bytes.Repeat([]byte{0x02}, 64),
		AlgorithmBLAKE2b256: bytes.Repeat([]byte{0x03}, 32),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = FormatContentDigest(digests)
	}
}

func BenchmarkParseContentDigest_SingleAlgorithm(b *testing.B) {
	header := "sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseContentDigest(header)
	}
}

func BenchmarkParseContentDigest_MultipleAlgorithms(b *testing.B) {
	header := "blake2b-256=:DldRwCblQ7Loqy6wYJnaoR0V30d3j3eH+qtFzfEv46g=:, sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:, sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==:"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseContentDigest(header)
	}
}

// All algorithms comparison
func BenchmarkAllAlgorithms_1KB(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 1024)

	for alg := range SupportedAlgorithms {
		b.Run(alg, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = ComputeDigest(data, alg)
			}
		})
	}
}

// ============================================================================
// Memory/Performance Tests
// ============================================================================

func TestMemoryProfile_StreamingO1(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory profiling test in short mode")
	}

	// Test with different data sizes
	sizes := []int{
		1024 * 1024,       // 1MB
		10 * 1024 * 1024,  // 10MB
		100 * 1024 * 1024, // 100MB
	}

	for _, size := range sizes {
		t.Run(formatSize(uint64(size)), func(t *testing.T) { //nolint:gosec // size is a non-negative compile-time constant
			// Force GC before measurement
			runtime.GC()

			var m1, m2 runtime.MemStats
			runtime.ReadMemStats(&m1)

			// Create streaming hasher
			h, err := NewDigester(AlgorithmSHA256)
			if err != nil {
				t.Fatalf("NewDigester failed: %v", err)
			}

			// Stream large data
			reader := &zeroReader{remaining: size}
			_, err = io.Copy(h, reader)
			if err != nil {
				t.Fatalf("io.Copy failed: %v", err)
			}

			_ = h.Sum(nil)

			runtime.ReadMemStats(&m2)

			// Memory used should be O(1), not O(n)
			// Allow up to 10MB for overhead (should be much less)
			memUsed := m2.Alloc - m1.Alloc
			maxAllowed := uint64(10 * 1024 * 1024)

			t.Logf("Size: %s, Memory used: %s", formatSize(uint64(size)), formatSize(memUsed)) //nolint:gosec // size is a non-negative compile-time constant

			if memUsed > maxAllowed {
				t.Errorf("Memory usage too high: %d bytes (max %d)", memUsed, maxAllowed)
			}
		})
	}
}

// T020: Test memory scalability (1GB test)
func TestMemoryProfile_LargeFile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large file test in short mode")
	}

	size := 1024 * 1024 * 1024 // 1GB

	runtime.GC()
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	h, _ := NewDigester(AlgorithmSHA256)
	reader := &zeroReader{remaining: size}
	_, err := io.Copy(h, reader)
	if err != nil {
		t.Fatalf("io.Copy failed: %v", err)
	}
	_ = h.Sum(nil)

	runtime.ReadMemStats(&m2)

	memUsed := m2.Alloc - m1.Alloc
	maxAllowed := uint64(10 * 1024 * 1024) // 10MB max

	t.Logf("1GB file: Memory used: %s (max allowed: %s)", formatSize(memUsed), formatSize(maxAllowed))

	if memUsed > maxAllowed {
		t.Errorf("Memory usage for 1GB file too high: %d bytes (should be <10MB)", memUsed)
	}
}

// Benchmark memory allocations for different algorithms
func BenchmarkMemoryAllocations(b *testing.B) {
	data := bytes.Repeat([]byte("test"), 256) // 1KB

	for alg := range SupportedAlgorithms {
		b.Run(alg, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				h, _ := NewDigester(alg)
				h.Write(data)
				_ = h.Sum(nil)
			}
		})
	}
}

// zeroReader is a reader that returns zeros without allocating memory
type zeroReader struct {
	remaining int
}

func (r *zeroReader) Read(p []byte) (n int, err error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}

	n = min(len(p), r.remaining)

	// Write zeros (p is already zeroed by Go runtime)
	for i := 0; i < n; i++ {
		p[i] = 0
	}

	r.remaining -= n
	return n, nil
}

// formatSize formats byte size for human readability
func formatSize(bytes uint64) string {
	if bytes < 1024 {
		return strconv.FormatUint(bytes, 10) + "B"
	} else if bytes < 1024*1024 {
		return strconv.FormatUint(bytes/1024, 10) + "KB"
	} else if bytes < 1024*1024*1024 {
		return strconv.FormatUint(bytes/(1024*1024), 10) + "MB"
	}
	return strconv.FormatUint(bytes/(1024*1024*1024), 10) + "GB"
}

// ============================================================================
// Integration Tests
// ============================================================================

func TestIntegration_RoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		body       []byte
		algorithms []string
	}{
		{
			name:       "single algorithm",
			body:       []byte("Hello, World!"),
			algorithms: []string{AlgorithmSHA256},
		},
		{
			name:       "multiple algorithms",
			body:       []byte("The quick brown fox jumps over the lazy dog"),
			algorithms: []string{AlgorithmSHA256, AlgorithmSHA512, AlgorithmBLAKE2b256},
		},
		{
			name:       "all 7 algorithms",
			body:       []byte("Test all algorithms"),
			algorithms: getAllSupportedAlgorithms(),
		},
		{
			name:       "empty body",
			body:       []byte{},
			algorithms: []string{AlgorithmSHA256, AlgorithmSHA3512},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Compute digests
			digests := make(map[string][]byte)
			for _, alg := range tt.algorithms {
				d, err := ComputeDigest(tt.body, alg)
				if err != nil {
					t.Fatalf("ComputeDigest(%q) failed: %v", alg, err)
				}
				digests[alg] = d
			}

			// Step 2: Format as Content-Digest header
			header, err := FormatContentDigest(digests)
			if err != nil {
				t.Fatalf("FormatContentDigest() failed: %v", err)
			}

			// Step 3: Parse header back
			parsed, err := ParseContentDigest(header)
			if err != nil {
				t.Fatalf("ParseContentDigest() failed: %v", err)
			}

			// Step 4: Verify equality
			if len(parsed) != len(digests) {
				t.Fatalf("Round-trip length mismatch: got %d, want %d", len(parsed), len(digests))
			}

			for alg, originalDigest := range digests {
				parsedDigest, ok := parsed[alg]
				if !ok {
					t.Errorf("Algorithm %q missing after round-trip", alg)
					continue
				}
				if !bytes.Equal(parsedDigest, originalDigest) {
					t.Errorf("Algorithm %q digest mismatch after round-trip:\noriginal: %x\nparsed:   %x", alg, originalDigest, parsedDigest)
				}
			}
		})
	}
}

// T019: Test round-trip with edge cases
func TestIntegration_RoundTripEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{
			name: "binary data",
			body: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
		},
		{
			name: "large text",
			body: bytes.Repeat([]byte("Lorem ipsum dolor sit amet. "), 1000),
		},
		{
			name: "unicode text",
			body: []byte("Hello 世界 🌍"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use sha-256 for edge case testing
			digest, err := ComputeDigest(tt.body, AlgorithmSHA256)
			if err != nil {
				t.Fatalf("ComputeDigest failed: %v", err)
			}

			header, err := FormatContentDigest(map[string][]byte{
				AlgorithmSHA256: digest,
			})
			if err != nil {
				t.Fatalf("FormatContentDigest failed: %v", err)
			}

			parsed, err := ParseContentDigest(header)
			if err != nil {
				t.Fatalf("ParseContentDigest failed: %v", err)
			}

			if !bytes.Equal(parsed[AlgorithmSHA256], digest) {
				t.Errorf("Round-trip failed for edge case")
			}
		})
	}
}

// T025: End-to-end integration test (generate → verify)
func TestIntegration_EndToEnd(t *testing.T) {
	tests := []struct {
		name       string
		body       []byte
		algorithms []string
	}{
		{
			name:       "single algorithm workflow",
			body:       []byte("Complete workflow test"),
			algorithms: []string{AlgorithmSHA256},
		},
		{
			name:       "all algorithms workflow",
			body:       []byte("Test all 7 algorithms in complete workflow"),
			algorithms: getAllSupportedAlgorithms(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Generate digests
			digests := make(map[string][]byte)
			for _, alg := range tt.algorithms {
				d, err := ComputeDigest(tt.body, alg)
				if err != nil {
					t.Fatalf("ComputeDigest failed: %v", err)
				}
				digests[alg] = d
			}

			// Step 2: Format header
			header, err := FormatContentDigest(digests)
			if err != nil {
				t.Fatalf("FormatContentDigest failed: %v", err)
			}

			// Step 3: Verify using VerifyContentDigestBytes
			err = VerifyContentDigestBytes(tt.body, header, tt.algorithms)
			if err != nil {
				t.Fatalf("VerifyContentDigestBytes failed: %v", err)
			}

			// Step 4: Verify using streaming API
			reader := bytes.NewReader(tt.body)
			err = VerifyContentDigest(reader, header, tt.algorithms)
			if err != nil {
				t.Fatalf("VerifyContentDigest failed: %v", err)
			}
		})
	}
}

// T025: Integration test with streaming large files
func TestIntegration_StreamingLargeFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large file test in short mode")
	}

	size := 50 * 1024 * 1024 // 50MB
	algorithms := []string{AlgorithmSHA256, AlgorithmSHA512}

	// Compute digests via streaming
	digests := make(map[string][]byte)
	for _, alg := range algorithms {
		h, _ := NewDigester(alg)
		reader := &zeroReader{remaining: size}
		_, _ = io.Copy(h, reader)
		digests[alg] = h.Sum(nil)
	}

	// Format header
	header, _ := FormatContentDigest(digests)

	// Verify via streaming
	reader := &zeroReader{remaining: size}
	err := VerifyContentDigest(reader, header, algorithms)
	if err != nil {
		t.Fatalf("Large file verification failed: %v", err)
	}
}

// T025: Integration test with all error scenarios
func TestIntegration_ErrorScenarios(t *testing.T) {
	body := []byte("error scenario test")

	tests := []struct {
		name        string
		setupHeader func() string
		required    []string
		wantErr     bool
		errContains string
	}{
		{
			name: "corrupted digest",
			setupHeader: func() string {
				// Compute correct digest then corrupt it
				d, _ := ComputeDigest(body, AlgorithmSHA256)
				d[0] ^= 0xFF // Flip bits
				header, _ := FormatContentDigest(map[string][]byte{AlgorithmSHA256: d})
				return header
			},
			required:    []string{AlgorithmSHA256},
			wantErr:     true,
			errContains: "mismatch",
		},
		{
			name: "missing required algorithm",
			setupHeader: func() string {
				d, _ := ComputeDigest(body, AlgorithmSHA512)
				header, _ := FormatContentDigest(map[string][]byte{AlgorithmSHA512: d})
				return header
			},
			required:    []string{AlgorithmSHA256},
			wantErr:     true,
			errContains: "not found",
		},
		{
			name: "invalid header syntax",
			setupHeader: func() string {
				return "invalid header format"
			},
			required:    []string{AlgorithmSHA256},
			wantErr:     true,
			errContains: "parse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := tt.setupHeader()
			err := VerifyContentDigestBytes(body, header, tt.required)

			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Error should contain %q: %v", tt.errContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// T025: Integration test for all 7 algorithms simultaneously
func TestIntegration_All7AlgorithmsSimultaneously(t *testing.T) {
	body := []byte("Test all 7 modern cryptographic algorithms simultaneously")

	// Compute all digests
	digests := make(map[string][]byte)
	for alg := range SupportedAlgorithms {
		d, err := ComputeDigest(body, alg)
		if err != nil {
			t.Fatalf("ComputeDigest(%q) failed: %v", alg, err)
		}
		digests[alg] = d
	}

	// Format
	header, err := FormatContentDigest(digests)
	if err != nil {
		t.Fatalf("FormatContentDigest failed: %v", err)
	}

	// Verify all
	err = VerifyContentDigestBytes(body, header, getAllSupportedAlgorithms())
	if err != nil {
		t.Fatalf("Verification of all 7 algorithms failed: %v", err)
	}

	// Verify via streaming
	reader := bytes.NewReader(body)
	err = VerifyContentDigest(reader, header, getAllSupportedAlgorithms())
	if err != nil {
		t.Fatalf("Streaming verification of all 7 algorithms failed: %v", err)
	}
}
