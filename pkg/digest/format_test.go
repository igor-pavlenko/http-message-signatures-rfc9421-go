package digest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// T016: Test FormatContentDigest with single algorithm
func TestFormatContentDigest_SingleAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		digests map[string][]byte
		want    string
	}{
		{
			name: "sha-256 only",
			digests: map[string][]byte{
				"sha-256": mustDecodeHex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
			},
			want: `sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`,
		},
		{
			name: "sha-512 only",
			digests: map[string][]byte{
				"sha-512": mustDecodeHex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
			},
			want: `sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==:`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FormatContentDigest(tt.digests)
			if err != nil {
				t.Fatalf("FormatContentDigest() error: %v", err)
			}
			if got != tt.want {
				t.Errorf("FormatContentDigest() mismatch:\ngot:  %q\nwant: %q", got, tt.want)
			}
		})
	}
}

// T016: Test FormatContentDigest with multiple algorithms
func TestFormatContentDigest_MultipleAlgorithms(t *testing.T) {
	digests := map[string][]byte{
		"sha-512":     mustDecodeHex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
		"sha-256":     mustDecodeHex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
		"blake2b-512": mustDecodeHex("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"),
	}

	got, err := FormatContentDigest(digests)
	if err != nil {
		t.Fatalf("FormatContentDigest() error: %v", err)
	}

	// Verify alphabetical ordering (RFC 8941 Dictionary requirement)
	// Expected: blake2b-512, sha-256, sha-512
	if !strings.HasPrefix(got, "blake2b-512=:") {
		t.Errorf("FormatContentDigest() not alphabetically ordered, got: %q", got)
	}

	// Verify all algorithms present
	if !strings.Contains(got, "blake2b-512=:") {
		t.Error("Missing blake2b-512 in output")
	}
	if !strings.Contains(got, "sha-256=:") {
		t.Error("Missing sha-256 in output")
	}
	if !strings.Contains(got, "sha-512=:") {
		t.Error("Missing sha-512 in output")
	}
}

// T016: Test FormatContentDigest validation
func TestFormatContentDigest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		digests map[string][]byte
		wantErr bool
	}{
		{
			name:    "nil map",
			digests: nil,
			wantErr: true,
		},
		{
			name:    "empty map",
			digests: map[string][]byte{},
			wantErr: true,
		},
		{
			name: "empty algorithm name",
			digests: map[string][]byte{
				"": []byte("digest"),
			},
			wantErr: true,
		},
		{
			name: "nil digest value",
			digests: map[string][]byte{
				"sha-256": nil,
			},
			wantErr: true,
		},
		{
			name: "empty digest value",
			digests: map[string][]byte{
				"sha-256": {},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FormatContentDigest(tt.digests)
			if (err != nil) != tt.wantErr {
				t.Errorf("FormatContentDigest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// T017: Test FormatContentDigest with real computed digests
func TestFormatContentDigest_WithRealDigests(t *testing.T) {
	body := []byte("test content")

	// Compute digests for multiple algorithms
	digests := make(map[string][]byte)
	for _, alg := range []string{AlgorithmSHA256, AlgorithmSHA512, AlgorithmBLAKE2b256} {
		d, err := ComputeDigest(body, alg)
		if err != nil {
			t.Fatalf("ComputeDigest(%q) failed: %v", alg, err)
		}
		digests[alg] = d
	}

	// Format
	header, err := FormatContentDigest(digests)
	if err != nil {
		t.Fatalf("FormatContentDigest() error: %v", err)
	}

	// Verify structure
	if !strings.Contains(header, "=:") || !strings.Contains(header, ":") {
		t.Errorf("FormatContentDigest() invalid format: %q", header)
	}

	// Verify alphabetical ordering
	if !strings.HasPrefix(header, "blake2b-256=:") {
		t.Errorf("FormatContentDigest() not alphabetically ordered: %q", header)
	}
}

// T017: Test base64 encoding in FormatContentDigest
func TestFormatContentDigest_Base64Encoding(t *testing.T) {
	digest := []byte{0x01, 0x02, 0x03, 0x04}
	digests := map[string][]byte{
		"sha-256": digest,
	}

	got, err := FormatContentDigest(digests)
	if err != nil {
		t.Fatalf("FormatContentDigest() error: %v", err)
	}

	// Extract base64 portion (format: "sha-256=:AQIDBA==:")
	if !strings.HasPrefix(got, "sha-256=:") || !strings.HasSuffix(got, ":") {
		t.Fatalf("Invalid format: %q", got)
	}
	b64Part := strings.TrimPrefix(got, "sha-256=:")
	b64Part = strings.TrimSuffix(b64Part, ":")

	// Decode and verify
	decoded, err := base64.StdEncoding.DecodeString(b64Part)
	if err != nil {
		t.Fatalf("Invalid base64: %v", err)
	}
	if !bytes.Equal(decoded, digest) {
		t.Errorf("Base64 round-trip failed: got %v, want %v", decoded, digest)
	}
}

// Helper: mustDecodeHex converts hex string to bytes (panics on error)
func mustDecodeHex(hexStr string) []byte {
	result, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	return result
}
