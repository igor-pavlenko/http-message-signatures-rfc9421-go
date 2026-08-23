package digest

import (
	"bytes"
	"strings"
	"testing"
)

// T018: Test ParseContentDigest with valid headers
func TestParseContentDigest_Valid(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   map[string][]byte
	}{
		{
			name:   "single sha-256",
			header: `sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`,
			want: map[string][]byte{
				"sha-256": mustDecodeHex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
			},
		},
		{
			name:   "multiple algorithms",
			header: `sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:, sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==:`,
			want: map[string][]byte{
				"sha-256": mustDecodeHex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
				"sha-512": mustDecodeHex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
			},
		},
		{
			name:   "all 7 algorithms",
			header: `blake2b-256=:DldRwCblQ7Loqy6wYJnaoR0V30d3j3eH+qtFzfEv46g=:, blake2b-512=:eGoCt0IBWQPGxv2FJVLSKS8UdA4VhHYYqG4hf3H1QZ0l4QMa/uWFMTiWRESTTrBLkDpoWxRIt1XVb3Aa/pvizg==:, sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:, sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==:, sha-512/256=:xnK40e9W7SireMNiLFEUBputOte4+XN0mNDAHs7wlno=:, sha3-256=:p//G+L8e12ZRwUdWoGHWYvWA/03kO0n6gtgKS4D4Q0o=:, sha3-512=:pp9zzKI6msXItWfcGFp1bpfJghZP4lhZ4NHcwUdcgKYVshI68fX5TBHj6UAsOsVY9QAZnZW20+MBdYWGKB3NJg==:`,
			want: map[string][]byte{
				"blake2b-256": mustDecodeHex("0e5751c026e543b2e8ab2eb06099daa11d15df47778f7787faab45cdf12fe3a8"),
				"blake2b-512": mustDecodeHex("786a02b742015903c6c6fd852552d2292f14740e15847618a86e217f71f5419d25e1031afee5853138964444934eb04b903a685b1448b755d56f701afe9be2ce"),
				"sha-256":     mustDecodeHex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"),
				"sha-512":     mustDecodeHex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
				"sha-512/256": mustDecodeHex("c672b8d1ef56ed28ab78c3622c5114069bad3ad7b8f9737498d0c01ecef0967a"),
				"sha3-256":    mustDecodeHex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
				"sha3-512":    mustDecodeHex("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseContentDigest(tt.header)
			if err != nil {
				t.Fatalf("ParseContentDigest() error: %v", err)
			}

			if len(got) != len(tt.want) {
				t.Fatalf("ParseContentDigest() length mismatch: got %d, want %d", len(got), len(tt.want))
			}

			for alg, wantDigest := range tt.want {
				gotDigest, ok := got[alg]
				if !ok {
					t.Errorf("ParseContentDigest() missing algorithm %q", alg)
					continue
				}
				if !bytes.Equal(gotDigest, wantDigest) {
					t.Errorf("ParseContentDigest() digest mismatch for %q:\ngot:  %x\nwant: %x", alg, gotDigest, wantDigest)
				}
			}
		})
	}
}

// T018: Test ParseContentDigest with invalid syntax
func TestParseContentDigest_InvalidSyntax(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{
			name:   "empty header",
			header: "",
		},
		{
			name:   "invalid format",
			header: "sha-256:not-byte-sequence",
		},
		{
			name:   "missing colon delimiters",
			header: "sha-256=base64data",
		},
		{
			name:   "invalid base64",
			header: "sha-256=:not-valid-base64!@#::",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseContentDigest(tt.header)
			if err == nil {
				t.Errorf("ParseContentDigest(%q) should fail", tt.header)
			}
		})
	}
}

// T018: Test ParseContentDigest rejects deprecated algorithms
func TestParseContentDigest_DeprecatedAlgorithms(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{
			name:   "md5",
			header: `md5=:AAAA:`,
		},
		{
			name:   "sha-1",
			header: `sha-1=:AAAA:`,
		},
		{
			name:   "mixed with supported",
			header: `sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:, md5=:AAAA:`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseContentDigest(tt.header)
			if err == nil {
				t.Errorf("ParseContentDigest(%q) should reject deprecated algorithm", tt.header)
			}
			if !strings.Contains(err.Error(), "unsupported") {
				t.Errorf("Error should mention unsupported algorithm: %v", err)
			}
		})
	}
}

// T018: Test ParseContentDigest validates digest length
func TestParseContentDigest_DigestLength(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{
			name:   "sha-256 too short",
			header: `sha-256=:YWJj:`, // "abc" in base64 (3 bytes, should be 32)
		},
		{
			name:   "sha-512 too short",
			header: `sha-512=:YWJj:`, // "abc" in base64 (3 bytes, should be 64)
		},
		{
			name:   "blake2b-256 wrong size",
			header: `blake2b-256=:AAAAAAAAAAAAAAAA:`, // Wrong size
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseContentDigest(tt.header)
			if err == nil {
				t.Errorf("ParseContentDigest(%q) should fail on wrong digest length", tt.header)
			}
			if !strings.Contains(err.Error(), "digest length") && !strings.Contains(err.Error(), "bytes") {
				t.Errorf("Error should mention digest length: %v", err)
			}
		})
	}
}

// ============================================================================
// Fuzz Tests
// ============================================================================

func FuzzParseContentDigest(f *testing.F) {
	// Seed corpus with known valid and invalid cases
	seeds := []string{
		// Valid single algorithm headers
		`sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`,
		`sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==:`,
		`sha-512/256=:xnK40e9W7SireMNiLFEUBputOte4+XN0mNDAHs7wlno=:`,
		`sha3-256=:p//G+L8e12ZRwUdWoGHWYvWA/03kO0n6gtgKS4D4Q0o=:`,
		`sha3-512=:pp9zzKI6msXItWfcGFp1bpfJghZP4lhZ4NHcwUdcgKYVshI68fX5TBHj6UAsOsVY9QAZnZW20+MBdYWGKB3NJg==:`,
		`blake2b-256=:DldRwCblQ7Loqy6wYJnaoR0V30d3j3eH+qtFzfEv46g=:`,
		`blake2b-512=:eGoCt0IBWQPGxv2FJVLSKS8UdA4VhHYYqG4hf3H1QZ0l4QMa/uWFMTiWRESTTrBLkDpoWxRIt1XVb3Aa/pvizg==:`,

		// Valid multiple algorithms
		`sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:, sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==:`,
		`blake2b-256=:DldRwCblQ7Loqy6wYJnaoR0V30d3j3eH+qtFzfEv46g=:, sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`,

		// Valid all 7 algorithms
		`blake2b-256=:DldRwCblQ7Loqy6wYJnaoR0V30d3j3eH+qtFzfEv46g=:, blake2b-512=:eGoCt0IBWQPGxv2FJVLSKS8UdA4VhHYYqG4hf3H1QZ0l4QMa/uWFMTiWRESTTrBLkDpoWxRIt1XVb3Aa/pvizg==:, sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:, sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==:, sha-512/256=:xnK40e9W7SireMNiLFEUBputOte4+XN0mNDAHs7wlno=:, sha3-256=:p//G+L8e12ZRwUdWoGHWYvWA/03kO0n6gtgKS4D4Q0o=:, sha3-512=:pp9zzKI6msXItWfcGFp1bpfJghZP4lhZ4NHcwUdcgKYVshI68fX5TBHj6UAsOsVY9QAZnZW20+MBdYWGKB3NJg==:`,

		// Edge cases - empty/whitespace
		``,
		` `,
		`  `,
		`	`,
		"\n",
		"\r\n",

		// Edge cases - malformed Dictionary syntax
		`sha-256`,      // Missing =: :
		`sha-256=`,     // Missing byte sequence
		`sha-256=:`,    // Missing closing :
		`sha-256:abc:`, // Missing = before :
		`=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`,         // Missing algorithm name
		`:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`,          // Missing algorithm and =
		`sha-256==:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`, // Double =
		`sha-256=::uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`, // Double :
		`sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=::`, // Double closing :

		// Edge cases - invalid base64
		`sha-256=:!!!invalid!!!:`,
		`sha-256=:not-base64:`,
		`sha-256=:ZGF0YQ:`, // Valid base64 but wrong length
		`sha-256=:AAAA:`,   // Too short
		`sha-256=:=:`,      // Just padding
		`sha-256=: :`,      // Just space
		`sha-256=:	:`,      // Tab

		// Edge cases - wrong digest length
		`sha-256=:AAAA:`,                                         // 3 bytes, need 32
		`sha-256=:AAAAAAAAAAAAAAAAAAAAAA==:`,                     // Wrong length
		`sha-512=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`, // 32 bytes, need 64

		// Edge cases - deprecated algorithms (must be rejected)
		`md5=:AAAAAAAAAAAAAAAAAAAAAA==:`,
		`sha-1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAA:`,
		`sha=:AAAAAAAAAAAAAAAAAAAAAAAAAAAA:`,
		`adler32=:AAAA:`,
		`crc32c=:AAAA:`,
		`unixsum=:AA==:`,
		`unixcksum=:AA==:`,

		// Edge cases - case sensitivity
		`SHA-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`, // Wrong case
		`Sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`,
		`SHA256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`, // No hyphen

		// Edge cases - unknown algorithms
		`unknown=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:`,
		`custom-algo=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:`,
		`sha-256-v2=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`,
		`sha256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`, // Missing hyphen

		// Edge cases - special characters in algorithm names
		`sha-256!@#=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`,
		`sha 256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`,   // Space
		`sha\n256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`,  // Newline
		`"sha-256"=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`, // Quoted

		// Edge cases - non-Item values (should be rejected)
		`sha-256=1`,        // Integer instead of byte sequence
		`sha-256="string"`, // String instead of byte sequence
		`sha-256=?1`,       // Boolean instead of byte sequence
		`sha-256=token`,    // Token instead of byte sequence
		`sha-256=(1 2 3)`,  // Inner list instead of byte sequence

		// Edge cases - multiple commas/separators
		`sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:,,sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==:`,
		`sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:, ,sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==:`,

		// Edge cases - trailing/leading separators
		`,sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`,
		`sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:,`,
		`, sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=: ,`,

		// Edge cases - parameters (should parse but may be ignored)
		`sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:;param=value`,
		`sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:;a=1;b=2`,

		// Edge cases - duplicate algorithms
		`sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:, sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`,

		// Edge cases - very long valid base64
		`sha-512=:` + strings.Repeat("A", 88) + `=:`, // 64 bytes base64-encoded

		// Edge cases - extremely long headers (DoS potential)
		`sha-256=:` + strings.Repeat("A", 1000) + `=:`,
		`sha-256=:` + strings.Repeat("A", 10000) + `=:`,

		// Edge cases - invalid UTF-8 sequences (will be added as raw bytes in f.Fuzz)
		// Cannot include raw bytes in string literals here

		// Edge cases - null bytes
		"sha-256=:\x00\x00\x00\x00:",

		// Edge cases - control characters
		"sha-256=:\x01\x02\x03\x04:",
		"sha-256=:\r\n:",
		"sha-256=:\t:",

		// Edge cases - Unicode in algorithm names
		`sha-256😀=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`,
		`café-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`,

		// Edge cases - mixed valid and invalid algorithms
		`sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:, md5=:AAAAAAAAAAAAAAAAAAAAAA==:`,
		`unknown=:AAAA:, sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`,
	}

	// Add all seeds to the corpus
	for _, seed := range seeds {
		f.Add(seed)
	}

	// Fuzz target
	f.Fuzz(func(t *testing.T, input string) {
		// The parser must never panic or crash, regardless of input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ParseContentDigest panicked on input %q: %v", input, r)
			}
		}()

		// Parse the input
		result, err := ParseContentDigest(input)

		// If parsing succeeded, validate the result
		if err == nil {
			// Result must not be nil
			if result == nil {
				t.Errorf("ParseContentDigest returned nil result without error for input: %q", input)
				return
			}

			// Result must not be empty (at least one algorithm)
			if len(result) == 0 {
				t.Errorf("ParseContentDigest returned empty result without error for input: %q", input)
				return
			}

			// All algorithms in result must be supported
			for alg, digest := range result {
				if !isAlgorithmSupported(alg) {
					t.Errorf("ParseContentDigest returned unsupported algorithm %q for input: %q", alg, input)
				}

				// Digest length must match expected length
				expectedLen := getExpectedDigestLength(alg)
				if expectedLen > 0 && len(digest) != expectedLen {
					t.Errorf("ParseContentDigest returned digest of length %d for algorithm %q (expected %d) for input: %q",
						len(digest), alg, expectedLen, input)
				}

				// Digest must not be nil
				if digest == nil {
					t.Errorf("ParseContentDigest returned nil digest for algorithm %q for input: %q", alg, input)
				}
			}
		}

		// If parsing failed, error must not be nil
		if err != nil && result != nil {
			t.Errorf("ParseContentDigest returned both error and non-nil result for input: %q, error: %v", input, err)
		}

		// Error messages should be descriptive (contain context)
		if err != nil {
			errMsg := err.Error()
			if errMsg == "" {
				t.Errorf("ParseContentDigest returned empty error message for input: %q", input)
			}
			// Error should mention what went wrong (basic sanity check)
			if !strings.Contains(errMsg, "algorithm") &&
				!strings.Contains(errMsg, "parse") &&
				!strings.Contains(errMsg, "header") &&
				!strings.Contains(errMsg, "digest") &&
				!strings.Contains(errMsg, "length") &&
				!strings.Contains(errMsg, "empty") &&
				!strings.Contains(errMsg, "byte sequence") &&
				!strings.Contains(errMsg, "unsupported") {
				// This is just a warning - we still want descriptive errors
				t.Logf("Warning: Error message may not be descriptive enough: %q for input: %q", errMsg, input)
			}
		}
	})
}

// FuzzParseContentDigest_ValidOnly tests the parser with inputs that should parse successfully.
// This helps ensure valid inputs continue to work as the parser evolves.
func FuzzParseContentDigest_ValidOnly(f *testing.F) {
	// Seed with only valid headers
	seeds := []struct {
		header   string
		algCount int // Expected number of algorithms
	}{
		{`sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:`, 1},
		{`sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==:`, 1},
		{`sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:, sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==:`, 2},
		{`blake2b-256=:DldRwCblQ7Loqy6wYJnaoR0V30d3j3eH+qtFzfEv46g=:, blake2b-512=:eGoCt0IBWQPGxv2FJVLSKS8UdA4VhHYYqG4hf3H1QZ0l4QMa/uWFMTiWRESTTrBLkDpoWxRIt1XVb3Aa/pvizg==:, sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:, sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==:, sha-512/256=:xnK40e9W7SireMNiLFEUBputOte4+XN0mNDAHs7wlno=:, sha3-256=:p//G+L8e12ZRwUdWoGHWYvWA/03kO0n6gtgKS4D4Q0o=:, sha3-512=:pp9zzKI6msXItWfcGFp1bpfJghZP4lhZ4NHcwUdcgKYVshI68fX5TBHj6UAsOsVY9QAZnZW20+MBdYWGKB3NJg==:`, 7},
	}

	for _, seed := range seeds {
		f.Add(seed.header, seed.algCount)
	}

	f.Fuzz(func(t *testing.T, header string, expectedCount int) {
		// Skip if expectedCount is unreasonable
		if expectedCount < 0 || expectedCount > 100 {
			t.Skip("Unreasonable expected count")
		}

		result, err := ParseContentDigest(header)

		// For valid-only fuzzing, we're more interested in crashes than correctness
		// But we can still do basic validation
		if err == nil && result != nil {
			// If it parsed successfully, verify basic invariants
			if len(result) == 0 {
				t.Errorf("ParseContentDigest returned empty result for header: %q", header)
			}

			for alg, digest := range result {
				if !isAlgorithmSupported(alg) {
					t.Errorf("Unsupported algorithm %q in result", alg)
				}
				if digest == nil {
					t.Errorf("Nil digest for algorithm %q", alg)
				}
			}
		}
	})
}
