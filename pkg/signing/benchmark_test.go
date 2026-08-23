package signing

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// Benchmark key fixtures - generated once per test run
var (
	benchRSAPrivKey    *rsa.PrivateKey
	benchRSAPubKey     *rsa.PublicKey
	benchECP256PrivKey *ecdsa.PrivateKey
	benchECP256PubKey  *ecdsa.PublicKey
	benchECP384PrivKey *ecdsa.PrivateKey
	benchECP384PubKey  *ecdsa.PublicKey
	benchEd25519Priv   ed25519.PrivateKey
	benchEd25519Pub    ed25519.PublicKey
	benchHMACKey       []byte

	// Pre-generated signatures for verify benchmarks
	benchSigRSAPSS  []byte
	benchSigRSAv15  []byte
	benchSigECP256  []byte
	benchSigECP384  []byte
	benchSigEd25519 []byte
	benchSigHMAC    []byte

	// Signature base samples
	benchSigBase256B []byte
	benchSigBase1KB  []byte
	benchSigBase10KB []byte
)

func init() {
	// Generate RSA 2048-bit key
	benchRSAPrivKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	benchRSAPubKey = &benchRSAPrivKey.PublicKey

	// Generate ECDSA P-256 key
	benchECP256PrivKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	benchECP256PubKey = &benchECP256PrivKey.PublicKey

	// Generate ECDSA P-384 key
	benchECP384PrivKey, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	benchECP384PubKey = &benchECP384PrivKey.PublicKey

	// Generate Ed25519 key
	benchEd25519Pub, benchEd25519Priv, _ = ed25519.GenerateKey(rand.Reader)

	// Generate HMAC key (32 bytes)
	benchHMACKey = make([]byte, 32)
	_, _ = rand.Read(benchHMACKey)

	// Generate signature base samples
	benchSigBase256B = make([]byte, 256)
	benchSigBase1KB = make([]byte, 1024)
	benchSigBase10KB = make([]byte, 10*1024)
	for i := range benchSigBase256B {
		benchSigBase256B[i] = byte('a' + (i % 26))
	}
	for i := range benchSigBase1KB {
		benchSigBase1KB[i] = byte('a' + (i % 26))
	}
	for i := range benchSigBase10KB {
		benchSigBase10KB[i] = byte('a' + (i % 26))
	}

	// Pre-generate signatures for verify benchmarks (using 1KB base)
	algRSAPSS, _ := GetAlgorithm("rsa-pss-sha512")
	algRSAv15, _ := GetAlgorithm("rsa-v1_5-sha256")
	algECP256, _ := GetAlgorithm("ecdsa-p256-sha256")
	algECP384, _ := GetAlgorithm("ecdsa-p384-sha384")
	algEd25519, _ := GetAlgorithm("ed25519")
	algHMAC, _ := GetAlgorithm("hmac-sha256")

	benchSigRSAPSS, _ = algRSAPSS.Sign(benchSigBase1KB, benchRSAPrivKey)
	benchSigRSAv15, _ = algRSAv15.Sign(benchSigBase1KB, benchRSAPrivKey)
	benchSigECP256, _ = algECP256.Sign(benchSigBase1KB, benchECP256PrivKey)
	benchSigECP384, _ = algECP384.Sign(benchSigBase1KB, benchECP384PrivKey)
	benchSigEd25519, _ = algEd25519.Sign(benchSigBase1KB, benchEd25519Priv)
	benchSigHMAC, _ = algHMAC.Sign(benchSigBase1KB, benchHMACKey)
}

// =============================================================================
// RSA-PSS-SHA512 Benchmarks
// =============================================================================

func BenchmarkSign_RSAPSSSHA512_256B(b *testing.B) {
	alg, _ := GetAlgorithm("rsa-pss-sha512")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase256B, benchRSAPrivKey)
	}
}

func BenchmarkSign_RSAPSSSHA512_1KB(b *testing.B) {
	alg, _ := GetAlgorithm("rsa-pss-sha512")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase1KB, benchRSAPrivKey)
	}
}

func BenchmarkSign_RSAPSSSHA512_10KB(b *testing.B) {
	alg, _ := GetAlgorithm("rsa-pss-sha512")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase10KB, benchRSAPrivKey)
	}
}

func BenchmarkVerify_RSAPSSSHA512_256B(b *testing.B) {
	alg, _ := GetAlgorithm("rsa-pss-sha512")
	sig, _ := alg.Sign(benchSigBase256B, benchRSAPrivKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase256B, sig, benchRSAPubKey)
	}
}

func BenchmarkVerify_RSAPSSSHA512_1KB(b *testing.B) {
	alg, _ := GetAlgorithm("rsa-pss-sha512")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase1KB, benchSigRSAPSS, benchRSAPubKey)
	}
}

func BenchmarkVerify_RSAPSSSHA512_10KB(b *testing.B) {
	alg, _ := GetAlgorithm("rsa-pss-sha512")
	sig, _ := alg.Sign(benchSigBase10KB, benchRSAPrivKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase10KB, sig, benchRSAPubKey)
	}
}

// =============================================================================
// RSA-v1_5-SHA256 Benchmarks
// =============================================================================

func BenchmarkSign_RSAv15SHA256_256B(b *testing.B) {
	alg, _ := GetAlgorithm("rsa-v1_5-sha256")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase256B, benchRSAPrivKey)
	}
}

func BenchmarkSign_RSAv15SHA256_1KB(b *testing.B) {
	alg, _ := GetAlgorithm("rsa-v1_5-sha256")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase1KB, benchRSAPrivKey)
	}
}

func BenchmarkSign_RSAv15SHA256_10KB(b *testing.B) {
	alg, _ := GetAlgorithm("rsa-v1_5-sha256")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase10KB, benchRSAPrivKey)
	}
}

func BenchmarkVerify_RSAv15SHA256_256B(b *testing.B) {
	alg, _ := GetAlgorithm("rsa-v1_5-sha256")
	sig, _ := alg.Sign(benchSigBase256B, benchRSAPrivKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase256B, sig, benchRSAPubKey)
	}
}

func BenchmarkVerify_RSAv15SHA256_1KB(b *testing.B) {
	alg, _ := GetAlgorithm("rsa-v1_5-sha256")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase1KB, benchSigRSAv15, benchRSAPubKey)
	}
}

func BenchmarkVerify_RSAv15SHA256_10KB(b *testing.B) {
	alg, _ := GetAlgorithm("rsa-v1_5-sha256")
	sig, _ := alg.Sign(benchSigBase10KB, benchRSAPrivKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase10KB, sig, benchRSAPubKey)
	}
}

// =============================================================================
// ECDSA-P256-SHA256 Benchmarks
// =============================================================================

func BenchmarkSign_ECDSAP256_256B(b *testing.B) {
	alg, _ := GetAlgorithm("ecdsa-p256-sha256")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase256B, benchECP256PrivKey)
	}
}

func BenchmarkSign_ECDSAP256_1KB(b *testing.B) {
	alg, _ := GetAlgorithm("ecdsa-p256-sha256")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase1KB, benchECP256PrivKey)
	}
}

func BenchmarkSign_ECDSAP256_10KB(b *testing.B) {
	alg, _ := GetAlgorithm("ecdsa-p256-sha256")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase10KB, benchECP256PrivKey)
	}
}

func BenchmarkVerify_ECDSAP256_256B(b *testing.B) {
	alg, _ := GetAlgorithm("ecdsa-p256-sha256")
	sig, _ := alg.Sign(benchSigBase256B, benchECP256PrivKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase256B, sig, benchECP256PubKey)
	}
}

func BenchmarkVerify_ECDSAP256_1KB(b *testing.B) {
	alg, _ := GetAlgorithm("ecdsa-p256-sha256")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase1KB, benchSigECP256, benchECP256PubKey)
	}
}

func BenchmarkVerify_ECDSAP256_10KB(b *testing.B) {
	alg, _ := GetAlgorithm("ecdsa-p256-sha256")
	sig, _ := alg.Sign(benchSigBase10KB, benchECP256PrivKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase10KB, sig, benchECP256PubKey)
	}
}

// =============================================================================
// ECDSA-P384-SHA384 Benchmarks
// =============================================================================

func BenchmarkSign_ECDSAP384_256B(b *testing.B) {
	alg, _ := GetAlgorithm("ecdsa-p384-sha384")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase256B, benchECP384PrivKey)
	}
}

func BenchmarkSign_ECDSAP384_1KB(b *testing.B) {
	alg, _ := GetAlgorithm("ecdsa-p384-sha384")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase1KB, benchECP384PrivKey)
	}
}

func BenchmarkSign_ECDSAP384_10KB(b *testing.B) {
	alg, _ := GetAlgorithm("ecdsa-p384-sha384")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase10KB, benchECP384PrivKey)
	}
}

func BenchmarkVerify_ECDSAP384_256B(b *testing.B) {
	alg, _ := GetAlgorithm("ecdsa-p384-sha384")
	sig, _ := alg.Sign(benchSigBase256B, benchECP384PrivKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase256B, sig, benchECP384PubKey)
	}
}

func BenchmarkVerify_ECDSAP384_1KB(b *testing.B) {
	alg, _ := GetAlgorithm("ecdsa-p384-sha384")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase1KB, benchSigECP384, benchECP384PubKey)
	}
}

func BenchmarkVerify_ECDSAP384_10KB(b *testing.B) {
	alg, _ := GetAlgorithm("ecdsa-p384-sha384")
	sig, _ := alg.Sign(benchSigBase10KB, benchECP384PrivKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase10KB, sig, benchECP384PubKey)
	}
}

// =============================================================================
// Ed25519 Benchmarks
// =============================================================================

func BenchmarkSign_Ed25519_256B(b *testing.B) {
	alg, _ := GetAlgorithm("ed25519")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase256B, benchEd25519Priv)
	}
}

func BenchmarkSign_Ed25519_1KB(b *testing.B) {
	alg, _ := GetAlgorithm("ed25519")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase1KB, benchEd25519Priv)
	}
}

func BenchmarkSign_Ed25519_10KB(b *testing.B) {
	alg, _ := GetAlgorithm("ed25519")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase10KB, benchEd25519Priv)
	}
}

func BenchmarkVerify_Ed25519_256B(b *testing.B) {
	alg, _ := GetAlgorithm("ed25519")
	sig, _ := alg.Sign(benchSigBase256B, benchEd25519Priv)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase256B, sig, benchEd25519Pub)
	}
}

func BenchmarkVerify_Ed25519_1KB(b *testing.B) {
	alg, _ := GetAlgorithm("ed25519")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase1KB, benchSigEd25519, benchEd25519Pub)
	}
}

func BenchmarkVerify_Ed25519_10KB(b *testing.B) {
	alg, _ := GetAlgorithm("ed25519")
	sig, _ := alg.Sign(benchSigBase10KB, benchEd25519Priv)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase10KB, sig, benchEd25519Pub)
	}
}

// =============================================================================
// HMAC-SHA256 Benchmarks
// =============================================================================

func BenchmarkSign_HMACSHA256_256B(b *testing.B) {
	alg, _ := GetAlgorithm("hmac-sha256")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase256B, benchHMACKey)
	}
}

func BenchmarkSign_HMACSHA256_1KB(b *testing.B) {
	alg, _ := GetAlgorithm("hmac-sha256")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase1KB, benchHMACKey)
	}
}

func BenchmarkSign_HMACSHA256_10KB(b *testing.B) {
	alg, _ := GetAlgorithm("hmac-sha256")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = alg.Sign(benchSigBase10KB, benchHMACKey)
	}
}

func BenchmarkVerify_HMACSHA256_256B(b *testing.B) {
	alg, _ := GetAlgorithm("hmac-sha256")
	sig, _ := alg.Sign(benchSigBase256B, benchHMACKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase256B, sig, benchHMACKey)
	}
}

func BenchmarkVerify_HMACSHA256_1KB(b *testing.B) {
	alg, _ := GetAlgorithm("hmac-sha256")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase1KB, benchSigHMAC, benchHMACKey)
	}
}

func BenchmarkVerify_HMACSHA256_10KB(b *testing.B) {
	alg, _ := GetAlgorithm("hmac-sha256")
	sig, _ := alg.Sign(benchSigBase10KB, benchHMACKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = alg.Verify(benchSigBase10KB, sig, benchHMACKey)
	}
}

// =============================================================================
// Cross-Algorithm Comparison Benchmarks
// =============================================================================

// BenchmarkAllAlgorithms_Sign_1KB compares signing performance across all algorithms.
func BenchmarkAllAlgorithms_Sign_1KB(b *testing.B) {
	tests := []struct {
		name string
		alg  string
		key  any
	}{
		{"RSAPSSSHA512", "rsa-pss-sha512", benchRSAPrivKey},
		{"RSAv15SHA256", "rsa-v1_5-sha256", benchRSAPrivKey},
		{"ECDSAP256", "ecdsa-p256-sha256", benchECP256PrivKey},
		{"ECDSAP384", "ecdsa-p384-sha384", benchECP384PrivKey},
		{"Ed25519", "ed25519", benchEd25519Priv},
		{"HMACSHA256", "hmac-sha256", benchHMACKey},
	}

	for _, tc := range tests {
		alg, _ := GetAlgorithm(tc.alg)
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = alg.Sign(benchSigBase1KB, tc.key)
			}
		})
	}
}

// BenchmarkAllAlgorithms_Verify_1KB compares verification performance across all algorithms.
func BenchmarkAllAlgorithms_Verify_1KB(b *testing.B) {
	tests := []struct {
		name string
		alg  string
		key  any
		sig  []byte
	}{
		{"RSAPSSSHA512", "rsa-pss-sha512", benchRSAPubKey, benchSigRSAPSS},
		{"RSAv15SHA256", "rsa-v1_5-sha256", benchRSAPubKey, benchSigRSAv15},
		{"ECDSAP256", "ecdsa-p256-sha256", benchECP256PubKey, benchSigECP256},
		{"ECDSAP384", "ecdsa-p384-sha384", benchECP384PubKey, benchSigECP384},
		{"Ed25519", "ed25519", benchEd25519Pub, benchSigEd25519},
		{"HMACSHA256", "hmac-sha256", benchHMACKey, benchSigHMAC},
	}

	for _, tc := range tests {
		alg, _ := GetAlgorithm(tc.alg)
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = alg.Verify(benchSigBase1KB, tc.sig, tc.key)
			}
		})
	}
}

// BenchmarkAllAlgorithms_SignAndVerify_1KB measures complete sign+verify round-trip.
func BenchmarkAllAlgorithms_SignAndVerify_1KB(b *testing.B) {
	tests := []struct {
		name    string
		alg     string
		signKey any
		verKey  any
	}{
		{"RSAPSSSHA512", "rsa-pss-sha512", benchRSAPrivKey, benchRSAPubKey},
		{"RSAv15SHA256", "rsa-v1_5-sha256", benchRSAPrivKey, benchRSAPubKey},
		{"ECDSAP256", "ecdsa-p256-sha256", benchECP256PrivKey, benchECP256PubKey},
		{"ECDSAP384", "ecdsa-p384-sha384", benchECP384PrivKey, benchECP384PubKey},
		{"Ed25519", "ed25519", benchEd25519Priv, benchEd25519Pub},
		{"HMACSHA256", "hmac-sha256", benchHMACKey, benchHMACKey},
	}

	for _, tc := range tests {
		alg, _ := GetAlgorithm(tc.alg)
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				sig, _ := alg.Sign(benchSigBase1KB, tc.signKey)
				_ = alg.Verify(benchSigBase1KB, sig, tc.verKey)
			}
		})
	}
}

// =============================================================================
// Memory Allocation Benchmarks
// =============================================================================

// BenchmarkMemoryAllocations_Sign tracks memory allocations during signing.
func BenchmarkMemoryAllocations_Sign(b *testing.B) {
	tests := []struct {
		name string
		alg  string
		key  any
	}{
		{"RSAPSSSHA512", "rsa-pss-sha512", benchRSAPrivKey},
		{"RSAv15SHA256", "rsa-v1_5-sha256", benchRSAPrivKey},
		{"ECDSAP256", "ecdsa-p256-sha256", benchECP256PrivKey},
		{"ECDSAP384", "ecdsa-p384-sha384", benchECP384PrivKey},
		{"Ed25519", "ed25519", benchEd25519Priv},
		{"HMACSHA256", "hmac-sha256", benchHMACKey},
	}

	for _, tc := range tests {
		alg, _ := GetAlgorithm(tc.alg)
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = alg.Sign(benchSigBase1KB, tc.key)
			}
		})
	}
}

// BenchmarkMemoryAllocations_Verify tracks memory allocations during verification.
func BenchmarkMemoryAllocations_Verify(b *testing.B) {
	tests := []struct {
		name string
		alg  string
		key  any
		sig  []byte
	}{
		{"RSAPSSSHA512", "rsa-pss-sha512", benchRSAPubKey, benchSigRSAPSS},
		{"RSAv15SHA256", "rsa-v1_5-sha256", benchRSAPubKey, benchSigRSAv15},
		{"ECDSAP256", "ecdsa-p256-sha256", benchECP256PubKey, benchSigECP256},
		{"ECDSAP384", "ecdsa-p384-sha384", benchECP384PubKey, benchSigECP384},
		{"Ed25519", "ed25519", benchEd25519Pub, benchSigEd25519},
		{"HMACSHA256", "hmac-sha256", benchHMACKey, benchSigHMAC},
	}

	for _, tc := range tests {
		alg, _ := GetAlgorithm(tc.alg)
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = alg.Verify(benchSigBase1KB, tc.sig, tc.key)
			}
		})
	}
}
