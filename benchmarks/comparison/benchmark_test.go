package comparison

import (
	"context"
	"crypto"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	// IgorPavlenko
	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/digest"
	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/httpsig"

	// yaronf/httpsign
	yaronf "github.com/yaronf/httpsign"

	// remitly-oss/httpsig-go
	remitly "github.com/remitly-oss/httpsig-go"

	// common-fate/httpsig
	"github.com/common-fate/httpsig/alg_ecdsa"
	"github.com/common-fate/httpsig/alg_hmac"
	"github.com/common-fate/httpsig/alg_rsa"
	"github.com/common-fate/httpsig/signature"
	"github.com/common-fate/httpsig/signer"
	"github.com/common-fate/httpsig/sigparams"
	"github.com/common-fate/httpsig/sigset"
	"github.com/common-fate/httpsig/verifier"
)

// =============================================================================
// RSA-PSS-SHA512 Sign Benchmarks
// =============================================================================

func BenchmarkSign_RSAPSS_IgorPavlenko(b *testing.B) {
	fbSigner, err := httpsig.NewSigner(httpsig.SignerOptions{
		Algorithm:  "rsa-pss-sha512",
		Key:        testRSAPrivKey,
		KeyID:      "test-key-rsa",
		Components: testComponents,
		Created:    time.Now(),
	})
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		_, _ = fbSigner.SignRequest(req)
	}
}

func BenchmarkSign_RSAPSS_Yaronf(b *testing.B) {
	fields := yaronf.Headers("@method", "@target-uri", "content-type")
	config := yaronf.NewSignConfig().SetKeyID("test-key-rsa").SignAlg(false)
	signerY, err := yaronf.NewRSAPSSSigner(*testRSAPrivKey, config, fields)
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		_, _, _ = yaronf.SignRequest("sig1", *signerY, req)
	}
}

func BenchmarkSign_RSAPSS_Remitly(b *testing.B) {
	profile := remitly.SigningProfile{
		Algorithm: remitly.Algo_RSA_PSS_SHA512,
		Fields:    remitly.Fields("@method", "@target-uri", "content-type"),
		Metadata:  []remitly.Metadata{remitly.MetaKeyID, remitly.MetaCreated},
		Label:     "sig1",
	}
	sigKey := remitly.SigningKey{Key: testRSAPrivKey, MetaKeyID: "test-key-rsa"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		_ = remitly.Sign(req, profile, sigKey)
	}
}

func BenchmarkSign_RSAPSS_CommonFate(b *testing.B) {
	sigAlg := alg_rsa.NewRSAPSS512Signer(testRSAPrivKey)
	transport := &signer.Transport{
		KeyID:             "test-key-rsa",
		Tag:               "benchmark",
		Alg:               sigAlg,
		CoveredComponents: []string{"@method", "@target-uri", "content-type"},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		msg, _ := transport.Sign(req)
		set := &sigset.Set{Messages: make(map[string]*signature.Message)}
		set.Add(msg)
		_ = set.Include(req)
	}
}

// =============================================================================
// RSA-PSS-SHA512 Verify Benchmarks
// =============================================================================

func BenchmarkVerify_RSAPSS_IgorPavlenko(b *testing.B) {
	fbSigner, err := httpsig.NewSigner(httpsig.SignerOptions{
		Algorithm:  "rsa-pss-sha512",
		Key:        testRSAPrivKey,
		KeyID:      "test-key-rsa",
		Components: testComponents,
		Created:    time.Now(),
	})
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	req := createTestRequest()
	if _, err := fbSigner.SignRequest(req); err != nil {
		b.Fatalf("failed to sign request: %v", err)
	}

	fbVerifier, err := httpsig.NewVerifier(httpsig.VerifyOptions{
		Key:              testRSAPubKey,
		Algorithm:        "rsa-pss-sha512",
		ParamsValidation: benchmarkValidationOptions(),
	})
	if err != nil {
		b.Fatalf("failed to create verifier: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = fbVerifier.VerifyRequest(req)
	}
}

func BenchmarkVerify_RSAPSS_Yaronf(b *testing.B) {
	fields := yaronf.Headers("@method", "@target-uri", "content-type")
	signConfig := yaronf.NewSignConfig().SetKeyID("test-key-rsa").SignAlg(false)
	verifyConfig := yaronf.NewVerifyConfig().
		SetKeyID("test-key-rsa").
		SetVerifyCreated(true).
		SetNotOlderThan(benchmarkCreatedMaxAge).
		SetNotNewerThan(benchmarkCreatedFutureSkew)
	signerY, _ := yaronf.NewRSAPSSSigner(*testRSAPrivKey, signConfig, fields)
	verifierY, _ := yaronf.NewRSAPSSVerifier(*testRSAPubKey, verifyConfig, fields)

	req := createTestRequest()
	sigInput, sig, _ := yaronf.SignRequest("sig1", *signerY, req)
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sig)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = yaronf.VerifyRequest("sig1", *verifierY, req)
	}
}

func BenchmarkVerify_RSAPSS_Remitly(b *testing.B) {
	profile := remitly.SigningProfile{
		Algorithm: remitly.Algo_RSA_PSS_SHA512,
		Fields:    remitly.Fields("@method", "@target-uri", "content-type"),
		Metadata:  []remitly.Metadata{remitly.MetaKeyID, remitly.MetaCreated},
		Label:     "sig1",
	}
	sigKey := remitly.SigningKey{Key: testRSAPrivKey, MetaKeyID: "test-key-rsa"}

	req := createTestRequest()
	_ = remitly.Sign(req, profile, sigKey)

	verifyProfile := remitly.VerifyProfile{
		SignatureLabel:       "sig1",
		AllowedAlgorithms:    []remitly.Algorithm{remitly.Algo_RSA_PSS_SHA512},
		RequiredMetadata:     []remitly.Metadata{remitly.MetaCreated},
		CreatedValidDuration: benchmarkCreatedMaxAge,
	}
	kf := &remitlyStaticKeyFetcher{keyID: "test-key-rsa", algo: remitly.Algo_RSA_PSS_SHA512, pubKey: testRSAPubKey}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = remitly.Verify(req, kf, verifyProfile)
	}
}

func BenchmarkVerify_RSAPSS_CommonFate(b *testing.B) {
	sigAlg := alg_rsa.NewRSAPSS512Signer(testRSAPrivKey)
	transport := &signer.Transport{
		KeyID:             "test-key-rsa",
		Tag:               "benchmark",
		Alg:               sigAlg,
		CoveredComponents: []string{"@method", "@target-uri", "content-type"},
	}

	req := createTestRequest()
	msg, _ := transport.Sign(req)
	set := &sigset.Set{Messages: make(map[string]*signature.Message)}
	set.Add(msg)
	_ = set.Include(req)

	keyDir := &commonFateRSAKeyDir{verifier: alg_rsa.NewRSAPSS512Verifier(testRSAPubKey)}
	v := verifier.Verifier{
		NonceStorage: &noopNonceStorage{},
		KeyDirectory: keyDir,
		Tag:          "benchmark",
		Scheme:       "https",
		Authority:    "example.com",
		Validation: sigparams.ValidateOpts{
			BeforeDuration: benchmarkCreatedMaxAge,
			AfterDuration:  benchmarkCreatedFutureSkew,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		_, _, _ = v.Parse(w, req, time.Now())
	}
}

// =============================================================================
// ECDSA-P256-SHA256 Sign Benchmarks
// =============================================================================

func BenchmarkSign_ECDSA_IgorPavlenko(b *testing.B) {
	fbSigner, err := httpsig.NewSigner(httpsig.SignerOptions{
		Algorithm:  "ecdsa-p256-sha256",
		Key:        testECPrivKey,
		KeyID:      "test-key-ecdsa",
		Components: testComponents,
		Created:    time.Now(),
	})
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		_, _ = fbSigner.SignRequest(req)
	}
}

func BenchmarkSign_ECDSA_Yaronf(b *testing.B) {
	fields := yaronf.Headers("@method", "@target-uri", "content-type")
	config := yaronf.NewSignConfig().SetKeyID("test-key-ecdsa").SignAlg(false)
	signerY, err := yaronf.NewP256Signer(*testECPrivKey, config, fields)
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		_, _, _ = yaronf.SignRequest("sig1", *signerY, req)
	}
}

func BenchmarkSign_ECDSA_Remitly(b *testing.B) {
	profile := remitly.SigningProfile{
		Algorithm: remitly.Algo_ECDSA_P256_SHA256,
		Fields:    remitly.Fields("@method", "@target-uri", "content-type"),
		Metadata:  []remitly.Metadata{remitly.MetaKeyID, remitly.MetaCreated},
		Label:     "sig1",
	}
	sigKey := remitly.SigningKey{Key: testECPrivKey, MetaKeyID: "test-key-ecdsa"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		_ = remitly.Sign(req, profile, sigKey)
	}
}

func BenchmarkSign_ECDSA_CommonFate(b *testing.B) {
	sigAlg := alg_ecdsa.NewP256Signer(testECPrivKey)
	transport := &signer.Transport{
		KeyID:             "test-key-ecdsa",
		Tag:               "benchmark",
		Alg:               sigAlg,
		CoveredComponents: []string{"@method", "@target-uri", "content-type"},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		msg, _ := transport.Sign(req)
		set := &sigset.Set{Messages: make(map[string]*signature.Message)}
		set.Add(msg)
		_ = set.Include(req)
	}
}

// =============================================================================
// ECDSA-P256-SHA256 Verify Benchmarks
// =============================================================================

func BenchmarkVerify_ECDSA_IgorPavlenko(b *testing.B) {
	fbSigner, err := httpsig.NewSigner(httpsig.SignerOptions{
		Algorithm:  "ecdsa-p256-sha256",
		Key:        testECPrivKey,
		KeyID:      "test-key-ecdsa",
		Components: testComponents,
		Created:    time.Now(),
	})
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	req := createTestRequest()
	if _, err := fbSigner.SignRequest(req); err != nil {
		b.Fatalf("failed to sign request: %v", err)
	}

	fbVerifier, err := httpsig.NewVerifier(httpsig.VerifyOptions{
		Key:              testECPubKey,
		Algorithm:        "ecdsa-p256-sha256",
		ParamsValidation: benchmarkValidationOptions(),
	})
	if err != nil {
		b.Fatalf("failed to create verifier: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = fbVerifier.VerifyRequest(req)
	}
}

func BenchmarkVerify_ECDSA_Yaronf(b *testing.B) {
	fields := yaronf.Headers("@method", "@target-uri", "content-type")
	signConfig := yaronf.NewSignConfig().SetKeyID("test-key-ecdsa").SignAlg(false)
	verifyConfig := yaronf.NewVerifyConfig().
		SetKeyID("test-key-ecdsa").
		SetVerifyCreated(true).
		SetNotOlderThan(benchmarkCreatedMaxAge).
		SetNotNewerThan(benchmarkCreatedFutureSkew)
	signerY, _ := yaronf.NewP256Signer(*testECPrivKey, signConfig, fields)
	verifierY, _ := yaronf.NewP256Verifier(*testECPubKey, verifyConfig, fields)

	req := createTestRequest()
	sigInput, sig, _ := yaronf.SignRequest("sig1", *signerY, req)
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sig)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = yaronf.VerifyRequest("sig1", *verifierY, req)
	}
}

func BenchmarkVerify_ECDSA_Remitly(b *testing.B) {
	profile := remitly.SigningProfile{
		Algorithm: remitly.Algo_ECDSA_P256_SHA256,
		Fields:    remitly.Fields("@method", "@target-uri", "content-type"),
		Metadata:  []remitly.Metadata{remitly.MetaKeyID, remitly.MetaCreated},
		Label:     "sig1",
	}
	sigKey := remitly.SigningKey{Key: testECPrivKey, MetaKeyID: "test-key-ecdsa"}

	req := createTestRequest()
	_ = remitly.Sign(req, profile, sigKey)

	verifyProfile := remitly.VerifyProfile{
		SignatureLabel:       "sig1",
		AllowedAlgorithms:    []remitly.Algorithm{remitly.Algo_ECDSA_P256_SHA256},
		RequiredMetadata:     []remitly.Metadata{remitly.MetaCreated},
		CreatedValidDuration: benchmarkCreatedMaxAge,
	}
	kf := &remitlyStaticKeyFetcher{keyID: "test-key-ecdsa", algo: remitly.Algo_ECDSA_P256_SHA256, pubKey: testECPubKey}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = remitly.Verify(req, kf, verifyProfile)
	}
}

func BenchmarkVerify_ECDSA_CommonFate(b *testing.B) {
	sigAlg := alg_ecdsa.NewP256Signer(testECPrivKey)
	transport := &signer.Transport{
		KeyID:             "test-key-ecdsa",
		Tag:               "benchmark",
		Alg:               sigAlg,
		CoveredComponents: []string{"@method", "@target-uri", "content-type"},
	}

	req := createTestRequest()
	msg, _ := transport.Sign(req)
	set := &sigset.Set{Messages: make(map[string]*signature.Message)}
	set.Add(msg)
	_ = set.Include(req)

	keyDir := &commonFateECDSAKeyDir{verifier: alg_ecdsa.NewP256Verifier(testECPubKey)}
	v := verifier.Verifier{
		NonceStorage: &noopNonceStorage{},
		KeyDirectory: keyDir,
		Tag:          "benchmark",
		Scheme:       "https",
		Authority:    "example.com",
		Validation: sigparams.ValidateOpts{
			BeforeDuration: benchmarkCreatedMaxAge,
			AfterDuration:  benchmarkCreatedFutureSkew,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		_, _, _ = v.Parse(w, req, time.Now())
	}
}

// =============================================================================
// HMAC-SHA256 Sign Benchmarks
// =============================================================================

func BenchmarkSign_HMAC_IgorPavlenko(b *testing.B) {
	fbSigner, err := httpsig.NewSigner(httpsig.SignerOptions{
		Algorithm:  "hmac-sha256",
		Key:        testHMACKey,
		KeyID:      "test-key-hmac",
		Components: testComponents,
		Created:    time.Now(),
	})
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		_, _ = fbSigner.SignRequest(req)
	}
}

func BenchmarkSign_HMAC_Yaronf(b *testing.B) {
	fields := yaronf.Headers("@method", "@target-uri", "content-type")
	config := yaronf.NewSignConfig().SetKeyID("test-key-hmac").SignAlg(false)
	signerY, err := yaronf.NewHMACSHA256Signer(testHMACKey, config, fields)
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		_, _, _ = yaronf.SignRequest("sig1", *signerY, req)
	}
}

func BenchmarkSign_HMAC_Remitly(b *testing.B) {
	profile := remitly.SigningProfile{
		Algorithm: remitly.Algo_HMAC_SHA256,
		Fields:    remitly.Fields("@method", "@target-uri", "content-type"),
		Metadata:  []remitly.Metadata{remitly.MetaKeyID, remitly.MetaCreated},
		Label:     "sig1",
	}
	sigKey := remitly.SigningKey{Secret: testHMACKey, MetaKeyID: "test-key-hmac"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		_ = remitly.Sign(req, profile, sigKey)
	}
}

func BenchmarkSign_HMAC_CommonFate(b *testing.B) {
	sigAlg := alg_hmac.NewHMAC(testHMACKey)
	transport := &signer.Transport{
		KeyID:             "test-key-hmac",
		Tag:               "benchmark",
		Alg:               sigAlg,
		CoveredComponents: []string{"@method", "@target-uri", "content-type"},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := createTestRequest()
		msg, _ := transport.Sign(req)
		set := &sigset.Set{Messages: make(map[string]*signature.Message)}
		set.Add(msg)
		_ = set.Include(req)
	}
}

// =============================================================================
// HMAC-SHA256 Verify Benchmarks
// =============================================================================

func BenchmarkVerify_HMAC_IgorPavlenko(b *testing.B) {
	fbSigner, err := httpsig.NewSigner(httpsig.SignerOptions{
		Algorithm:  "hmac-sha256",
		Key:        testHMACKey,
		KeyID:      "test-key-hmac",
		Components: testComponents,
		Created:    time.Now(),
	})
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	req := createTestRequest()
	if _, err := fbSigner.SignRequest(req); err != nil {
		b.Fatalf("failed to sign request: %v", err)
	}

	fbVerifier, err := httpsig.NewVerifier(httpsig.VerifyOptions{
		Key:              testHMACKey,
		Algorithm:        "hmac-sha256",
		ParamsValidation: benchmarkValidationOptions(),
	})
	if err != nil {
		b.Fatalf("failed to create verifier: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = fbVerifier.VerifyRequest(req)
	}
}

func BenchmarkVerify_HMAC_Yaronf(b *testing.B) {
	fields := yaronf.Headers("@method", "@target-uri", "content-type")
	signConfig := yaronf.NewSignConfig().SetKeyID("test-key-hmac").SignAlg(false)
	verifyConfig := yaronf.NewVerifyConfig().
		SetKeyID("test-key-hmac").
		SetVerifyCreated(true).
		SetNotOlderThan(benchmarkCreatedMaxAge).
		SetNotNewerThan(benchmarkCreatedFutureSkew)
	signerY, _ := yaronf.NewHMACSHA256Signer(testHMACKey, signConfig, fields)
	verifierY, _ := yaronf.NewHMACSHA256Verifier(testHMACKey, verifyConfig, fields)

	req := createTestRequest()
	sigInput, sig, _ := yaronf.SignRequest("sig1", *signerY, req)
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sig)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = yaronf.VerifyRequest("sig1", *verifierY, req)
	}
}

func BenchmarkVerify_HMAC_Remitly(b *testing.B) {
	profile := remitly.SigningProfile{
		Algorithm: remitly.Algo_HMAC_SHA256,
		Fields:    remitly.Fields("@method", "@target-uri", "content-type"),
		Metadata:  []remitly.Metadata{remitly.MetaKeyID, remitly.MetaCreated},
		Label:     "sig1",
	}
	sigKey := remitly.SigningKey{Secret: testHMACKey, MetaKeyID: "test-key-hmac"}

	req := createTestRequest()
	_ = remitly.Sign(req, profile, sigKey)

	verifyProfile := remitly.VerifyProfile{
		SignatureLabel:       "sig1",
		AllowedAlgorithms:    []remitly.Algorithm{remitly.Algo_HMAC_SHA256},
		RequiredMetadata:     []remitly.Metadata{remitly.MetaCreated},
		CreatedValidDuration: benchmarkCreatedMaxAge,
	}
	kf := &remitlyStaticKeyFetcher{keyID: "test-key-hmac", algo: remitly.Algo_HMAC_SHA256, secret: testHMACKey}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = remitly.Verify(req, kf, verifyProfile)
	}
}

func BenchmarkVerify_HMAC_CommonFate(b *testing.B) {
	sigAlg := alg_hmac.NewHMAC(testHMACKey)
	transport := &signer.Transport{
		KeyID:             "test-key-hmac",
		Tag:               "benchmark",
		Alg:               sigAlg,
		CoveredComponents: []string{"@method", "@target-uri", "content-type"},
	}

	req := createTestRequest()
	msg, _ := transport.Sign(req)
	set := &sigset.Set{Messages: make(map[string]*signature.Message)}
	set.Add(msg)
	_ = set.Include(req)

	keyDir := alg_hmac.NewSingleHMACKeyDirectory(alg_hmac.NewHMAC(testHMACKey))
	v := verifier.Verifier{
		NonceStorage: &noopNonceStorage{},
		KeyDirectory: keyDir,
		Tag:          "benchmark",
		Scheme:       "https",
		Authority:    "example.com",
		Validation: sigparams.ValidateOpts{
			BeforeDuration: benchmarkCreatedMaxAge,
			AfterDuration:  benchmarkCreatedFutureSkew,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		_, _, _ = v.Parse(w, req, time.Now())
	}
}

// =============================================================================
// HMAC-SHA256 Sign + Content-Digest (10MB Body) Benchmarks
// =============================================================================

func BenchmarkSign_HMAC_ContentDigest_10MB_IgorPavlenko(b *testing.B) {
	fbSigner, err := httpsig.NewSigner(httpsig.SignerOptions{
		Algorithm:  "hmac-sha256",
		Key:        testHMACKey,
		KeyID:      "test-key-hmac",
		Components: testDigestComponents,
	})
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	buf := make([]byte, benchmarkLargeBodyChunk)
	b.SetBytes(benchmarkLargeBodySize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := createLargeRequest()

		h, _ := digest.NewDigester(digest.AlgorithmSHA256)
		_, _ = io.CopyBuffer(h, req.Body, buf)
		_ = req.Body.Close()
		req.Body = newLargeBody()

		header, _ := digest.FormatContentDigest(map[string][]byte{
			digest.AlgorithmSHA256: h.Sum(nil),
		})
		req.Header.Set("Content-Digest", header)

		_, _ = fbSigner.SignRequest(req)
	}
}

func BenchmarkSign_HMAC_ContentDigest_10MB_Yaronf(b *testing.B) {
	fields := yaronf.Headers("@method", "@target-uri", "content-type", "content-length", "content-digest")
	config := yaronf.NewSignConfig().SetKeyID("test-key-hmac").SignAlg(false)
	signerY, err := yaronf.NewHMACSHA256Signer(testHMACKey, config, fields)
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	b.SetBytes(benchmarkLargeBodySize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := createLargeRequest()
		digestHeader, _ := yaronf.GenerateContentDigestHeader(&req.Body, []string{yaronf.DigestSha256})
		req.Header.Set("Content-Digest", digestHeader)
		_, _, _ = yaronf.SignRequest("sig1", *signerY, req)
	}
}

func BenchmarkSign_HMAC_ContentDigest_10MB_Remitly(b *testing.B) {
	profile := remitly.SigningProfile{
		Algorithm: remitly.Algo_HMAC_SHA256,
		Digest:    remitly.DigestSHA256,
		Fields:    remitly.Fields("@method", "@target-uri", "content-type", "content-length", "content-digest"),
		Metadata:  []remitly.Metadata{remitly.MetaKeyID, remitly.MetaCreated},
		Label:     "sig1",
	}
	sigKey := remitly.SigningKey{Secret: testHMACKey, MetaKeyID: "test-key-hmac"}

	b.SetBytes(benchmarkLargeBodySize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := createLargeRequest()
		_ = remitly.Sign(req, profile, sigKey)
	}
}

func BenchmarkSign_HMAC_ContentDigest_10MB_CommonFate(b *testing.B) {
	sigAlg := alg_hmac.NewHMAC(testHMACKey)
	transport := &signer.Transport{
		KeyID:             "test-key-hmac",
		Tag:               "benchmark",
		Alg:               sigAlg,
		CoveredComponents: []string{"@method", "@target-uri", "content-type", "content-length", "content-digest"},
	}

	b.SetBytes(benchmarkLargeBodySize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := createLargeRequest()
		msg, _ := transport.Sign(req)
		set := &sigset.Set{Messages: make(map[string]*signature.Message)}
		set.Add(msg)
		_ = set.Include(req)
	}
}

// =============================================================================
// Helper types for library adapters
// =============================================================================

type remitlyStaticKeyFetcher struct {
	keyID  string
	algo   remitly.Algorithm
	pubKey crypto.PublicKey
	secret []byte
}

func (f *remitlyStaticKeyFetcher) FetchByKeyID(_ context.Context, _ http.Header, _ string) (remitly.KeySpecer, error) {
	if f.secret != nil {
		return remitly.KeySpec{KeyID: f.keyID, Algo: f.algo, Secret: f.secret}, nil
	}
	return remitly.KeySpec{KeyID: f.keyID, Algo: f.algo, PubKey: f.pubKey}, nil
}

func (f *remitlyStaticKeyFetcher) Fetch(ctx context.Context, rh http.Header, _ remitly.MetadataProvider) (remitly.KeySpecer, error) {
	return f.FetchByKeyID(ctx, rh, f.keyID)
}

type commonFateRSAKeyDir struct {
	verifier *alg_rsa.RSAPSS512
}

func (d *commonFateRSAKeyDir) GetKey(_ context.Context, _ string, _ string) (verifier.Algorithm, error) {
	return d.verifier, nil
}

type commonFateECDSAKeyDir struct {
	verifier *alg_ecdsa.P256
}

func (d *commonFateECDSAKeyDir) GetKey(_ context.Context, _ string, _ string) (verifier.Algorithm, error) {
	return d.verifier, nil
}

type noopNonceStorage struct{}

func (n *noopNonceStorage) Seen(_ context.Context, _ string) (bool, error) {
	return false, nil
}

// =============================================================================
// Grouped Comparison Benchmarks
// =============================================================================

func BenchmarkSign_AllLibraries_RSAPSS(b *testing.B) {
	b.Run("IgorPavlenko", BenchmarkSign_RSAPSS_IgorPavlenko)
	b.Run("Yaronf", BenchmarkSign_RSAPSS_Yaronf)
	b.Run("Remitly", BenchmarkSign_RSAPSS_Remitly)
	b.Run("CommonFate", BenchmarkSign_RSAPSS_CommonFate)
}

func BenchmarkSign_AllLibraries_ECDSA(b *testing.B) {
	b.Run("IgorPavlenko", BenchmarkSign_ECDSA_IgorPavlenko)
	b.Run("Yaronf", BenchmarkSign_ECDSA_Yaronf)
	b.Run("Remitly", BenchmarkSign_ECDSA_Remitly)
	b.Run("CommonFate", BenchmarkSign_ECDSA_CommonFate)
}

func BenchmarkSign_AllLibraries_HMAC(b *testing.B) {
	b.Run("IgorPavlenko", BenchmarkSign_HMAC_IgorPavlenko)
	b.Run("Yaronf", BenchmarkSign_HMAC_Yaronf)
	b.Run("Remitly", BenchmarkSign_HMAC_Remitly)
	b.Run("CommonFate", BenchmarkSign_HMAC_CommonFate)
}

func BenchmarkVerify_AllLibraries_RSAPSS(b *testing.B) {
	b.Run("IgorPavlenko", BenchmarkVerify_RSAPSS_IgorPavlenko)
	b.Run("Yaronf", BenchmarkVerify_RSAPSS_Yaronf)
	b.Run("Remitly", BenchmarkVerify_RSAPSS_Remitly)
	b.Run("CommonFate", BenchmarkVerify_RSAPSS_CommonFate)
}

func BenchmarkVerify_AllLibraries_ECDSA(b *testing.B) {
	b.Run("IgorPavlenko", BenchmarkVerify_ECDSA_IgorPavlenko)
	b.Run("Yaronf", BenchmarkVerify_ECDSA_Yaronf)
	b.Run("Remitly", BenchmarkVerify_ECDSA_Remitly)
	b.Run("CommonFate", BenchmarkVerify_ECDSA_CommonFate)
}

func BenchmarkVerify_AllLibraries_HMAC(b *testing.B) {
	b.Run("IgorPavlenko", BenchmarkVerify_HMAC_IgorPavlenko)
	b.Run("Yaronf", BenchmarkVerify_HMAC_Yaronf)
	b.Run("Remitly", BenchmarkVerify_HMAC_Remitly)
	b.Run("CommonFate", BenchmarkVerify_HMAC_CommonFate)
}

func BenchmarkSign_AllLibraries_HMAC_ContentDigest_10MB(b *testing.B) {
	b.Run("IgorPavlenko", BenchmarkSign_HMAC_ContentDigest_10MB_IgorPavlenko)
	b.Run("Yaronf", BenchmarkSign_HMAC_ContentDigest_10MB_Yaronf)
	b.Run("Remitly", BenchmarkSign_HMAC_ContentDigest_10MB_Remitly)
	b.Run("CommonFate", BenchmarkSign_HMAC_ContentDigest_10MB_CommonFate)
}

// =============================================================================
// Sanity Tests
// =============================================================================

func TestSign_IgorPavlenko(t *testing.T) {
	fbSigner, err := httpsig.NewSigner(httpsig.SignerOptions{
		Algorithm:  "rsa-pss-sha512",
		Key:        testRSAPrivKey,
		KeyID:      "test-key-rsa",
		Components: testComponents,
		Created:    time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	req := createTestRequest()
	headers, err := fbSigner.SignRequest(req)
	if err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	fbVerifier, err := httpsig.NewVerifier(httpsig.VerifyOptions{
		Key:              testRSAPubKey,
		Algorithm:        "rsa-pss-sha512",
		ParamsValidation: benchmarkValidationOptions(),
	})
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	if _, err := fbVerifier.VerifyRequest(req); err != nil {
		t.Fatalf("failed to verify: %v", err)
	}

	t.Logf("Signature-Input: %s", headers.SignatureInput)
	t.Logf("Signature: %s", headers.Signature)
}
