package base

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/base"
	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/signing"
)

// testAssetsDir is the path to test-assets/ relative to this package.
const testAssetsDir = "."

// =============================================================================
// Helper Functions
// =============================================================================

// loadTestFile loads a file from test-assets directory.
func loadTestFile(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testAssetsDir, filename)) //nolint:gosec // test assets from known directory
	if err != nil {
		t.Fatalf("failed to load test file %s: %v", filename, err)
	}
	return data
}

// loadPrivateKey loads and parses a private key from test-assets.
func loadPrivateKey(t *testing.T, filename string) any {
	t.Helper()
	data := loadTestFile(t, filename)
	key, err := signing.ParsePrivateKey(data)
	if err != nil {
		t.Fatalf("failed to parse private key %s: %v", filename, err)
	}
	return key
}

// loadPublicKey loads and parses a public key from test-assets.
func loadPublicKey(t *testing.T, filename string) any {
	t.Helper()
	data := loadTestFile(t, filename)
	key, err := signing.ParsePublicKey(data)
	if err != nil {
		t.Fatalf("failed to parse public key %s: %v", filename, err)
	}
	return key
}

// loadSharedSecret loads the HMAC shared secret from test-assets.
func loadSharedSecret(t *testing.T) []byte {
	t.Helper()
	data := loadTestFile(t, "test-shared-secret")
	// Remove any trailing newline
	secretB64 := strings.TrimSpace(string(data))
	secret, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		t.Fatalf("failed to decode shared secret: %v", err)
	}
	return secret
}

// RFC 9421 Appendix B.2.1 - Minimal Signature
func TestRFC9421_AppendixB_2_1_MinimalSignature(t *testing.T) {
	privKey := loadPrivateKey(t, "test-key-rsa-private.pem").(*rsa.PrivateKey)
	pubKey := loadPublicKey(t, "test-key-rsa-public.pem").(*rsa.PublicKey)

	alg, err := signing.GetAlgorithm("rsa-pss-sha512")
	if err != nil {
		t.Fatalf("failed to get algorithm: %v", err)
	}

	body := strings.NewReader(`{"hello": "world"}`)
	req, _ := http.NewRequest("POST", "https://example.com/foo?param=Value&Pet=dog", body)
	req.Header.Set("Host", "example.com")
	req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "18")

	msg := base.WrapRequest(req)

	components := []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "@authority", Type: parser.ComponentDerived},
		{Name: "@path", Type: parser.ComponentDerived},
		{Name: "@query", Type: parser.ComponentDerived},
		{Name: "content-type", Type: parser.ComponentField},
	}

	created := int64(1618884473)
	keyid := "test-key-rsa-pss"
	params := parser.SignatureParams{
		Created: &created,
		KeyID:   &keyid,
	}

	signatureBase, err := base.Build(msg, components, params)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	want := `"@method": POST
"@authority": example.com
"@path": /foo
"@query": ?param=Value&Pet=dog
"content-type": application/json
"@signature-params": ("@method" "@authority" "@path" "@query" "content-type");created=1618884473;keyid="test-key-rsa-pss"`

	if signatureBase != want {
		t.Errorf("Build() signature base mismatch\nGot:\n%s\n\nWant:\n%s", signatureBase, want)
	}

	// Sign (RSA-PSS is non-deterministic, output differs each time)
	sig, err := alg.Sign([]byte(signatureBase), privKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// RSA 2048-bit key produces 256-byte signature
	if len(sig) != 256 {
		t.Errorf("expected signature length 256, got %d", len(sig))
	}

	// Verify our generated signature
	if err := alg.Verify([]byte(signatureBase), sig, pubKey); err != nil {
		t.Fatalf("failed to verify our signature: %v", err)
	}

	// Note: We cannot verify the RFC example signature because it was created with
	// test-key-rsa-pss (PKCS#8 with RSA-PSS OID) which Go stdlib doesn't support.
	// Our test proves the algorithm works correctly with the standard RSA key.

	t.Logf("B.2.1: Generated signature length: %d bytes", len(sig))
	t.Logf("B.2.1: Sign and verify successful with RSA-PSS algorithm")
}

// RFC 9421 Appendix B.2.2 - Selective Covered Components
func TestRFC9421_AppendixB_2_2_SelectiveCoverage(t *testing.T) {
	privKey := loadPrivateKey(t, "test-key-rsa-private.pem").(*rsa.PrivateKey)
	pubKey := loadPublicKey(t, "test-key-rsa-public.pem").(*rsa.PublicKey)

	alg, err := signing.GetAlgorithm("rsa-pss-sha512")
	if err != nil {
		t.Fatalf("failed to get algorithm: %v", err)
	}

	body := strings.NewReader(`{"hello": "world"}`)
	req, _ := http.NewRequest("POST", "https://example.com/foo?param=Value&Pet=dog", body)
	req.Header.Set("Host", "example.com")
	req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "18")

	msg := base.WrapRequest(req)

	components := []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "@authority", Type: parser.ComponentDerived},
		{Name: "@path", Type: parser.ComponentDerived},
		{Name: "@query", Type: parser.ComponentDerived},
		{Name: "date", Type: parser.ComponentField},
		{Name: "content-type", Type: parser.ComponentField},
		{Name: "content-length", Type: parser.ComponentField},
	}

	created := int64(1618884473)
	keyid := "test-key-rsa-pss"
	params := parser.SignatureParams{
		Created: &created,
		KeyID:   &keyid,
	}

	signatureBase, err := base.Build(msg, components, params)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	want := `"@method": POST
"@authority": example.com
"@path": /foo
"@query": ?param=Value&Pet=dog
"date": Tue, 20 Apr 2021 02:07:55 GMT
"content-type": application/json
"content-length": 18
"@signature-params": ("@method" "@authority" "@path" "@query" "date" "content-type" "content-length");created=1618884473;keyid="test-key-rsa-pss"`

	if signatureBase != want {
		t.Errorf("Build() signature base mismatch\nGot:\n%s\n\nWant:\n%s", signatureBase, want)
	}

	// Sign
	sig, err := alg.Sign([]byte(signatureBase), privKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Verify our generated signature
	if err := alg.Verify([]byte(signatureBase), sig, pubKey); err != nil {
		t.Fatalf("failed to verify our signature: %v", err)
	}

	// Note: We cannot verify the RFC example signature because it was created with
	// test-key-rsa-pss (PKCS#8 with RSA-PSS OID) which Go stdlib doesn't support.

	t.Logf("B.2.2: Generated signature length: %d bytes", len(sig))
	t.Logf("B.2.2: Sign and verify successful with RSA-PSS algorithm")
}

// RFC 9421 Appendix B.2.3 - Full Coverage Using rsa-pss-sha512
func TestRFC9421_AppendixB_2_3_FullCoverage(t *testing.T) {
	privKey := loadPrivateKey(t, "test-key-rsa-private.pem").(*rsa.PrivateKey)
	pubKey := loadPublicKey(t, "test-key-rsa-public.pem").(*rsa.PublicKey)

	alg, err := signing.GetAlgorithm("rsa-pss-sha512")
	if err != nil {
		t.Fatalf("failed to get algorithm: %v", err)
	}

	body := strings.NewReader(`{"hello": "world"}`)
	req, _ := http.NewRequest("POST", "https://example.com/foo?param=Value&Pet=dog", body)
	req.Header.Set("Host", "example.com")
	req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:")
	req.Header.Set("Content-Length", "18")

	msg := base.WrapRequest(req)

	// Full coverage: date, @method, @path, @query, @authority, content-type, content-digest, content-length
	components := []parser.ComponentIdentifier{
		{Name: "date", Type: parser.ComponentField},
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "@path", Type: parser.ComponentDerived},
		{Name: "@query", Type: parser.ComponentDerived},
		{Name: "@authority", Type: parser.ComponentDerived},
		{Name: "content-type", Type: parser.ComponentField},
		{Name: "content-digest", Type: parser.ComponentField},
		{Name: "content-length", Type: parser.ComponentField},
	}

	created := int64(1618884473)
	keyid := "test-key-rsa-pss"
	params := parser.SignatureParams{
		Created: &created,
		KeyID:   &keyid,
	}

	signatureBase, err := base.Build(msg, components, params)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	want := `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@query": ?param=Value&Pet=dog
"@authority": example.com
"content-type": application/json
"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`

	if signatureBase != want {
		t.Errorf("Build() signature base mismatch\nGot:\n%s\n\nWant:\n%s", signatureBase, want)
	}

	// Sign (RSA-PSS is non-deterministic, output differs each time)
	sig, err := alg.Sign([]byte(signatureBase), privKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// RSA 2048-bit key produces 256-byte signature
	if len(sig) != 256 {
		t.Errorf("expected signature length 256, got %d", len(sig))
	}

	// Verify our generated signature
	if err := alg.Verify([]byte(signatureBase), sig, pubKey); err != nil {
		t.Fatalf("failed to verify our signature: %v", err)
	}

	// Note: We cannot verify the RFC example signature because it was created with
	// test-key-rsa-pss (PKCS#8 with RSA-PSS OID) which Go stdlib doesn't support.
	// Our test proves the algorithm works correctly with the standard RSA key.

	t.Logf("B.2.3: Generated signature length: %d bytes", len(sig))
	t.Logf("B.2.3: Sign and verify successful with RSA-PSS algorithm (full coverage)")
}

// RFC 9421 Appendix B.2.4 - Signing a Response (with req parameter)
func TestRFC9421_AppendixB_2_4_ResponseSignature(t *testing.T) {
	privKey := loadPrivateKey(t, "test-key-ecc-p256-private.pem").(*ecdsa.PrivateKey)
	pubKey := loadPublicKey(t, "test-key-ecc-p256-public.pem").(*ecdsa.PublicKey)

	alg, err := signing.GetAlgorithm("ecdsa-p256-sha256")
	if err != nil {
		t.Fatalf("failed to get algorithm: %v", err)
	}

	// Original request
	reqBody := strings.NewReader(`{"hello": "world"}`)
	originalReq, _ := http.NewRequest("POST", "https://example.com/foo?param=Value&Pet=dog", reqBody)
	originalReq.Header.Set("Host", "example.com")
	originalReq.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	originalReq.Header.Set("Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:")
	originalReq.Header.Set("Content-Type", "application/json")
	originalReq.Header.Set("Content-Length", "18")

	// Response
	respBody := strings.NewReader(`{"message": "good dog"}`)
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Date":           []string{"Tue, 20 Apr 2021 02:07:56 GMT"},
			"Content-Type":   []string{"application/json"},
			"Content-Length": []string{"23"},
			"Content-Digest": []string{"sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:"},
		},
		Body: io.NopCloser(respBody),
	}

	msg := base.WrapResponse(resp, originalReq)

	components := []parser.ComponentIdentifier{
		{Name: "@status", Type: parser.ComponentDerived},
		{Name: "content-digest", Type: parser.ComponentField},
		{Name: "content-type", Type: parser.ComponentField},
		{
			Name: "@authority",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "req", Value: parser.Boolean{Value: true}},
			},
		},
		{
			Name: "@method",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "req", Value: parser.Boolean{Value: true}},
			},
		},
		{
			Name: "@path",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "req", Value: parser.Boolean{Value: true}},
			},
		},
		{
			Name: "content-digest",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "req", Value: parser.Boolean{Value: true}},
			},
		},
	}

	created := int64(1618884479)
	keyid := "test-key-ecc-p256"
	params := parser.SignatureParams{
		Created: &created,
		KeyID:   &keyid,
	}

	signatureBase, err := base.Build(msg, components, params)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	want := `"@status": 200
"content-digest": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:
"content-type": application/json
"@authority";req: example.com
"@method";req: POST
"@path";req: /foo
"content-digest";req: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"@signature-params": ("@status" "content-digest" "content-type" "@authority";req "@method";req "@path";req "content-digest";req);created=1618884479;keyid="test-key-ecc-p256"`

	if signatureBase != want {
		t.Errorf("Build() signature base mismatch\nGot:\n%s\n\nWant:\n%s", signatureBase, want)
	}

	// Sign
	sig, err := alg.Sign([]byte(signatureBase), privKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// RFC 9421 Section 3.3.4: fixed 64-byte r||s encoding for P-256.
	if len(sig) != 64 {
		t.Errorf("unexpected ECDSA signature length: %d, want 64", len(sig))
	}

	// Verify our generated signature
	if err := alg.Verify([]byte(signatureBase), sig, pubKey); err != nil {
		t.Fatalf("failed to verify our signature: %v", err)
	}

	t.Logf("B.2.4: Generated signature length: %d bytes (r||s)", len(sig))
}

// RFC 9421 Appendix B.2.5 - Signing a Request Using hmac-sha256
func TestRFC9421_AppendixB_2_5_HMAC(t *testing.T) {
	sharedSecret := loadSharedSecret(t)

	alg, err := signing.GetAlgorithm("hmac-sha256")
	if err != nil {
		t.Fatalf("failed to get algorithm: %v", err)
	}

	body := strings.NewReader(`{"hello": "world"}`)
	req, _ := http.NewRequest("POST", "https://example.com/foo?param=Value&Pet=dog", body)
	req.Header.Set("Host", "example.com")
	req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "18")

	msg := base.WrapRequest(req)

	components := []parser.ComponentIdentifier{
		{Name: "date", Type: parser.ComponentField},
		{Name: "@authority", Type: parser.ComponentDerived},
		{Name: "content-type", Type: parser.ComponentField},
	}

	created := int64(1618884473)
	keyid := "test-shared-secret"
	params := parser.SignatureParams{
		Created: &created,
		KeyID:   &keyid,
	}

	signatureBase, err := base.Build(msg, components, params)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	want := `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@authority": example.com
"content-type": application/json
"@signature-params": ("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`

	if signatureBase != want {
		t.Errorf("Build() signature base mismatch\nGot:\n%s\n\nWant:\n%s", signatureBase, want)
	}

	// Sign
	sig, err := alg.Sign([]byte(signatureBase), sharedSecret)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// HMAC-SHA256 produces 32-byte signature
	if len(sig) != 32 {
		t.Errorf("expected signature length 32, got %d", len(sig))
	}

	// HMAC is deterministic - verify against RFC expected signature
	wantSigB64 := "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8="
	gotSigB64 := base64.StdEncoding.EncodeToString(sig)
	if gotSigB64 != wantSigB64 {
		t.Errorf("signature mismatch\nGot:  %s\nWant: %s", gotSigB64, wantSigB64)
	}

	// Verify our generated signature
	if err := alg.Verify([]byte(signatureBase), sig, sharedSecret); err != nil {
		t.Fatalf("failed to verify our signature: %v", err)
	}

	t.Logf("B.2.5: Generated signature: %s", gotSigB64)
	t.Logf("B.2.5: Signature matches RFC expected value exactly (HMAC is deterministic)")
}

// RFC 9421 Appendix B.2.6 - Signing a Request Using ed25519
func TestRFC9421_AppendixB_2_6_Ed25519(t *testing.T) {
	privKey := loadPrivateKey(t, "test-key-ed25519-private.pem")
	pubKey := loadPublicKey(t, "test-key-ed25519-public.pem")

	alg, err := signing.GetAlgorithm("ed25519")
	if err != nil {
		t.Fatalf("failed to get algorithm: %v", err)
	}

	body := strings.NewReader(`{"hello": "world"}`)
	req, _ := http.NewRequest("POST", "https://example.com/foo?param=Value&Pet=dog", body)
	req.Header.Set("Host", "example.com")
	req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "18")

	msg := base.WrapRequest(req)

	components := []parser.ComponentIdentifier{
		{Name: "date", Type: parser.ComponentField},
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "@path", Type: parser.ComponentDerived},
		{Name: "@authority", Type: parser.ComponentDerived},
		{Name: "content-type", Type: parser.ComponentField},
		{Name: "content-length", Type: parser.ComponentField},
	}

	created := int64(1618884473)
	keyid := "test-key-ed25519"
	params := parser.SignatureParams{
		Created: &created,
		KeyID:   &keyid,
	}

	signatureBase, err := base.Build(msg, components, params)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	want := `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@authority": example.com
"content-type": application/json
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`

	if signatureBase != want {
		t.Errorf("Build() signature base mismatch\nGot:\n%s\n\nWant:\n%s", signatureBase, want)
	}

	// Sign
	sig, err := alg.Sign([]byte(signatureBase), privKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Ed25519 produces 64-byte signature
	if len(sig) != 64 {
		t.Errorf("expected signature length 64, got %d", len(sig))
	}

	// Ed25519 is deterministic - verify against RFC expected signature
	wantSigB64 := "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=="
	gotSigB64 := base64.StdEncoding.EncodeToString(sig)
	if gotSigB64 != wantSigB64 {
		t.Errorf("signature mismatch\nGot:  %s\nWant: %s", gotSigB64, wantSigB64)
	}

	// Verify our generated signature
	if err := alg.Verify([]byte(signatureBase), sig, pubKey); err != nil {
		t.Fatalf("failed to verify our signature: %v", err)
	}

	t.Logf("B.2.6: Generated signature: %s", gotSigB64)
	t.Logf("B.2.6: Signature matches RFC expected value exactly (Ed25519 is deterministic)")
}
