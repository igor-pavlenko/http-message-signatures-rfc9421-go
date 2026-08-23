package httpsig

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/sfv"
)

func TestSigner_SetsParams(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	components := []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "content-type", Type: parser.ComponentField},
	}
	now := time.Unix(1_700_000_123, 0)
	expires := now.Add(30 * time.Second)

	signer, err := NewSigner(SignerOptions{
		Algorithm:  "hmac-sha256",
		Key:        key,
		KeyID:      "key-1",
		Nonce:      "nonce-1",
		Tag:        "tag-1",
		Components: components,
		Expires:    expires,
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://example.com/foo", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	headers, err := signer.SignRequest(req)
	if err != nil {
		t.Fatalf("SignRequest() error: %v", err)
	}

	parsed, err := parser.ParseSignatures(headers.SignatureInput, headers.Signature, sfv.DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSignatures() error: %v", err)
	}
	entry := parsed.Signatures[DefaultLabel]

	if entry.SignatureParams.Created == nil || *entry.SignatureParams.Created != now.Unix() {
		t.Fatalf("Created param = %v, want %d", entry.SignatureParams.Created, now.Unix())
	}
	if entry.SignatureParams.Expires == nil || *entry.SignatureParams.Expires != expires.Unix() {
		t.Fatalf("Expires param = %v, want %d", entry.SignatureParams.Expires, expires.Unix())
	}
	if entry.SignatureParams.Algorithm == nil || *entry.SignatureParams.Algorithm != "hmac-sha256" {
		t.Fatalf("Algorithm param = %v, want hmac-sha256", entry.SignatureParams.Algorithm)
	}
	if entry.SignatureParams.KeyID == nil || *entry.SignatureParams.KeyID != "key-1" {
		t.Fatalf("KeyID param = %v, want key-1", entry.SignatureParams.KeyID)
	}
	if entry.SignatureParams.Nonce == nil || *entry.SignatureParams.Nonce != "nonce-1" {
		t.Fatalf("Nonce param = %v, want nonce-1", entry.SignatureParams.Nonce)
	}
	if entry.SignatureParams.Tag == nil || *entry.SignatureParams.Tag != "tag-1" {
		t.Fatalf("Tag param = %v, want tag-1", entry.SignatureParams.Tag)
	}
}

func TestSigner_CustomLabel(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := NewSigner(SignerOptions{
		Label:      "custom",
		Algorithm:  "hmac-sha256",
		Key:        key,
		Components: []parser.ComponentIdentifier{{Name: "@method", Type: parser.ComponentDerived}},
	})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}

	headers, err := signer.SignRequest(req)
	if err != nil {
		t.Fatalf("SignRequest() error: %v", err)
	}

	parsed, err := parser.ParseSignatures(headers.SignatureInput, headers.Signature, sfv.DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSignatures() error: %v", err)
	}
	if _, ok := parsed.Signatures["custom"]; !ok {
		t.Fatalf("signature label %q not found", "custom")
	}
	if _, ok := parsed.Signatures[DefaultLabel]; ok {
		t.Fatalf("unexpected default label %q present", DefaultLabel)
	}
}

func TestSigner_SignRequestErrors(t *testing.T) {
	signer := &Signer{}
	if _, err := signer.SignRequest(nil); err == nil {
		t.Fatal("SignRequest() expected error for nil request")
	}

	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := NewSigner(SignerOptions{
		Algorithm:  "hmac-sha256",
		Key:        key,
		Components: []parser.ComponentIdentifier{{Name: "x-missing", Type: parser.ComponentField}},
	})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	if _, err := signer.SignRequest(req); err == nil {
		t.Fatal("SignRequest() expected error for missing header component")
	}
}

func TestSigner_SignRequestInvalidKey(t *testing.T) {
	signer, err := NewSigner(SignerOptions{
		Algorithm:  "hmac-sha256",
		Key:        "not-bytes",
		Components: []parser.ComponentIdentifier{{Name: "@method", Type: parser.ComponentDerived}},
	})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}

	if _, err := signer.SignRequest(req); err == nil {
		t.Fatal("SignRequest() expected error for invalid key type")
	}
}

func TestSigner_SignResponse(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	components := []parser.ComponentIdentifier{
		{Name: "@status", Type: parser.ComponentDerived},
		{Name: "content-type", Type: parser.ComponentField},
	}
	signer, err := NewSigner(SignerOptions{
		Algorithm:  "hmac-sha256",
		Key:        key,
		Components: components,
	})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}

	resp := &http.Response{
		StatusCode: 200,
		Header:     nil,
	}
	resp.Header = http.Header{}
	resp.Header.Set("Content-Type", "application/json")

	headers, err := signer.SignResponse(resp, nil)
	if err != nil {
		t.Fatalf("SignResponse() error: %v", err)
	}
	if headers.SignatureInput == "" || headers.Signature == "" {
		t.Fatalf("SignResponse() returned empty headers")
	}
	if got := resp.Header.Get("Signature-Input"); got == "" {
		t.Fatalf("response missing Signature-Input header")
	}
	if got := resp.Header.Get("Signature"); got == "" {
		t.Fatalf("response missing Signature header")
	}
}

func TestSigner_SignResponseInitializesHeader(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := NewSigner(SignerOptions{
		Algorithm:  "hmac-sha256",
		Key:        key,
		Components: []parser.ComponentIdentifier{{Name: "@status", Type: parser.ComponentDerived}},
	})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}

	resp := &http.Response{StatusCode: 200}
	if _, err := signer.SignResponse(resp, nil); err != nil {
		t.Fatalf("SignResponse() error: %v", err)
	}
	if resp.Header == nil {
		t.Fatal("SignResponse() did not initialize response headers")
	}
	if resp.Header.Get("Signature") == "" || resp.Header.Get("Signature-Input") == "" {
		t.Fatal("SignResponse() did not set signature headers")
	}
}

func TestSigner_SignResponseNil(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := NewSigner(SignerOptions{
		Algorithm:  "hmac-sha256",
		Key:        key,
		Components: []parser.ComponentIdentifier{{Name: "@status", Type: parser.ComponentDerived}},
	})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}
	if _, err := signer.SignResponse(nil, nil); err == nil {
		t.Fatal("SignResponse() expected error for nil response")
	}
}

func TestSigner_ConcurrentUse(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	components := []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "@authority", Type: parser.ComponentDerived},
	}

	signer, err := NewSigner(SignerOptions{
		Algorithm:  "hmac-sha256",
		Key:        key,
		Components: components,
		Created:    time.Unix(1618884473, 0),
	})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}

	verifier, err := NewVerifier(VerifyOptions{
		Key:       key,
		Algorithm: "hmac-sha256",
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				req, err := http.NewRequest(http.MethodGet, "https://example.com/foo", nil)
				if err != nil {
					t.Errorf("NewRequest() error: %v", err)
					return
				}
				if _, err := signer.SignRequest(req); err != nil {
					t.Errorf("SignRequest() error: %v", err)
					return
				}
				if _, err := verifier.VerifyRequest(req); err != nil {
					t.Errorf("VerifyRequest() error: %v", err)
					return
				}
			}
		})
	}
	wg.Wait()
}
