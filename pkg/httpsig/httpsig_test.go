package httpsig

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/sfv"
)

func TestSignerVerifier_RequestRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	components := []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "@path", Type: parser.ComponentDerived},
		{Name: "content-type", Type: parser.ComponentField},
	}

	now := time.Unix(1_700_000_000, 0)

	signer, err := NewSigner(SignerOptions{
		Algorithm:  "hmac-sha256",
		Key:        key,
		KeyID:      "test-key",
		Components: components,
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

	if _, err := signer.SignRequest(req); err != nil {
		t.Fatalf("SignRequest() error: %v", err)
	}

	verifier, err := NewVerifier(VerifyOptions{
		Key:       key,
		Algorithm: "hmac-sha256",
		RequiredComponents: []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
			{Name: "@path", Type: parser.ComponentDerived},
		},
		ParamsValidation: parser.SignatureParamsValidationOptions{
			RequireCreated:      true,
			CreatedNotOlderThan: time.Minute,
			CreatedNotNewerThan: time.Minute,
			Now:                 now,
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	result, err := verifier.VerifyRequest(req)
	if err != nil {
		t.Fatalf("VerifyRequest() error: %v", err)
	}
	if result.Label != DefaultLabel {
		t.Fatalf("VerifyRequest() label = %q, want %q", result.Label, DefaultLabel)
	}
	if result.SignatureBase == "" {
		t.Fatalf("VerifyRequest() signature base is empty")
	}
}

func TestVerifier_RequiredComponentMissing(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	components := []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
	}

	signer, err := NewSigner(SignerOptions{
		Algorithm:  "hmac-sha256",
		Key:        key,
		Components: components,
	})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://example.com/foo", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}

	if _, err := signer.SignRequest(req); err != nil {
		t.Fatalf("SignRequest() error: %v", err)
	}

	verifier, err := NewVerifier(VerifyOptions{
		Key: key,
		RequiredComponents: []parser.ComponentIdentifier{
			{Name: "@path", Type: parser.ComponentDerived},
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	_, err = verifier.VerifyRequest(req)
	if err == nil {
		t.Fatal("VerifyRequest() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "required component") {
		t.Fatalf("VerifyRequest() error = %q, want required component error", err.Error())
	}
}

func TestNewSigner_Errors(t *testing.T) {
	if _, err := NewSigner(SignerOptions{}); err == nil {
		t.Fatal("NewSigner() expected error for missing algorithm")
	}
	if _, err := NewSigner(SignerOptions{Algorithm: "hmac-sha256"}); err == nil {
		t.Fatal("NewSigner() expected error for missing key")
	}
	if _, err := NewSigner(SignerOptions{Algorithm: "not-real", Key: []byte("k")}); err == nil {
		t.Fatal("NewSigner() expected error for unsupported algorithm")
	}
}

func TestSigner_DisableCreatedAndAlgorithm(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	components := []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
	}

	signer, err := NewSigner(SignerOptions{
		Algorithm:        "hmac-sha256",
		Key:              key,
		Components:       components,
		DisableCreated:   true,
		DisableAlgorithm: true,
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
	entry := parsed.Signatures[DefaultLabel]
	if entry.SignatureParams.Created != nil {
		t.Fatalf("Created param = %v, want nil", entry.SignatureParams.Created)
	}
	if entry.SignatureParams.Algorithm != nil {
		t.Fatalf("Algorithm param = %v, want nil", entry.SignatureParams.Algorithm)
	}
}
