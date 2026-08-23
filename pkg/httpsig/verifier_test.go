package httpsig

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
)

func TestNewVerifier_Errors(t *testing.T) {
	_, err := NewVerifier(VerifyOptions{Key: []byte("k"), KeyResolver: KeyResolverFunc(func(context.Context, string, parser.SignatureParams) (any, string, error) {
		return []byte("k"), "hmac-sha256", nil
	})})
	if err == nil {
		t.Fatal("NewVerifier() expected error for key + key resolver")
	}

	_, err = NewVerifier(VerifyOptions{})
	if err == nil {
		t.Fatal("NewVerifier() expected error for missing key and resolver")
	}
}

func TestVerifier_RequestNil(t *testing.T) {
	verifier, err := NewVerifier(VerifyOptions{
		Key:       []byte("0123456789abcdef0123456789abcdef"),
		Algorithm: "hmac-sha256",
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	if _, err := verifier.VerifyRequest(nil); err == nil {
		t.Fatal("VerifyRequest() expected error for nil request")
	}
}

func TestVerifier_ResponseNil(t *testing.T) {
	verifier, err := NewVerifier(VerifyOptions{
		Key:       []byte("0123456789abcdef0123456789abcdef"),
		Algorithm: "hmac-sha256",
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	if _, err := verifier.VerifyResponse(nil, nil); err == nil {
		t.Fatal("VerifyResponse() expected error for nil response")
	}
}

func TestVerifier_MissingHeaders(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	verifier, err := NewVerifier(VerifyOptions{
		Key:       key,
		Algorithm: "hmac-sha256",
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}

	if _, err := verifier.VerifyRequest(req); err == nil || !strings.Contains(err.Error(), "Signature-Input") {
		t.Fatalf("VerifyRequest() error = %v, want missing headers error", err)
	}

	req.Header.Set("Signature-Input", `sig1=("@method");created=1`)
	req.Header.Del("Signature")
	if _, err := verifier.VerifyRequest(req); err == nil || !strings.Contains(err.Error(), "Signature is empty") {
		t.Fatalf("VerifyRequest() error = %v, want missing Signature error", err)
	}
}

func TestVerifier_LabelRequiredWithMultipleSignatures(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	req.Header.Set("Signature-Input", `sig1=("@method");created=1, sig2=("@method");created=1`)
	req.Header.Set("Signature", `sig1=:YWJj:, sig2=:ZGVm:`)

	verifier, err := NewVerifier(VerifyOptions{
		Key:       []byte("0123456789abcdef0123456789abcdef"),
		Algorithm: "hmac-sha256",
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	_, err = verifier.VerifyRequest(req)
	if err == nil || !strings.Contains(err.Error(), "label is required") {
		t.Fatalf("VerifyRequest() error = %v, want label required error", err)
	}
}

func TestVerifier_ResponseRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	components := []parser.ComponentIdentifier{
		{Name: "@status", Type: parser.ComponentDerived},
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
		Header:     http.Header{},
	}
	if _, err := signer.SignResponse(resp, nil); err != nil {
		t.Fatalf("SignResponse() error: %v", err)
	}

	verifier, err := NewVerifier(VerifyOptions{
		Key:       key,
		Algorithm: "hmac-sha256",
		RequiredComponents: []parser.ComponentIdentifier{
			{Name: "@status", Type: parser.ComponentDerived},
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	if _, err := verifier.VerifyResponse(resp, nil); err != nil {
		t.Fatalf("VerifyResponse() error: %v", err)
	}
}

func TestVerifier_SignatureNotFound(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := NewSigner(SignerOptions{
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
	if _, err := signer.SignRequest(req); err != nil {
		t.Fatalf("SignRequest() error: %v", err)
	}

	verifier, err := NewVerifier(VerifyOptions{
		Label:     "sig2",
		Key:       key,
		Algorithm: "hmac-sha256",
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	_, err = verifier.VerifyRequest(req)
	if err == nil || !strings.Contains(err.Error(), "signature \"sig2\" not found") {
		t.Fatalf("VerifyRequest() error = %v, want signature not found error", err)
	}
}

func TestVerifier_InvalidSignature(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := NewSigner(SignerOptions{
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
	if _, err := signer.SignRequest(req); err != nil {
		t.Fatalf("SignRequest() error: %v", err)
	}

	verifier, err := NewVerifier(VerifyOptions{
		Key:       []byte("abcdef0123456789abcdef0123456789"),
		Algorithm: "hmac-sha256",
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	_, err = verifier.VerifyRequest(req)
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("VerifyRequest() error = %v, want verification failed error", err)
	}
}

func TestVerifier_AlgorithmMismatch(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := NewSigner(SignerOptions{
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
	if _, err := signer.SignRequest(req); err != nil {
		t.Fatalf("SignRequest() error: %v", err)
	}

	verifier, err := NewVerifier(VerifyOptions{
		Key:       key,
		Algorithm: "ed25519",
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	_, err = verifier.VerifyRequest(req)
	if err == nil || !strings.Contains(err.Error(), "algorithm mismatch") {
		t.Fatalf("VerifyRequest() error = %v, want algorithm mismatch error", err)
	}
}

func TestVerifier_AlgorithmFromOptions(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := NewSigner(SignerOptions{
		Algorithm:        "hmac-sha256",
		Key:              key,
		Components:       []parser.ComponentIdentifier{{Name: "@method", Type: parser.ComponentDerived}},
		DisableAlgorithm: true,
	})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	if _, err := signer.SignRequest(req); err != nil {
		t.Fatalf("SignRequest() error: %v", err)
	}

	verifier, err := NewVerifier(VerifyOptions{
		Key:       key,
		Algorithm: "hmac-sha256",
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	if _, err := verifier.VerifyRequest(req); err != nil {
		t.Fatalf("VerifyRequest() error: %v", err)
	}
}

func TestVerifier_KeyResolverAlgorithmMismatch(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := NewSigner(SignerOptions{
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
	if _, err := signer.SignRequest(req); err != nil {
		t.Fatalf("SignRequest() error: %v", err)
	}

	verifier, err := NewVerifier(VerifyOptions{
		KeyResolver: KeyResolverFunc(func(context.Context, string, parser.SignatureParams) (any, string, error) {
			return key, "ed25519", nil
		}),
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	_, err = verifier.VerifyRequest(req)
	if err == nil || !strings.Contains(err.Error(), "algorithm mismatch") {
		t.Fatalf("VerifyRequest() error = %v, want algorithm mismatch error", err)
	}
}

func TestVerifier_RequiredComponentParamMismatch(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	components := []parser.ComponentIdentifier{
		{
			Name: "@query-param",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "name", Value: parser.String{Value: "foo"}},
			},
		},
	}

	signer, err := NewSigner(SignerOptions{
		Algorithm:  "hmac-sha256",
		Key:        key,
		Components: components,
	})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com/search?foo=bar", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	if _, err := signer.SignRequest(req); err != nil {
		t.Fatalf("SignRequest() error: %v", err)
	}

	verifier, err := NewVerifier(VerifyOptions{
		Key: key,
		RequiredComponents: []parser.ComponentIdentifier{
			{
				Name: "@query-param",
				Type: parser.ComponentDerived,
				Parameters: []parser.Parameter{
					{Key: "name", Value: parser.String{Value: "bar"}},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	_, err = verifier.VerifyRequest(req)
	if err == nil || !strings.Contains(err.Error(), "required component") {
		t.Fatalf("VerifyRequest() error = %v, want required component error", err)
	}
}

func TestVerifier_AlgorithmMissing(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := NewSigner(SignerOptions{
		Algorithm:        "hmac-sha256",
		Key:              key,
		Components:       []parser.ComponentIdentifier{{Name: "@method", Type: parser.ComponentDerived}},
		DisableAlgorithm: true,
	})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	if _, err := signer.SignRequest(req); err != nil {
		t.Fatalf("SignRequest() error: %v", err)
	}

	verifier, err := NewVerifier(VerifyOptions{
		Key: key,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	_, err = verifier.VerifyRequest(req)
	if err == nil || !strings.Contains(err.Error(), "algorithm is required") {
		t.Fatalf("VerifyRequest() error = %v, want algorithm required error", err)
	}
}

func TestVerifier_AllowedAlgorithms(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := NewSigner(SignerOptions{
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
	if _, err := signer.SignRequest(req); err != nil {
		t.Fatalf("SignRequest() error: %v", err)
	}

	verifier, err := NewVerifier(VerifyOptions{
		Key:               key,
		AllowedAlgorithms: []string{"rsa-pss-sha512"},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	_, err = verifier.VerifyRequest(req)
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("VerifyRequest() error = %v, want allowed algorithm error", err)
	}
}

func TestVerifier_KeyResolverSuccess(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := NewSigner(SignerOptions{
		Algorithm:        "hmac-sha256",
		Key:              key,
		Components:       []parser.ComponentIdentifier{{Name: "@method", Type: parser.ComponentDerived}},
		DisableAlgorithm: true,
	})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	if _, err := signer.SignRequest(req); err != nil {
		t.Fatalf("SignRequest() error: %v", err)
	}

	called := false
	verifier, err := NewVerifier(VerifyOptions{
		KeyResolver: KeyResolverFunc(func(ctx context.Context, label string, params parser.SignatureParams) (any, string, error) {
			called = true
			return key, "hmac-sha256", nil
		}),
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	if _, err := verifier.VerifyRequest(req); err != nil {
		t.Fatalf("VerifyRequest() error: %v", err)
	}
	if !called {
		t.Fatal("key resolver was not called")
	}
}

func TestVerifier_KeyResolverNilKey(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := NewSigner(SignerOptions{
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
	if _, err := signer.SignRequest(req); err != nil {
		t.Fatalf("SignRequest() error: %v", err)
	}

	verifier, err := NewVerifier(VerifyOptions{
		KeyResolver: KeyResolverFunc(func(context.Context, string, parser.SignatureParams) (any, string, error) {
			return nil, "hmac-sha256", nil
		}),
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	_, err = verifier.VerifyRequest(req)
	if err == nil || !strings.Contains(err.Error(), "verification key is required") {
		t.Fatalf("VerifyRequest() error = %v, want key required error", err)
	}
}

func TestVerifier_KeyResolverError(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := NewSigner(SignerOptions{
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
	if _, err := signer.SignRequest(req); err != nil {
		t.Fatalf("SignRequest() error: %v", err)
	}

	resolverErr := errors.New("resolver failed")
	verifier, err := NewVerifier(VerifyOptions{
		KeyResolver: KeyResolverFunc(func(context.Context, string, parser.SignatureParams) (any, string, error) {
			return nil, "", resolverErr
		}),
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	_, err = verifier.VerifyRequest(req)
	if !errors.Is(err, resolverErr) {
		t.Fatalf("VerifyRequest() error = %v, want resolver error", err)
	}
}

func TestVerifier_ParamsValidationError(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := NewSigner(SignerOptions{
		Algorithm:      "hmac-sha256",
		Key:            key,
		Components:     []parser.ComponentIdentifier{{Name: "@method", Type: parser.ComponentDerived}},
		DisableCreated: true,
	})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	if _, err := signer.SignRequest(req); err != nil {
		t.Fatalf("SignRequest() error: %v", err)
	}

	verifier, err := NewVerifier(VerifyOptions{
		Key: key,
		ParamsValidation: parser.SignatureParamsValidationOptions{
			RequireCreated:      true,
			CreatedNotOlderThan: time.Minute,
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	_, err = verifier.VerifyRequest(req)
	if err == nil || !strings.Contains(err.Error(), "missing \"created\"") {
		t.Fatalf("VerifyRequest() error = %v, want missing created error", err)
	}
}

func TestComponentEquality(t *testing.T) {
	a := parser.ComponentIdentifier{
		Name: "@query-param",
		Type: parser.ComponentDerived,
		Parameters: []parser.Parameter{
			{Key: "name", Value: parser.String{Value: "a"}},
			{Key: "req", Value: parser.Boolean{Value: true}},
			{Key: "sf", Value: parser.Boolean{Value: false}},
			{Key: "id", Value: parser.Integer{Value: 1}},
			{Key: "tok", Value: parser.Token{Value: "t"}},
			{Key: "bs", Value: parser.ByteSequence{Value: []byte("x")}},
		},
	}

	b := parser.ComponentIdentifier{
		Name: "@query-param",
		Type: parser.ComponentDerived,
		Parameters: []parser.Parameter{
			{Key: "name", Value: parser.String{Value: "a"}},
			{Key: "req", Value: parser.Boolean{Value: true}},
			{Key: "sf", Value: parser.Boolean{Value: false}},
			{Key: "id", Value: parser.Integer{Value: 1}},
			{Key: "tok", Value: parser.Token{Value: "t"}},
			{Key: "bs", Value: parser.ByteSequence{Value: []byte("x")}},
		},
	}

	if !componentEqual(a, b) {
		t.Fatalf("componentEqual() expected true for identical components")
	}

	b.Parameters[0] = parser.Parameter{Key: "name", Value: parser.String{Value: "b"}}
	if componentEqual(a, b) {
		t.Fatalf("componentEqual() expected false for mismatched parameters")
	}

	b = a
	b.Parameters = b.Parameters[:len(b.Parameters)-1]
	if componentEqual(a, b) {
		t.Fatalf("componentEqual() expected false for parameter length mismatch")
	}

	if !bareItemEqual(nil, nil) {
		t.Fatalf("bareItemEqual(nil, nil) expected true")
	}
	if bareItemEqual(parser.String{Value: "a"}, parser.Token{Value: "a"}) {
		t.Fatalf("bareItemEqual() expected false for mismatched types")
	}
}

func TestVerifier_ConcurrentUse(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	components := []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "@authority", Type: parser.ComponentDerived},
	}

	// Sign several messages with distinct Signature-Input values so
	// concurrent verifications parse different headers.
	var pairs []SignatureHeaders
	for i := range int64(4) {
		signer, err := NewSigner(SignerOptions{
			Algorithm:  "hmac-sha256",
			Key:        key,
			Components: components,
			Created:    time.Unix(1618884473+i, 0),
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
		pairs = append(pairs, headers)
	}
	// Mismatched pair: valid signature bytes over a different base.
	tampered := SignatureHeaders{SignatureInput: pairs[0].SignatureInput, Signature: pairs[1].Signature}

	verifier, err := NewVerifier(VerifyOptions{
		Key:       key,
		Algorithm: "hmac-sha256",
	})
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range 200 {
				req, err := http.NewRequest(http.MethodGet, "https://example.com/foo", nil)
				if err != nil {
					t.Errorf("NewRequest() error: %v", err)
					return
				}
				if i%5 == 4 {
					req.Header.Set("Signature-Input", tampered.SignatureInput)
					req.Header.Set("Signature", tampered.Signature)
					if _, err := verifier.VerifyRequest(req); err == nil {
						t.Errorf("VerifyRequest() expected error for tampered signature")
						return
					}
					continue
				}
				headers := pairs[(g+i)%len(pairs)]
				req.Header.Set("Signature-Input", headers.SignatureInput)
				req.Header.Set("Signature", headers.Signature)
				if _, err := verifier.VerifyRequest(req); err != nil {
					t.Errorf("VerifyRequest() error: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
