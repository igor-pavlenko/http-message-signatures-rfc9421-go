package httpsig

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/base"
	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/sfv"
	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/signing"
)

// KeyResolver resolves a verification key (and optionally an algorithm) for a signature.
type KeyResolver interface {
	ResolveKey(ctx context.Context, label string, params parser.SignatureParams) (key any, algorithm string, err error)
}

// KeyResolverFunc adapts a function to the KeyResolver interface.
type KeyResolverFunc func(ctx context.Context, label string, params parser.SignatureParams) (any, string, error)

// ResolveKey implements KeyResolver.
func (f KeyResolverFunc) ResolveKey(ctx context.Context, label string, params parser.SignatureParams) (any, string, error) {
	return f(ctx, label, params)
}

// VerifyOptions configures signature verification.
type VerifyOptions struct {
	Label              string
	RequiredComponents []parser.ComponentIdentifier
	AllowedAlgorithms  []string
	Key                any
	Algorithm          string
	KeyResolver        KeyResolver
	ParamsValidation   parser.SignatureParamsValidationOptions
	Limits             *sfv.Limits
}

// VerifyResult contains details about a successful verification.
type VerifyResult struct {
	Label         string
	Entry         parser.SignatureEntry
	SignatureBase string
}

// Verifier verifies HTTP message signatures using a configured policy.
// A Verifier is safe for concurrent use by multiple goroutines.
type Verifier struct {
	label              string
	requiredComponents []parser.ComponentIdentifier
	allowedAlgorithms  map[string]struct{}
	key                any
	algorithm          string
	keyResolver        KeyResolver
	paramsValidation   parser.SignatureParamsValidationOptions
	limits             sfv.Limits
}

// NewVerifier creates a Verifier with the provided options.
func NewVerifier(opts VerifyOptions) (*Verifier, error) {
	if opts.KeyResolver != nil && opts.Key != nil {
		return nil, fmt.Errorf("key and key resolver are mutually exclusive")
	}
	if opts.KeyResolver == nil && opts.Key == nil {
		return nil, fmt.Errorf("verification key or key resolver is required")
	}

	label := opts.Label

	limits := sfv.DefaultLimits()
	if opts.Limits != nil {
		limits = *opts.Limits
	}

	allowed := make(map[string]struct{}, len(opts.AllowedAlgorithms))
	for _, alg := range opts.AllowedAlgorithms {
		allowed[alg] = struct{}{}
	}

	return &Verifier{
		label:              label,
		requiredComponents: opts.RequiredComponents,
		allowedAlgorithms:  allowed,
		key:                opts.Key,
		algorithm:          opts.Algorithm,
		keyResolver:        opts.KeyResolver,
		paramsValidation:   opts.ParamsValidation,
		limits:             limits,
	}, nil
}

// VerifyRequest verifies the signature(s) on an HTTP request.
func (v *Verifier) VerifyRequest(req *http.Request) (VerifyResult, error) {
	if req == nil {
		return VerifyResult{}, fmt.Errorf("request is required")
	}
	msg := base.WrapRequest(req)
	return v.verifyMessage(req.Context(), msg, req.Header)
}

// VerifyResponse verifies the signature(s) on an HTTP response.
func (v *Verifier) VerifyResponse(resp *http.Response, relatedReq *http.Request) (VerifyResult, error) {
	if resp == nil {
		return VerifyResult{}, fmt.Errorf("response is required")
	}
	msg := base.WrapResponse(resp, relatedReq)
	return v.verifyMessage(context.Background(), msg, resp.Header)
}

func (v *Verifier) verifyMessage(ctx context.Context, msg base.HTTPMessage, headers http.Header) (VerifyResult, error) {
	signatureInput := headers.Get("Signature-Input")
	signature := headers.Get("Signature")

	if signatureInput == "" {
		return VerifyResult{}, fmt.Errorf("header Signature-Input is empty")
	}
	if signature == "" {
		return VerifyResult{}, fmt.Errorf("header Signature is empty")
	}

	parsed, err := parser.ParseSignatureInput(signatureInput, v.limits)
	if err != nil {
		return VerifyResult{}, err
	}
	signatures := parsed.Signatures

	// Now parse the Signature header as a dictionary to match labels
	sigParser := sfv.NewParser(signature, v.limits)
	sigDict, err := sigParser.ParseDictionary()
	if err != nil {
		return VerifyResult{}, fmt.Errorf("failed to parse Signature header: %w", err)
	}

	label := v.label
	if label == "" {
		if len(signatures) != 1 {
			return VerifyResult{}, fmt.Errorf("signature label is required when multiple signatures are present")
		}
		for k := range signatures {
			label = k
			break
		}
	}

	entry, ok := signatures[label]
	if !ok {
		return VerifyResult{}, fmt.Errorf("signature %q not found in Signature-Input", label)
	}

	// Match signature value from Signature header
	sigValue, ok := sigDict.Values[label]
	if !ok {
		return VerifyResult{}, fmt.Errorf("signature %q not found in Signature header", label)
	}

	sigItem, ok := sigValue.(sfv.Item)
	if !ok {
		return VerifyResult{}, fmt.Errorf("signature value must be an item")
	}

	sigBytes, ok := sigItem.Value.([]byte)
	if !ok {
		return VerifyResult{}, fmt.Errorf("signature value must be a byte sequence, got %T", sigItem.Value)
	}
	entry.SignatureValue = sigBytes

	if err := v.validateRequiredComponents(entry.CoveredComponents); err != nil {
		return VerifyResult{}, err
	}

	if err := parser.ValidateSignatureParams(entry.SignatureParams, v.paramsValidation); err != nil {
		return VerifyResult{}, err
	}

	key, algID, err := v.resolveKeyAndAlgorithm(ctx, label, entry.SignatureParams)
	if err != nil {
		return VerifyResult{}, err
	}

	alg, err := signing.GetAlgorithm(algID)
	if err != nil {
		return VerifyResult{}, err
	}

	sigBase, err := base.Build(msg, entry.CoveredComponents, entry.SignatureParams)
	if err != nil {
		return VerifyResult{}, err
	}

	if err := alg.Verify([]byte(sigBase), entry.SignatureValue, key); err != nil {
		return VerifyResult{}, err
	}

	return VerifyResult{
		Label:         label,
		Entry:         entry,
		SignatureBase: sigBase,
	}, nil
}

func (v *Verifier) resolveKeyAndAlgorithm(ctx context.Context, label string, params parser.SignatureParams) (any, string, error) {
	algID := v.algorithm
	if params.Algorithm != nil {
		if algID != "" && algID != *params.Algorithm {
			return nil, "", fmt.Errorf("algorithm mismatch between options and signature parameters")
		}
		if algID == "" {
			algID = *params.Algorithm
		}
	}

	var key any
	var resolvedAlg string
	var err error
	if v.keyResolver != nil {
		key, resolvedAlg, err = v.keyResolver.ResolveKey(ctx, label, params)
		if err != nil {
			return nil, "", err
		}
	} else {
		key = v.key
	}

	if key == nil {
		return nil, "", fmt.Errorf("verification key is required")
	}

	if resolvedAlg != "" {
		if algID != "" && algID != resolvedAlg {
			return nil, "", fmt.Errorf("algorithm mismatch between resolver and signature parameters")
		}
		algID = resolvedAlg
	}

	if algID == "" {
		return nil, "", fmt.Errorf("algorithm is required for verification")
	}

	if len(v.allowedAlgorithms) > 0 {
		if _, ok := v.allowedAlgorithms[algID]; !ok {
			return nil, "", fmt.Errorf("algorithm %q is not allowed", algID)
		}
	}

	return key, algID, nil
}

func (v *Verifier) validateRequiredComponents(covered []parser.ComponentIdentifier) error {
	for _, required := range v.requiredComponents {
		if !componentInList(covered, required) {
			return fmt.Errorf("required component %q is missing", required.Name)
		}
	}
	return nil
}

func componentInList(list []parser.ComponentIdentifier, target parser.ComponentIdentifier) bool {
	for _, comp := range list {
		if componentEqual(comp, target) {
			return true
		}
	}
	return false
}

func componentEqual(a, b parser.ComponentIdentifier) bool {
	if a.Name != b.Name || a.Type != b.Type {
		return false
	}
	if len(a.Parameters) != len(b.Parameters) {
		return false
	}
	for i := range a.Parameters {
		if !parameterEqual(a.Parameters[i], b.Parameters[i]) {
			return false
		}
	}
	return true
}

func parameterEqual(a, b parser.Parameter) bool {
	if a.Key != b.Key {
		return false
	}
	return bareItemEqual(a.Value, b.Value)
}

func bareItemEqual(a, b parser.BareItem) bool {
	switch av := a.(type) {
	case parser.Boolean:
		bv, ok := b.(parser.Boolean)
		return ok && av.Value == bv.Value
	case parser.Integer:
		bv, ok := b.(parser.Integer)
		return ok && av.Value == bv.Value
	case parser.String:
		bv, ok := b.(parser.String)
		return ok && av.Value == bv.Value
	case parser.Token:
		bv, ok := b.(parser.Token)
		return ok && av.Value == bv.Value
	case parser.ByteSequence:
		bv, ok := b.(parser.ByteSequence)
		return ok && bytes.Equal(av.Value, bv.Value)
	case nil:
		return b == nil
	default:
		return false
	}
}
