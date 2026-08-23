package httpsig

import (
	"fmt"
	"net/http"
	"time"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/base"
	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/signing"
)

// DefaultLabel is the default signature label used by Signer and Verifier.
const DefaultLabel = "sig1"

// SignatureHeaders contains serialized Signature-Input and Signature header values.
type SignatureHeaders struct {
	SignatureInput string
	Signature      string
}

// SignerOptions configures a high-level signature operation.
type SignerOptions struct {
	Label      string
	Components []parser.ComponentIdentifier

	Algorithm string
	Key       any

	KeyID   string
	Nonce   string
	Tag     string
	Created time.Time
	Expires time.Time

	DisableCreated   bool
	DisableAlgorithm bool
	Now              func() time.Time
}

// Signer signs HTTP messages and attaches Signature-Input and Signature headers.
// A Signer is safe for concurrent use by multiple goroutines.
type Signer struct {
	label      string
	components []parser.ComponentIdentifier
	params     parser.SignatureParams
	alg        signing.Algorithm
	key        any
	sigInput   string
}

// NewSigner creates a Signer with the provided options.
func NewSigner(opts SignerOptions) (*Signer, error) {
	if opts.Algorithm == "" {
		return nil, fmt.Errorf("algorithm is required")
	}
	if opts.Key == nil {
		return nil, fmt.Errorf("signing key is required")
	}

	label := opts.Label
	if label == "" {
		label = DefaultLabel
	}

	alg, err := signing.GetAlgorithm(opts.Algorithm)
	if err != nil {
		return nil, err
	}

	params := parser.SignatureParams{}

	if !opts.DisableCreated {
		created := opts.Created
		if created.IsZero() {
			if opts.Now != nil {
				created = opts.Now()
			} else {
				created = time.Now()
			}
		}
		createdUnix := created.Unix()
		params.Created = &createdUnix
	}

	if !opts.Expires.IsZero() {
		expiresUnix := opts.Expires.Unix()
		params.Expires = &expiresUnix
	}

	if !opts.DisableAlgorithm {
		algID := opts.Algorithm
		params.Algorithm = &algID
	}

	if opts.KeyID != "" {
		keyID := opts.KeyID
		params.KeyID = &keyID
	}
	if opts.Nonce != "" {
		nonce := opts.Nonce
		params.Nonce = &nonce
	}
	if opts.Tag != "" {
		tag := opts.Tag
		params.Tag = &tag
	}

	sigInput, err := serializeSignatureInput(label, opts.Components, params)
	if err != nil {
		return nil, err
	}

	return &Signer{
		label:      label,
		components: opts.Components,
		params:     params,
		alg:        alg,
		key:        opts.Key,
		sigInput:   sigInput,
	}, nil
}

// SignRequest signs an HTTP request and sets Signature-Input and Signature headers.
func (s *Signer) SignRequest(req *http.Request) (SignatureHeaders, error) {
	if req == nil {
		return SignatureHeaders{}, fmt.Errorf("request is required")
	}
	msg := base.WrapRequest(req)
	headers, err := s.signMessage(msg)
	if err != nil {
		return SignatureHeaders{}, err
	}
	req.Header.Set("Signature-Input", headers.SignatureInput)
	req.Header.Set("Signature", headers.Signature)
	return headers, nil
}

// SignResponse signs an HTTP response and sets Signature-Input and Signature headers.
func (s *Signer) SignResponse(resp *http.Response, relatedReq *http.Request) (SignatureHeaders, error) {
	if resp == nil {
		return SignatureHeaders{}, fmt.Errorf("response is required")
	}
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	msg := base.WrapResponse(resp, relatedReq)
	headers, err := s.signMessage(msg)
	if err != nil {
		return SignatureHeaders{}, err
	}
	resp.Header.Set("Signature-Input", headers.SignatureInput)
	resp.Header.Set("Signature", headers.Signature)
	return headers, nil
}

func (s *Signer) signMessage(msg base.HTTPMessage) (SignatureHeaders, error) {
	sigBase, err := base.Build(msg, s.components, s.params)
	if err != nil {
		return SignatureHeaders{}, err
	}

	signature, err := s.alg.Sign([]byte(sigBase), s.key)
	if err != nil {
		return SignatureHeaders{}, err
	}

	sigHeader, err := serializeSignature(s.label, signature)
	if err != nil {
		return SignatureHeaders{}, err
	}

	return SignatureHeaders{
		SignatureInput: s.sigInput,
		Signature:      sigHeader,
	}, nil
}
