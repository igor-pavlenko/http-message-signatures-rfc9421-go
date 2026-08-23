package main

import (
	"fmt"
	"time"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/httpsig"
	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
	yaronf "github.com/yaronf/httpsign"
)

const (
	sigLabel        = "sig1"
	expiresAfterSec = 300
	createdMaxAge   = 24 * time.Hour
	createdSkew     = 5 * time.Minute
)

// checkResult is one signer -> verifier interop check.
type checkResult struct {
	scenario  string
	algID     string
	direction string // "yaronf/httpsign -> ours" or "ours -> yaronf/httpsign"
	ok        bool
	errMsg    string
	sigInput  string
	signature string
}

func oursValidation() parser.SignatureParamsValidationOptions {
	return parser.SignatureParamsValidationOptions{
		RequireCreated:          true,
		CreatedNotOlderThan:     createdMaxAge,
		CreatedNotNewerThan:     createdSkew,
		RejectExpired:           true,
		ExpiresNotBeforeCreated: true,
	}
}

func theirsVerifyConfig(s scenario) *yaronf.VerifyConfig {
	cfg := yaronf.NewVerifyConfig().
		SetVerifyCreated(true).
		SetNotOlderThan(createdMaxAge).
		SetNotNewerThan(createdSkew).
		SetRejectExpired(true)
	if s.extra.keyID {
		cfg.SetKeyID(keyIDFor(s.algID))
	}
	return cfg
}

func theirsSignConfig(s scenario) *yaronf.SignConfig {
	cfg := yaronf.NewSignConfig()
	if s.extra.keyID {
		cfg.SetKeyID(keyIDFor(s.algID))
	}
	if s.extra.nonce != "" {
		cfg.SetNonce(s.extra.nonce)
	}
	if s.extra.tag != "" {
		cfg.SetTag(s.extra.tag)
	}
	if s.extra.expires {
		cfg.SetExpiresAfter(expiresAfterSec)
	}
	return cfg
}

func oursSignerOptions(s scenario) httpsig.SignerOptions {
	opts := httpsig.SignerOptions{
		Label:      sigLabel,
		Components: oursComponents(s.headers, s.queryParams),
		Algorithm:  s.algID,
		Key:        oursSignKey(s.algID),
	}
	if s.extra.keyID {
		opts.KeyID = keyIDFor(s.algID)
	}
	if s.extra.nonce != "" {
		opts.Nonce = s.extra.nonce
	}
	if s.extra.tag != "" {
		opts.Tag = s.extra.tag
	}
	if s.extra.expires {
		opts.Expires = time.Now().Add(expiresAfterSec * time.Second)
	}
	return opts
}

// runTheirsSignOursVerify signs the scenario's request/response with
// yaronf/httpsign and verifies it with this library.
func runTheirsSignOursVerify(s scenario) checkResult {
	res := checkResult{scenario: s.name, algID: s.algID, direction: "yaronf/httpsign → ours"}

	req := s.buildReq()

	signer, err := theirsNewSigner(s.algID, theirsSignConfig(s), theirsFields(s.headers, s.queryParams))
	if err != nil {
		return fail(res, fmt.Errorf("build yaronf signer: %w", err))
	}

	if s.isResponse {
		hResp := s.buildResp(req)
		defer func() { _ = hResp.Body.Close() }()
		sigInput, sig, err := yaronf.SignResponse(sigLabel, *signer, hResp, req)
		if err != nil {
			return fail(res, fmt.Errorf("yaronf sign response: %w", err))
		}
		hResp.Header.Set("Signature-Input", sigInput)
		hResp.Header.Set("Signature", sig)
		res.sigInput, res.signature = sigInput, sig

		verifier, err := httpsig.NewVerifier(httpsig.VerifyOptions{
			Label: sigLabel, Key: oursVerifyKey(s.algID), ParamsValidation: oursValidation(),
		})
		if err != nil {
			return fail(res, fmt.Errorf("build our verifier: %w", err))
		}
		if _, err := verifier.VerifyResponse(hResp, req); err != nil {
			return fail(res, fmt.Errorf("our verify: %w", err))
		}
		return ok(res)
	}

	sigInput, sig, err := yaronf.SignRequest(sigLabel, *signer, req)
	if err != nil {
		return fail(res, fmt.Errorf("yaronf sign request: %w", err))
	}
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sig)
	res.sigInput, res.signature = sigInput, sig

	verifier, err := httpsig.NewVerifier(httpsig.VerifyOptions{
		Label: sigLabel, Key: oursVerifyKey(s.algID), ParamsValidation: oursValidation(),
	})
	if err != nil {
		return fail(res, fmt.Errorf("build our verifier: %w", err))
	}
	if _, err := verifier.VerifyRequest(req); err != nil {
		return fail(res, fmt.Errorf("our verify: %w", err))
	}
	return ok(res)
}

// runOursSignTheirsVerify signs the scenario's request/response with this
// library and verifies it with yaronf/httpsign.
func runOursSignTheirsVerify(s scenario) checkResult {
	res := checkResult{scenario: s.name, algID: s.algID, direction: "ours → yaronf/httpsign"}

	req := s.buildReq()

	signer, err := httpsig.NewSigner(oursSignerOptions(s))
	if err != nil {
		return fail(res, fmt.Errorf("build our signer: %w", err))
	}

	verifier, err := theirsNewVerifier(s.algID, theirsVerifyConfig(s), theirsFields(s.headers, s.queryParams))
	if err != nil {
		return fail(res, fmt.Errorf("build yaronf verifier: %w", err))
	}

	if s.isResponse {
		hResp := s.buildResp(req)
		defer func() { _ = hResp.Body.Close() }()
		headers, err := signer.SignResponse(hResp, req)
		if err != nil {
			return fail(res, fmt.Errorf("our sign response: %w", err))
		}
		res.sigInput, res.signature = headers.SignatureInput, headers.Signature
		if err := yaronf.VerifyResponse(sigLabel, *verifier, hResp, req); err != nil {
			return fail(res, fmt.Errorf("yaronf verify: %w", err))
		}
		return ok(res)
	}

	headers, err := signer.SignRequest(req)
	if err != nil {
		return fail(res, fmt.Errorf("our sign request: %w", err))
	}
	res.sigInput, res.signature = headers.SignatureInput, headers.Signature
	if err := yaronf.VerifyRequest(sigLabel, *verifier, req); err != nil {
		return fail(res, fmt.Errorf("yaronf verify: %w", err))
	}
	return ok(res)
}

func ok(r checkResult) checkResult {
	r.ok = true
	return r
}

func fail(r checkResult, err error) checkResult {
	r.ok = false
	r.errMsg = err.Error()
	return r
}
