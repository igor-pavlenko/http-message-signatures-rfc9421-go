package main

import (
	"fmt"

	yaronf "github.com/yaronf/httpsign"
)

// theirsNewSigner builds a yaronf/httpsign Signer for the given RFC 9421
// algorithm ID, mirroring the constructor pkg/signing.GetAlgorithm(algID)
// would select on our side.
func theirsNewSigner(algID string, cfg *yaronf.SignConfig, fields yaronf.Fields) (*yaronf.Signer, error) {
	switch algID {
	case "rsa-pss-sha512":
		return yaronf.NewRSAPSSSigner(*rsaPriv, cfg, fields)
	case "rsa-v1_5-sha256":
		return yaronf.NewRSASigner(*rsaPriv, cfg, fields)
	case "ecdsa-p256-sha256":
		return yaronf.NewP256Signer(*ecP256Priv, cfg, fields)
	case "ed25519":
		return yaronf.NewEd25519Signer(ed25519Sec, cfg, fields)
	case "hmac-sha256":
		return yaronf.NewHMACSHA256Signer(hmacKey, cfg, fields)
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algID)
	}
}

// theirsNewVerifier builds the matching yaronf/httpsign Verifier.
func theirsNewVerifier(algID string, cfg *yaronf.VerifyConfig, fields yaronf.Fields) (*yaronf.Verifier, error) {
	switch algID {
	case "rsa-pss-sha512":
		return yaronf.NewRSAPSSVerifier(*rsaPub, cfg, fields)
	case "rsa-v1_5-sha256":
		return yaronf.NewRSAVerifier(*rsaPub, cfg, fields)
	case "ecdsa-p256-sha256":
		return yaronf.NewP256Verifier(*ecP256Pub, cfg, fields)
	case "ed25519":
		return yaronf.NewEd25519Verifier(ed25519Pub, cfg, fields)
	case "hmac-sha256":
		return yaronf.NewHMACSHA256Verifier(hmacKey, cfg, fields)
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algID)
	}
}

// theirsFields translates a scenario's component list into yaronf/httpsign's
// Fields type: bare derived/header names go through AddHeaders, and
// @query-param components (identified by name) go through AddQueryParam.
func theirsFields(headers []string, queryParams []string) yaronf.Fields {
	fs := yaronf.NewFields()
	fs.AddHeaders(headers...)
	for _, qp := range queryParams {
		fs.AddQueryParam(qp)
	}
	return *fs
}
