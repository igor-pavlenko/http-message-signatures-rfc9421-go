package parser

import (
	"fmt"
	"time"
)

// SignatureParamsValidationOptions controls validation of signature parameters.
// These checks correspond to RFC 9421 Section 3.2.1 application requirements.
type SignatureParamsValidationOptions struct {
	// Now is the time used for validation. If zero, time.Now() is used.
	Now time.Time

	// RequireCreated enforces presence of the created parameter.
	RequireCreated bool

	// RequireExpires enforces presence of the expires parameter.
	RequireExpires bool

	// CreatedNotNewerThan is the allowed future skew for created.
	CreatedNotNewerThan time.Duration

	// CreatedNotOlderThan is the maximum allowed age for created.
	CreatedNotOlderThan time.Duration

	// RejectExpired rejects signatures with expires in the past.
	RejectExpired bool

	// ExpiresNotBeforeCreated enforces expires >= created when both are present.
	ExpiresNotBeforeCreated bool
}

// ValidateSignatureParams validates created/expires parameters using the provided options.
func ValidateSignatureParams(params SignatureParams, opts SignatureParamsValidationOptions) error {
	if opts.CreatedNotNewerThan < 0 {
		return fmt.Errorf("created not-newer-than must be >= 0")
	}
	if opts.CreatedNotOlderThan < 0 {
		return fmt.Errorf("created not-older-than must be >= 0")
	}

	needsCreated := opts.RequireCreated || opts.CreatedNotNewerThan > 0 || opts.CreatedNotOlderThan > 0
	needsNow := opts.CreatedNotNewerThan > 0 || opts.CreatedNotOlderThan > 0 || opts.RejectExpired

	var now time.Time
	if needsNow {
		now = opts.Now
		if now.IsZero() {
			now = time.Now()
		}
	}

	var createdTime time.Time
	if params.Created == nil {
		if needsCreated {
			return fmt.Errorf("missing \"created\" parameter")
		}
	} else {
		createdTime = time.Unix(*params.Created, 0)
		if opts.CreatedNotNewerThan > 0 && createdTime.After(now.Add(opts.CreatedNotNewerThan)) {
			return fmt.Errorf("created time is too far in the future")
		}
		if opts.CreatedNotOlderThan > 0 && createdTime.Add(opts.CreatedNotOlderThan).Before(now) {
			return fmt.Errorf("created time is too old")
		}
	}

	if params.Expires == nil {
		if opts.RequireExpires {
			return fmt.Errorf("missing \"expires\" parameter")
		}
	} else {
		expiresTime := time.Unix(*params.Expires, 0)
		if opts.RejectExpired && now.After(expiresTime) {
			return fmt.Errorf("signature is expired")
		}
		if opts.ExpiresNotBeforeCreated && params.Created != nil && expiresTime.Before(createdTime) {
			return fmt.Errorf("expires time is before created time")
		}
	}

	return nil
}
