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

	now := resolveValidationNow(opts)

	createdTime, err := validateCreatedParam(params, opts, now)
	if err != nil {
		return err
	}

	return validateExpiresParam(params, opts, now, createdTime)
}

// resolveValidationNow returns the reference time for validation, defaulting
// to time.Now() when opts.Now is unset and a time reference is actually needed.
func resolveValidationNow(opts SignatureParamsValidationOptions) time.Time {
	needsNow := opts.CreatedNotNewerThan > 0 || opts.CreatedNotOlderThan > 0 || opts.RejectExpired
	if !needsNow {
		return time.Time{}
	}
	if !opts.Now.IsZero() {
		return opts.Now
	}
	return time.Now()
}

// validateCreatedParam validates the "created" parameter and returns its
// parsed time (zero if absent) for use by validateExpiresParam.
func validateCreatedParam(params SignatureParams, opts SignatureParamsValidationOptions, now time.Time) (time.Time, error) {
	if params.Created == nil {
		needsCreated := opts.RequireCreated || opts.CreatedNotNewerThan > 0 || opts.CreatedNotOlderThan > 0
		if needsCreated {
			return time.Time{}, fmt.Errorf("missing \"created\" parameter")
		}
		return time.Time{}, nil
	}

	createdTime := time.Unix(*params.Created, 0)
	if opts.CreatedNotNewerThan > 0 && createdTime.After(now.Add(opts.CreatedNotNewerThan)) {
		return time.Time{}, fmt.Errorf("created time is too far in the future")
	}
	if opts.CreatedNotOlderThan > 0 && createdTime.Add(opts.CreatedNotOlderThan).Before(now) {
		return time.Time{}, fmt.Errorf("created time is too old")
	}
	return createdTime, nil
}

// validateExpiresParam validates the "expires" parameter against now and,
// optionally, the already-validated created time.
func validateExpiresParam(params SignatureParams, opts SignatureParamsValidationOptions, now, createdTime time.Time) error {
	if params.Expires == nil {
		if opts.RequireExpires {
			return fmt.Errorf("missing \"expires\" parameter")
		}
		return nil
	}

	expiresTime := time.Unix(*params.Expires, 0)
	if opts.RejectExpired && now.After(expiresTime) {
		return fmt.Errorf("signature is expired")
	}
	if opts.ExpiresNotBeforeCreated && params.Created != nil && expiresTime.Before(createdTime) {
		return fmt.Errorf("expires time is before created time")
	}
	return nil
}
