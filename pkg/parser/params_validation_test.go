package parser

import (
	"strings"
	"testing"
	"time"
)

func TestValidateSignatureParams(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	createdNew := now.Add(6 * time.Second).Unix()
	createdOld := now.Add(-11 * time.Second).Unix()
	createdOK := now.Add(-9 * time.Second).Unix()
	expiresBeforeCreated := now.Add(-20 * time.Second).Unix()
	expiresPast := now.Add(-1 * time.Second).Unix()
	expiresFuture := now.Add(1 * time.Second).Unix()

	tests := []struct {
		name          string
		params        SignatureParams
		opts          SignatureParamsValidationOptions
		wantErrSubstr string
	}{
		{
			name:   "no options",
			params: SignatureParams{},
		},
		{
			name:          "require created missing",
			params:        SignatureParams{},
			opts:          SignatureParamsValidationOptions{RequireCreated: true},
			wantErrSubstr: "missing \"created\" parameter",
		},
		{
			name:          "created window requires created",
			params:        SignatureParams{},
			opts:          SignatureParamsValidationOptions{CreatedNotOlderThan: 1 * time.Second},
			wantErrSubstr: "missing \"created\" parameter",
		},
		{
			name:          "require expires missing",
			params:        SignatureParams{},
			opts:          SignatureParamsValidationOptions{RequireExpires: true},
			wantErrSubstr: "missing \"expires\" parameter",
		},
		{
			name:   "created too new",
			params: SignatureParams{Created: &createdNew},
			opts: SignatureParamsValidationOptions{
				Now:                 now,
				CreatedNotNewerThan: 5 * time.Second,
			},
			wantErrSubstr: "created time is too far in the future",
		},
		{
			name:   "created too old",
			params: SignatureParams{Created: &createdOld},
			opts: SignatureParamsValidationOptions{
				Now:                 now,
				CreatedNotOlderThan: 10 * time.Second,
			},
			wantErrSubstr: "created time is too old",
		},
		{
			name:   "created within window",
			params: SignatureParams{Created: &createdOK},
			opts: SignatureParamsValidationOptions{
				Now:                 now,
				CreatedNotOlderThan: 10 * time.Second,
			},
		},
		{
			name:   "expires in past",
			params: SignatureParams{Expires: &expiresPast},
			opts: SignatureParamsValidationOptions{
				Now:           now,
				RejectExpired: true,
			},
			wantErrSubstr: "signature is expired",
		},
		{
			name:   "expires in future",
			params: SignatureParams{Expires: &expiresFuture},
			opts: SignatureParamsValidationOptions{
				Now:           now,
				RejectExpired: true,
			},
		},
		{
			name: "expires before created",
			params: SignatureParams{
				Created: &createdOK,
				Expires: &expiresBeforeCreated,
			},
			opts:          SignatureParamsValidationOptions{ExpiresNotBeforeCreated: true},
			wantErrSubstr: "expires time is before created time",
		},
		{
			name:   "expires before created without created",
			params: SignatureParams{Expires: &expiresPast},
			opts:   SignatureParamsValidationOptions{ExpiresNotBeforeCreated: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSignatureParams(tt.params, tt.opts)
			if tt.wantErrSubstr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErrSubstr)
			}
			if !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErrSubstr)
			}
		})
	}
}
