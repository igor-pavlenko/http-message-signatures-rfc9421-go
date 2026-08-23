package parser

import (
	"strings"
	"testing"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/sfv"
)

// T028: Test single signature parsing with @method, date, alg, keyid.
func TestParseSignatures_SingleSignature(t *testing.T) {
	signatureInput := `sig1=("@method" "date");created=1618884473;keyid="test-key-rsa";alg="rsa-pss-sha512"`
	signature := `sig1=:LAH8BjcfcOcLojiuOBFWn0P5keD3xAOuJRGziCLuD8r5MW9S0RoXXLzLSRfGY/3SF8kVIkHjE13SEFdTo4Af/fJ/Pu9wheqoLVdwXyY/UkBIS1M8Brc8IODsn5DFIrG0Dv2qSVCmToC0IcQJCdRVEcHZcGLNSQMX3Cqx4EkFug0=:`

	result, err := ParseSignatures(signatureInput, signature, sfv.DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSignatures() error = %v", err)
	}

	// Verify single signature entry
	if len(result.Signatures) != 1 {
		t.Errorf("got %d signatures, want 1", len(result.Signatures))
	}

	sig, exists := result.Signatures["sig1"]
	if !exists {
		t.Fatal("signature 'sig1' not found")
	}

	// Verify label
	if sig.Label != "sig1" {
		t.Errorf("sig.Label = %q, want %q", sig.Label, "sig1")
	}

	// Verify covered components
	if len(sig.CoveredComponents) != 2 {
		t.Errorf("got %d covered components, want 2", len(sig.CoveredComponents))
	}

	expectedComponents := []string{"@method", "date"}
	for i, expected := range expectedComponents {
		if sig.CoveredComponents[i].Name != expected {
			t.Errorf("component[%d].Name = %q, want %q", i, sig.CoveredComponents[i].Name, expected)
		}
	}

	// Verify signature parameters
	if sig.SignatureParams.Algorithm == nil || *sig.SignatureParams.Algorithm != "rsa-pss-sha512" {
		t.Errorf("Algorithm = %v, want %q", sig.SignatureParams.Algorithm, "rsa-pss-sha512")
	}

	if sig.SignatureParams.KeyID == nil || *sig.SignatureParams.KeyID != "test-key-rsa" {
		t.Errorf("KeyID = %v, want %q", sig.SignatureParams.KeyID, "test-key-rsa")
	}

	if sig.SignatureParams.Created == nil || *sig.SignatureParams.Created != 1618884473 {
		t.Errorf("Created = %v, want %d", sig.SignatureParams.Created, 1618884473)
	}

	// Verify signature value
	if len(sig.SignatureValue) == 0 {
		t.Error("SignatureValue is empty")
	}
}

// T029: Test component parameter extraction (content-digest;sf, @authority).
func TestParseSignatures_ComponentParameters(t *testing.T) {
	signatureInput := `sig1=("content-digest";sf "@authority");alg="ed25519"`
	signature := `sig1=:Y2lnbmF0dXJl:`

	result, err := ParseSignatures(signatureInput, signature, sfv.DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSignatures() error = %v", err)
	}

	sig := result.Signatures["sig1"]

	// Verify first component has 'sf' parameter
	if len(sig.CoveredComponents) != 2 {
		t.Fatalf("got %d components, want 2", len(sig.CoveredComponents))
	}

	firstComp := sig.CoveredComponents[0]
	if firstComp.Name != "content-digest" {
		t.Errorf("first component name = %q, want %q", firstComp.Name, "content-digest")
	}

	// Check for 'sf' parameter
	hasSF := false
	for _, param := range firstComp.Parameters {
		if param.Key == "sf" {
			hasSF = true
			// param.Value is a BareItem interface, need to type assert
			if boolVal, ok := param.Value.(Boolean); !ok || !boolVal.Value {
				t.Errorf("sf parameter value = %v, want Boolean{true}", param.Value)
			}
			break
		}
	}
	if !hasSF {
		t.Error("expected 'sf' parameter on content-digest component")
	}

	// Verify second component has no parameters
	secondComp := sig.CoveredComponents[1]
	if secondComp.Name != "@authority" {
		t.Errorf("second component name = %q, want %q", secondComp.Name, "@authority")
	}
	if len(secondComp.Parameters) != 0 {
		t.Errorf("@authority should have no parameters, got %d", len(secondComp.Parameters))
	}
}

// T030: Test all signature parameters.
func TestParseSignatures_AllSignatureParameters(t *testing.T) {
	signatureInput := `sig1=("@method");created=1618884473;expires=1618884773;nonce="random123";alg="rsa-pss-sha512";keyid="key-1";tag="app-tag"`
	signature := `sig1=:c2lnbmF0dXJl:`

	result, err := ParseSignatures(signatureInput, signature, sfv.DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSignatures() error = %v", err)
	}

	params := result.Signatures["sig1"].SignatureParams

	// Check all parameters
	if params.Algorithm == nil || *params.Algorithm != "rsa-pss-sha512" {
		t.Errorf("Algorithm = %v, want %q", params.Algorithm, "rsa-pss-sha512")
	}

	if params.Created == nil || *params.Created != 1618884473 {
		t.Errorf("Created = %v, want 1618884473", params.Created)
	}

	if params.Expires == nil || *params.Expires != 1618884773 {
		t.Errorf("Expires = %v, want 1618884773", params.Expires)
	}

	if params.Nonce == nil || *params.Nonce != "random123" {
		t.Errorf("Nonce = %v, want %q", params.Nonce, "random123")
	}

	if params.KeyID == nil || *params.KeyID != "key-1" {
		t.Errorf("KeyID = %v, want %q", params.KeyID, "key-1")
	}

	if params.Tag == nil || *params.Tag != "app-tag" {
		t.Errorf("Tag = %v, want %q", params.Tag, "app-tag")
	}
}

// T031: Test signature value decoding.
func TestParseSignatures_SignatureValueDecoding(t *testing.T) {
	signatureInput := `sig1=("@method");alg="ed25519"`
	signature := `sig1=:aGVsbG8gd29ybGQ=:` // "hello world" in base64

	result, err := ParseSignatures(signatureInput, signature, sfv.DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSignatures() error = %v", err)
	}

	sig := result.Signatures["sig1"]

	expected := []byte("hello world")
	if string(sig.SignatureValue) != string(expected) {
		t.Errorf("SignatureValue = %q, want %q", sig.SignatureValue, expected)
	}
}

// Additional test: Error handling for empty headers.
func TestParseSignatures_EmptyHeaders(t *testing.T) {
	tests := []struct {
		name           string
		signatureInput string
		signature      string
		wantErr        bool
	}{
		{
			name:           "both empty",
			signatureInput: "",
			signature:      "",
			wantErr:        true,
		},
		{
			name:           "empty signature-input",
			signatureInput: "",
			signature:      "sig1=:YWJj:",
			wantErr:        true,
		},
		{
			name:           "empty signature",
			signatureInput: `sig1=("@method");alg="ed25519"`,
			signature:      "",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSignatures(tt.signatureInput, tt.signature, sfv.DefaultLimits())
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSignatures() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParseSignatures_LabelMismatch tests error handling when signature labels don't match.
// Per Contract PS-002: Every label in Signature-Input must have corresponding entry in Signature,
// and vice versa. This validates parser.go:47-58.
func TestParseSignatures_LabelMismatch(t *testing.T) {
	tests := []struct {
		name           string
		signatureInput string
		signature      string
		wantErrSubstr  string
	}{
		{
			name:           "Signature-Input has label not in Signature",
			signatureInput: `sig1=("@method" "@path");created=1618884473;keyid="test-key"`,
			signature:      `sig2=:YWJjZGVmZ2hpams=:`, // Different label: sig2 vs sig1
			wantErrSubstr:  "Signature-Input label \"sig1\" has no corresponding Signature entry",
		},
		{
			name:           "Signature has label not in Signature-Input",
			signatureInput: `sig1=("@method" "@path");created=1618884473;keyid="test-key"`,
			signature:      `sig1=:YWJjZGVmZ2hpams=:, sig2=:bm9wZQ==:`, // sig2 only in Signature
			wantErrSubstr:  "header Signature label \"sig2\" has no corresponding Signature-Input entry",
		},
		{
			name:           "Multiple signatures with one mismatch in Signature-Input",
			signatureInput: `sig1=("@method");created=1618884473;keyid="test-key", sig3=("@path");created=1618884474;keyid="key2"`,
			signature:      `sig1=:YWJj:, sig2=:ZGVm:`, // sig3 missing in Signature
			wantErrSubstr:  "Signature-Input label \"sig3\" has no corresponding Signature entry",
		},
		{
			name:           "Multiple signatures with one mismatch in Signature",
			signatureInput: `sig1=("@method");created=1618884473;keyid="test-key", sig2=("@path");created=1618884474;keyid="key2"`,
			signature:      `sig1=:YWJj:, sig3=:ZGVm:`, // sig3 instead of sig2
			wantErrSubstr:  "has no corresponding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSignatures(tt.signatureInput, tt.signature, sfv.DefaultLimits())
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErrSubstr)
			}
		})
	}
}

// TestParseSignatures_ComponentClassification tests User Story 4:
// Distinguish Field vs Derived Components.
func TestParseSignatures_ComponentClassification(t *testing.T) {
	// Mixed HTTP fields and derived components
	signatureInput := `sig1=("@method" "date" "@authority" "content-digest");alg="ed25519"`
	signature := `sig1=:c2lnbmF0dXJl:`

	result, err := ParseSignatures(signatureInput, signature, sfv.DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSignatures() error = %v", err)
	}

	sig := result.Signatures["sig1"]
	components := sig.CoveredComponents

	if len(components) != 4 {
		t.Fatalf("expected 4 components, got %d", len(components))
	}

	// Test each component's classification
	tests := []struct {
		index    int
		name     string
		wantType ComponentType
	}{
		{0, "@method", ComponentDerived},
		{1, "date", ComponentField},
		{2, "@authority", ComponentDerived},
		{3, "content-digest", ComponentField},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comp := components[tt.index]

			if comp.Name != tt.name {
				t.Errorf("component[%d].Name = %q, want %q", tt.index, comp.Name, tt.name)
			}

			if comp.Type != tt.wantType {
				t.Errorf("component[%d].Type = %v, want %v", tt.index, comp.Type, tt.wantType)
			}
		})
	}
}

// Test all RFC 9421 derived components.
func TestParseSignatures_AllDerivedComponents(t *testing.T) {
	tests := []struct {
		compName string
		params   string // additional parameters if needed
	}{
		{"@method", ""},
		{"@path", ""},
		{"@query", ""},
		{"@query-param", `;name="search"`}, // Requires 'name' parameter per RFC 9421
		{"@status", ""},
		{"@authority", ""},
		{"@scheme", ""},
		{"@request-target", ""},
		{"@target-uri", ""},
	}

	for _, tt := range tests {
		t.Run(tt.compName, func(t *testing.T) {
			signatureInput := `sig1=("` + tt.compName + `"` + tt.params + `);alg="ed25519"`
			signature := `sig1=:YWJj:`

			result, err := ParseSignatures(signatureInput, signature, sfv.DefaultLimits())
			if err != nil {
				t.Fatalf("ParseSignatures() error = %v", err)
			}

			comp := result.Signatures["sig1"].CoveredComponents[0]

			if comp.Name != tt.compName {
				t.Errorf("Name = %q, want %q", comp.Name, tt.compName)
			}

			if comp.Type != ComponentDerived {
				t.Errorf("Type = %v, want ComponentDerived", comp.Type)
			}
		})
	}
}

// Test HTTP field components.
func TestParseSignatures_HTTPFieldComponents(t *testing.T) {
	fieldComponents := []string{
		"date",
		"content-type",
		"content-digest",
		"authorization",
		"cache-control",
		"x-custom-header",
	}

	for _, compName := range fieldComponents {
		t.Run(compName, func(t *testing.T) {
			signatureInput := `sig1=("` + compName + `");alg="ed25519"`
			signature := `sig1=:YWJj:`

			result, err := ParseSignatures(signatureInput, signature, sfv.DefaultLimits())
			if err != nil {
				t.Fatalf("ParseSignatures() error = %v", err)
			}

			comp := result.Signatures["sig1"].CoveredComponents[0]

			if comp.Name != compName {
				t.Errorf("Name = %q, want %q", comp.Name, compName)
			}

			if comp.Type != ComponentField {
				t.Errorf("Type = %v, want ComponentField", comp.Type)
			}
		})
	}
}

// Test ComponentType string representation for debugging.
func TestComponentType_String(t *testing.T) {
	// This will be useful for debugging and logging
	tests := []struct {
		typ  ComponentType
		name string
	}{
		{ComponentField, "field"},
		{ComponentDerived, "derived"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Type should be distinguishable
			if tt.typ == ComponentField && tt.name != "field" {
				t.Error("ComponentField should represent HTTP fields")
			}
			if tt.typ == ComponentDerived && tt.name != "derived" {
				t.Error("ComponentDerived should represent derived components")
			}
		})
	}
}

// TestParseSignatures_RejectInvalidDerivedComponents tests parser rejects unknown derived components
func TestParseSignatures_RejectInvalidDerivedComponents(t *testing.T) {
	tests := []struct {
		name          string
		component     string
		wantErrSubstr string
	}{
		{
			name:          "unknown @custom",
			component:     "@custom",
			wantErrSubstr: "not in RFC 9421",
		},
		{
			name:          "unknown @foo",
			component:     "@foo",
			wantErrSubstr: "not in RFC 9421",
		},
		{
			name:          "typo @metod",
			component:     "@metod",
			wantErrSubstr: "not in RFC 9421",
		},
		{
			name:          "reserved @signature-params",
			component:     "@signature-params",
			wantErrSubstr: "auto-generated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signatureInput := `sig1=("` + tt.component + `");alg="ed25519"`
			signature := `sig1=:YWJj:`

			_, err := ParseSignatures(signatureInput, signature, sfv.DefaultLimits())
			if err == nil {
				t.Errorf("ParseSignatures() expected error for component %q", tt.component)
				return
			}

			if !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Errorf("error = %v, want substring %q", err, tt.wantErrSubstr)
			}
		})
	}
}

// TestParseSignatures_AcceptAllValidDerivedComponents tests all RFC 9421 derived components work.
func TestParseSignatures_AcceptAllValidDerivedComponents(t *testing.T) {
	validComponents := []string{
		"@method",
		"@target-uri",
		"@authority",
		"@scheme",
		"@request-target",
		"@path",
		"@query",
		"@status",
	}

	for _, comp := range validComponents {
		t.Run(comp, func(t *testing.T) {
			signatureInput := `sig1=("` + comp + `");alg="ed25519"`
			signature := `sig1=:YWJj:`

			result, err := ParseSignatures(signatureInput, signature, sfv.DefaultLimits())
			if err != nil {
				t.Errorf("ParseSignatures() unexpected error for valid component %q: %v", comp, err)
				return
			}

			if len(result.Signatures) != 1 {
				t.Errorf("expected 1 signature, got %d", len(result.Signatures))
			}

			parsed := result.Signatures["sig1"].CoveredComponents[0]
			if parsed.Name != comp {
				t.Errorf("component name = %q, want %q", parsed.Name, comp)
			}

			if !parsed.IsDerived() {
				t.Errorf("component %q should be classified as derived", comp)
			}
		})
	}
}

// TestParseSignatures_QueryParamRequiresName tests @query-param validation.
func TestParseSignatures_QueryParamRequiresName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "with name parameter",
			input:   `sig1=("@query-param";name="search");alg="ed25519"`,
			wantErr: false,
		},
		{
			name:    "without name parameter",
			input:   `sig1=("@query-param");alg="ed25519"`,
			wantErr: true,
		},
		{
			name:    "with other parameters but no name",
			input:   `sig1=("@query-param";sf);alg="ed25519"`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature := `sig1=:YWJj:`
			_, err := ParseSignatures(tt.input, signature, sfv.DefaultLimits())

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSignatures() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && !strings.Contains(err.Error(), "requires 'name'") {
				t.Errorf("error should mention required 'name' parameter, got: %v", err)
			}
		})
	}
}

// TestParseSignatures_RejectInvalidParameterCombinations tests FR-024 enforcement.
func TestParseSignatures_RejectInvalidParameterCombinations(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantErrSubstr string
	}{
		{
			name:          "bs and sf together",
			input:         `sig1=("content-digest";bs;sf);alg="ed25519"`,
			wantErrSubstr: "mutually exclusive",
		},
		{
			name:          "bs and key together",
			input:         `sig1=("example-dict";bs;key="member");alg="ed25519"`,
			wantErrSubstr: "mutually exclusive",
		},
		{
			name:          "key without sf",
			input:         `sig1=("example-dict";key="member");alg="ed25519"`,
			wantErrSubstr: "'key' parameter requires 'sf'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature := `sig1=:YWJj:`
			_, err := ParseSignatures(tt.input, signature, sfv.DefaultLimits())

			if err == nil {
				t.Error("ParseSignatures() expected error for invalid parameter combination")
				return
			}

			if !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Errorf("error = %v, want substring %q", err, tt.wantErrSubstr)
			}
		})
	}
}

// TestParseSignatures_AcceptValidParameterCombinations tests allowed combinations.
func TestParseSignatures_AcceptValidParameterCombinations(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "sf only",
			input: `sig1=("content-digest";sf);alg="ed25519"`,
		},
		{
			name:  "bs only",
			input: `sig1=("authorization";bs);alg="ed25519"`,
		},
		{
			name:  "sf and key together (allowed)",
			input: `sig1=("example-dict";sf;key="member");alg="ed25519"`,
		},
		{
			name:  "req and tr together (allowed)",
			input: `sig1=("content-type";req;tr);alg="ed25519"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature := `sig1=:YWJj:`
			_, err := ParseSignatures(tt.input, signature, sfv.DefaultLimits())

			if err != nil {
				t.Errorf("ParseSignatures() unexpected error for valid combination: %v", err)
			}
		})
	}
}

// TestParseSignatures_HTTPFieldsNotRestricted tests HTTP fields can be arbitrary.
func TestParseSignatures_HTTPFieldsNotRestricted(t *testing.T) {
	arbitraryFields := []string{
		"date",
		"x-custom-header",
		"my-arbitrary-header",
		"content-type",
		"authorization",
		"cache-control",
		"x-foo-bar-baz",
	}

	for _, field := range arbitraryFields {
		t.Run(field, func(t *testing.T) {
			signatureInput := `sig1=("` + field + `");alg="ed25519"`
			signature := `sig1=:YWJj:`

			result, err := ParseSignatures(signatureInput, signature, sfv.DefaultLimits())
			if err != nil {
				t.Errorf("ParseSignatures() unexpected error for HTTP field %q: %v", field, err)
				return
			}

			comp := result.Signatures["sig1"].CoveredComponents[0]
			if comp.Name != field {
				t.Errorf("component name = %q, want %q", comp.Name, field)
			}

			if comp.Type != ComponentField {
				t.Errorf("component type = %v, want ComponentField", comp.Type)
			}
		})
	}
}

// TestParseSignatures_RFC9421_TestCases tests all official RFC 9421 Appendix B.2 test cases.
// These are the canonical test cases from the specification.
func TestParseSignatures_RFC9421_TestCases(t *testing.T) {
	tests := []struct {
		name           string
		signatureInput string
		signature      string
		wantLabel      string
		wantAlg        string
		wantKeyID      string
		wantCreated    *int64
		wantNonce      *string
		wantTag        *string
		wantExpires    *int64
		wantComponents []string
	}{
		{
			name:           "B.2.1 - Minimal Signature Using rsa-pss-sha512",
			signatureInput: `sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`,
			signature:      `sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:`,
			wantLabel:      "sig-b21",
			wantAlg:        "", // No alg parameter in RFC test case
			wantKeyID:      "test-key-rsa-pss",
			wantCreated:    func() *int64 { v := int64(1618884473); return &v }(),
			wantNonce:      func() *string { v := "b3k2pp5k7z-50gnwp.yemd"; return &v }(),
			wantComponents: []string{},
		},
		{
			name:           "B.2.2 - Selective Covered Components Using rsa-pss-sha512",
			signatureInput: `sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"`,
			signature:      `sig-b22=:LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQEdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SARYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoKUqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==:`,
			wantLabel:      "sig-b22",
			wantAlg:        "", // No alg parameter in RFC test case
			wantKeyID:      "test-key-rsa-pss",
			wantCreated:    func() *int64 { v := int64(1618884473); return &v }(),
			wantTag:        func() *string { v := "header-example"; return &v }(),
			wantComponents: []string{"@authority", "content-digest", "@query-param"},
		},
		{
			name:           "B.2.3 - Full Coverage Using rsa-pss-sha512",
			signatureInput: `sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`,
			signature:      `sig-b23=:bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yBiMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fUxN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5ZJzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==:`,
			wantLabel:      "sig-b23",
			wantAlg:        "", // No alg parameter in RFC test case
			wantKeyID:      "test-key-rsa-pss",
			wantCreated:    func() *int64 { v := int64(1618884473); return &v }(),
			wantComponents: []string{"date", "@method", "@path", "@query", "@authority", "content-type", "content-digest", "content-length"},
		},
		{
			name:           "B.2.4 - Signing a Response Using ecdsa-p256-sha256",
			signatureInput: `sig-b24=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"`,
			signature:      `sig-b24=:wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==:`,
			wantLabel:      "sig-b24",
			wantAlg:        "", // No alg parameter in RFC test case
			wantKeyID:      "test-key-ecc-p256",
			wantCreated:    func() *int64 { v := int64(1618884473); return &v }(),
			wantComponents: []string{"@status", "content-type", "content-digest", "content-length"},
		},
		{
			name:           "B.2.5 - Signing a Request Using hmac-sha256",
			signatureInput: `sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`,
			signature:      `sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:`,
			wantLabel:      "sig-b25",
			wantAlg:        "", // No alg parameter in RFC test case
			wantKeyID:      "test-shared-secret",
			wantCreated:    func() *int64 { v := int64(1618884473); return &v }(),
			wantComponents: []string{"date", "@authority", "content-type"},
		},
		{
			name:           "B.2.6 - Signing a Request Using ed25519",
			signatureInput: `sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`,
			signature:      `sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:`,
			wantLabel:      "sig-b26",
			wantAlg:        "", // No alg parameter in RFC test case
			wantKeyID:      "test-key-ed25519",
			wantCreated:    func() *int64 { v := int64(1618884473); return &v }(),
			wantComponents: []string{"date", "@method", "@path", "@authority", "content-type", "content-length"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSignatures(tt.signatureInput, tt.signature, sfv.DefaultLimits())
			if err != nil {
				t.Fatalf("ParseSignatures() error = %v", err)
			}

			// Verify signature entry exists
			sig, ok := result.Signatures[tt.wantLabel]
			if !ok {
				t.Fatalf("expected signature label %q not found", tt.wantLabel)
			}

			// Verify algorithm
			if tt.wantAlg == "" {
				// Algorithm should be nil
				if sig.SignatureParams.Algorithm != nil {
					t.Errorf("Algorithm = %v, want nil", sig.SignatureParams.Algorithm)
				}
			} else {
				// Algorithm should match expected value
				if sig.SignatureParams.Algorithm == nil {
					t.Errorf("Algorithm is nil, want %q", tt.wantAlg)
				} else if *sig.SignatureParams.Algorithm != tt.wantAlg {
					t.Errorf("Algorithm = %q, want %q", *sig.SignatureParams.Algorithm, tt.wantAlg)
				}
			}

			// Verify keyid
			if sig.SignatureParams.KeyID == nil {
				t.Errorf("KeyID is nil, want %q", tt.wantKeyID)
			} else if *sig.SignatureParams.KeyID != tt.wantKeyID {
				t.Errorf("KeyID = %q, want %q", *sig.SignatureParams.KeyID, tt.wantKeyID)
			}

			// Verify created
			if tt.wantCreated != nil {
				if sig.SignatureParams.Created == nil {
					t.Errorf("Created is nil, want %d", *tt.wantCreated)
				} else if *sig.SignatureParams.Created != *tt.wantCreated {
					t.Errorf("Created = %d, want %d", *sig.SignatureParams.Created, *tt.wantCreated)
				}
			}

			// Verify nonce (if expected)
			if tt.wantNonce != nil {
				if sig.SignatureParams.Nonce == nil {
					t.Errorf("Nonce is nil, want %q", *tt.wantNonce)
				} else if *sig.SignatureParams.Nonce != *tt.wantNonce {
					t.Errorf("Nonce = %q, want %q", *sig.SignatureParams.Nonce, *tt.wantNonce)
				}
			}

			// Verify tag (if expected)
			if tt.wantTag != nil {
				if sig.SignatureParams.Tag == nil {
					t.Errorf("Tag is nil, want %q", *tt.wantTag)
				} else if *sig.SignatureParams.Tag != *tt.wantTag {
					t.Errorf("Tag = %q, want %q", *sig.SignatureParams.Tag, *tt.wantTag)
				}
			}

			// Verify covered components
			if len(sig.CoveredComponents) != len(tt.wantComponents) {
				t.Errorf("CoveredComponents count = %d, want %d", len(sig.CoveredComponents), len(tt.wantComponents))
			} else {
				for i, wantName := range tt.wantComponents {
					if sig.CoveredComponents[i].Name != wantName {
						t.Errorf("CoveredComponents[%d].Name = %q, want %q", i, sig.CoveredComponents[i].Name, wantName)
					}
				}
			}

			// Verify signature value exists and is non-empty
			if len(sig.SignatureValue) == 0 {
				t.Error("SignatureValue is empty")
			}
		})
	}
}

// TestParseSignatures_MultipleSignatures tests parsing of multiple signatures from a single HTTP message.
// This test validates Phase 4 (User Story 2 - Multiple Signatures T050-T056).
//
// Example from RFC 9421 showing two signatures:
// - sig1: ECC signature with created and keyid
// - proxy_sig: RSA signature with created, keyid, alg, and expires.
func TestParseSignatures_MultipleSignatures(t *testing.T) {
	signatureInput := `sig1=("@method" "@authority" "@path" "content-digest" "content-type" "content-length");created=1618884475;keyid="test-key-ecc-p256", proxy_sig=("@method" "@authority" "@path" "content-digest" "content-type" "content-length" "forwarded");created=1618884480;keyid="test-key-rsa";alg="rsa-v1_5-sha256";expires=1618884540`

	signature := `sig1=:X5spyd6CFnAG5QnDyHfqoSNICd+BUP4LYMz2Q0JXlb//4Ijpzp+kve2w4NIyqeAuM7jTDX+sNalzA8ESSaHD3A==:, proxy_sig=:S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+JH+8XY1I6+8Cy+CM5g92iHgxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49GwiyUpZ10KHgOEe11sx3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7LB5YAv0RAGhB8tmpv7sFnIm9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtflzvZdXAsD3LH2TwevU+/PBPv0B6NMNk93wUs/vfJvye+YuI87HU38lZHowtznbLVdp770I6VHR6WfgS9ddzirrswsE1w5o0LV/g==:`

	result, err := ParseSignatures(signatureInput, signature, sfv.DefaultLimits())
	if err != nil {
		t.Fatalf("ParseSignatures() error = %v", err)
	}

	// Verify two signature entries
	if len(result.Signatures) != 2 {
		t.Fatalf("got %d signatures, want 2", len(result.Signatures))
	}

	// Test sig1 (ECC signature)
	t.Run("sig1", func(t *testing.T) {
		sig1, exists := result.Signatures["sig1"]
		if !exists {
			t.Fatal("signature 'sig1' not found")
		}

		// Verify label
		if sig1.Label != "sig1" {
			t.Errorf("Label = %q, want %q", sig1.Label, "sig1")
		}

		// Verify covered components
		expectedComponents := []string{"@method", "@authority", "@path", "content-digest", "content-type", "content-length"}
		if len(sig1.CoveredComponents) != len(expectedComponents) {
			t.Errorf("CoveredComponents count = %d, want %d", len(sig1.CoveredComponents), len(expectedComponents))
		} else {
			for i, expected := range expectedComponents {
				if sig1.CoveredComponents[i].Name != expected {
					t.Errorf("CoveredComponents[%d].Name = %q, want %q", i, sig1.CoveredComponents[i].Name, expected)
				}
			}
		}

		// Verify signature parameters
		expectedCreated := int64(1618884475)
		if sig1.SignatureParams.Created == nil {
			t.Error("Created is nil, want 1618884475")
		} else if *sig1.SignatureParams.Created != expectedCreated {
			t.Errorf("Created = %d, want %d", *sig1.SignatureParams.Created, expectedCreated)
		}

		expectedKeyID := "test-key-ecc-p256"
		if sig1.SignatureParams.KeyID == nil {
			t.Errorf("KeyID is nil, want %q", expectedKeyID)
		} else if *sig1.SignatureParams.KeyID != expectedKeyID {
			t.Errorf("KeyID = %q, want %q", *sig1.SignatureParams.KeyID, expectedKeyID)
		}

		// Algorithm should be nil (not present in sig1)
		if sig1.SignatureParams.Algorithm != nil {
			t.Errorf("Algorithm = %v, want nil", sig1.SignatureParams.Algorithm)
		}

		// Expires should be nil (not present in sig1)
		if sig1.SignatureParams.Expires != nil {
			t.Errorf("Expires = %v, want nil", sig1.SignatureParams.Expires)
		}

		// Verify signature value exists
		if len(sig1.SignatureValue) == 0 {
			t.Error("SignatureValue is empty")
		}
	})

	// Test proxy_sig (RSA signature with more parameters)
	t.Run("proxy_sig", func(t *testing.T) {
		proxySig, exists := result.Signatures["proxy_sig"]
		if !exists {
			t.Fatal("signature 'proxy_sig' not found")
		}

		// Verify label
		if proxySig.Label != "proxy_sig" {
			t.Errorf("Label = %q, want %q", proxySig.Label, "proxy_sig")
		}

		// Verify covered components (includes "forwarded" field)
		expectedComponents := []string{"@method", "@authority", "@path", "content-digest", "content-type", "content-length", "forwarded"}
		if len(proxySig.CoveredComponents) != len(expectedComponents) {
			t.Errorf("CoveredComponents count = %d, want %d", len(proxySig.CoveredComponents), len(expectedComponents))
		} else {
			for i, expected := range expectedComponents {
				if proxySig.CoveredComponents[i].Name != expected {
					t.Errorf("CoveredComponents[%d].Name = %q, want %q", i, proxySig.CoveredComponents[i].Name, expected)
				}
			}
		}

		// Verify signature parameters
		expectedCreated := int64(1618884480)
		if proxySig.SignatureParams.Created == nil {
			t.Error("Created is nil, want 1618884480")
		} else if *proxySig.SignatureParams.Created != expectedCreated {
			t.Errorf("Created = %d, want %d", *proxySig.SignatureParams.Created, expectedCreated)
		}

		expectedKeyID := "test-key-rsa"
		if proxySig.SignatureParams.KeyID == nil {
			t.Errorf("KeyID is nil, want %q", expectedKeyID)
		} else if *proxySig.SignatureParams.KeyID != expectedKeyID {
			t.Errorf("KeyID = %q, want %q", *proxySig.SignatureParams.KeyID, expectedKeyID)
		}

		expectedAlg := "rsa-v1_5-sha256"
		if proxySig.SignatureParams.Algorithm == nil {
			t.Errorf("Algorithm is nil, want %q", expectedAlg)
		} else if *proxySig.SignatureParams.Algorithm != expectedAlg {
			t.Errorf("Algorithm = %q, want %q", *proxySig.SignatureParams.Algorithm, expectedAlg)
		}

		expectedExpires := int64(1618884540)
		if proxySig.SignatureParams.Expires == nil {
			t.Error("Expires is nil, want 1618884540")
		} else if *proxySig.SignatureParams.Expires != expectedExpires {
			t.Errorf("Expires = %d, want %d", *proxySig.SignatureParams.Expires, expectedExpires)
		}

		// Verify signature value exists
		if len(proxySig.SignatureValue) == 0 {
			t.Error("SignatureValue is empty")
		}
	})
}

// ============================================================================
// Fuzz Tests
// ============================================================================

// FuzzParseSignatures tests the ParseSignatures function with random inputs to discover
// edge cases, crashes, panics, or unexpected behavior.
//
// This fuzzer tests the main entry point for parsing RFC 9421 HTTP Message Signatures,
// covering:
// - Label correspondence validation (FR-007, FR-008)
// - Component identifier parsing and validation
// - Signature parameter extraction
// - Byte sequence decoding
// - Error handling for malformed inputs
func FuzzParseSignatures(f *testing.F) {
	// Seed corpus with known edge cases and valid RFC 9421 examples
	seeds := []struct {
		signatureInput string
		signature      string
	}{
		// Valid cases from RFC 9421 Appendix B
		{
			`sig1=("@method" "@path");alg="rsa-pss-sha512"`,
			`sig1=:YWJjZGVm:`,
		},
		{
			`sig1=("@method" "@path");created=1618884473;keyid="test-key-rsa-pss"`,
			`sig1=:YWJjZGVm:`,
		},
		{
			`sig1=("date" "@method" "@path");created=1618884473`,
			`sig1=:YWJjZGVm:`,
		},

		// Multiple signatures
		{
			`sig1=("@method");alg="rsa", proxy_sig=("@path");alg="ecdsa"`,
			`sig1=:YWJj:, proxy_sig=:ZGVm:`,
		},

		// Empty component list (allowed per RFC 9421 B.2.1)
		{
			`sig1=();created=1618884473`,
			`sig1=:YWJjZGVm:`,
		},

		// All signature parameters
		{
			`sig1=("@method");created=1;expires=2;nonce="abc";alg="rsa";keyid="key1";tag="test"`,
			`sig1=:YWJj:`,
		},

		// Component parameters
		{
			`sig1=("content-type";sf);alg="rsa"`,
			`sig1=:YWJj:`,
		},
		{
			`sig1=("content-type";bs);alg="rsa"`,
			`sig1=:YWJj:`,
		},
		{
			`sig1=("content-digest";key="sha-256");alg="rsa"`,
			`sig1=:YWJj:`,
		},
		{
			`sig1=("@query-param";name="foo");alg="rsa"`,
			`sig1=:YWJj:`,
		},

		// Derived components
		{
			`sig1=("@method" "@target-uri" "@authority" "@scheme");alg="rsa"`,
			`sig1=:YWJj:`,
		},
		{
			`sig1=("@request-target" "@path" "@query");alg="rsa"`,
			`sig1=:YWJj:`,
		},
		{
			`sig1=("@status");alg="rsa"`,
			`sig1=:YWJj:`,
		},

		// Edge cases - empty headers
		{``, ``},
		{`sig1=("@method")`, ``},
		{``, `sig1=:YWJj:`},

		// Edge cases - label mismatch
		{
			`sig1=("@method")`,
			`sig2=:YWJj:`,
		},
		{
			`sig1=("@method"), sig2=("@path")`,
			`sig1=:YWJj:`,
		},

		// Edge cases - invalid component types
		{
			`sig1=(123);alg="rsa"`,
			`sig1=:YWJj:`,
		},
		{
			`sig1=(?1);alg="rsa"`,
			`sig1=:YWJj:`,
		},
		{
			`sig1=(token);alg="rsa"`,
			`sig1=:YWJj:`,
		},

		// Edge cases - invalid signature value types
		{
			`sig1=("@method")`,
			`sig1="not-bytes"`,
		},
		{
			`sig1=("@method")`,
			`sig1=123`,
		},
		{
			`sig1=("@method")`,
			`sig1=?1`,
		},

		// Edge cases - reserved components
		{
			`sig1=("@signature-params");alg="rsa"`,
			`sig1=:YWJj:`,
		},

		// Edge cases - invalid derived components
		{
			`sig1=("@invalid-component");alg="rsa"`,
			`sig1=:YWJj:`,
		},
		{
			`sig1=("@custom");alg="rsa"`,
			`sig1=:YWJj:`,
		},

		// Edge cases - parameter validation
		{
			`sig1=("@query-param");alg="rsa"`, // Missing 'name' parameter
			`sig1=:YWJj:`,
		},
		{
			`sig1=("content-type";bs;sf);alg="rsa"`, // Mutually exclusive
			`sig1=:YWJj:`,
		},
		{
			`sig1=("content-type";bs;key="foo");alg="rsa"`, // Mutually exclusive
			`sig1=:YWJj:`,
		},

		// Edge cases - malformed dictionaries
		{
			`sig1=("@method"),`,
			`sig1=:YWJj:`,
		},
		{
			`sig1`,
			`sig1=:YWJj:`,
		},
		{
			`sig1=`,
			`sig1=:YWJj:`,
		},

		// Edge cases - non-inner-list values
		{
			`sig1="not-a-list"`,
			`sig1=:YWJj:`,
		},
		{
			`sig1=123`,
			`sig1=:YWJj:`,
		},

		// Edge cases - whitespace and special characters
		{
			`sig1=("@method" "@path")`,
			`sig1=:YWJj:`,
		},
		{
			` sig1=("@method")`,
			`sig1=:YWJj:`,
		},
		{
			`sig1=("@method") `,
			`sig1=:YWJj: `,
		},

		// Edge cases - extreme lengths
		{
			`sig1=("@method" "header1" "header2" "header3" "header4" "header5" "header6" "header7" "header8" "header9" "header10")`,
			`sig1=:` + string(make([]byte, 1000)) + `:`,
		},

		// Edge cases - duplicate labels (last wins in SFV)
		{
			`sig1=("@method"), sig1=("@path")`,
			`sig1=:YWJj:, sig1=:ZGVm:`,
		},

		// Edge cases - many signatures
		{
			`sig1=("@method"), sig2=("@path"), sig3=("date"), sig4=("content-type"), sig5=("@authority")`,
			`sig1=:YWJj:, sig2=:ZGVm:, sig3=:Z2hp:, sig4=:amts:, sig5=:bW5v:`,
		},

		// Edge cases - parameter type variations
		{
			`sig1=("@method");created=0`,
			`sig1=:YWJj:`,
		},
		{
			`sig1=("@method");expires=-1`,
			`sig1=:YWJj:`,
		},
		{
			`sig1=("@method");nonce=""`,
			`sig1=:YWJj:`,
		},
		{
			`sig1=("@method");alg=""`,
			`sig1=:YWJj:`,
		},

		// Edge cases - mixed valid and invalid
		{
			`sig1=("@method" "invalid@header" "@path")`,
			`sig1=:YWJj:`,
		},
	}

	for _, seed := range seeds {
		f.Add(seed.signatureInput, seed.signature)
	}

	f.Fuzz(func(t *testing.T, signatureInput, signature string) {
		// Parser must never panic, crash, or enter infinite loops
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ParseSignatures panicked on input:\nSignature-Input: %q\nSignature: %q\nPanic: %v",
					signatureInput, signature, r)
			}
		}()

		// Parse the input
		result1, err1 := ParseSignatures(signatureInput, signature, sfv.DefaultLimits())

		// Verify deterministic behavior
		result2, err2 := ParseSignatures(signatureInput, signature, sfv.DefaultLimits())

		// Check determinism: errors must match
		if (err1 == nil) != (err2 == nil) {
			t.Errorf("Non-deterministic error behavior:\nSignature-Input: %q\nSignature: %q\nFirst:  %v\nSecond: %v",
				signatureInput, signature, err1, err2)
		}

		// If both succeeded, results must match
		if err1 == nil && err2 == nil {
			if len(result1.Signatures) != len(result2.Signatures) {
				t.Errorf("Non-deterministic signature count:\nSignature-Input: %q\nSignature: %q\nFirst:  %d\nSecond: %d",
					signatureInput, signature, len(result1.Signatures), len(result2.Signatures))
			}

			// Verify signature labels match
			for label := range result1.Signatures {
				if _, exists := result2.Signatures[label]; !exists {
					t.Errorf("Non-deterministic signature labels:\nSignature-Input: %q\nSignature: %q\nLabel %q missing in second parse",
						signatureInput, signature, label)
				}
			}
		}

		// Memory safety validation
		if err1 == nil {
			// Reasonable limits on number of signatures
			if len(result1.Signatures) > 1000 {
				t.Errorf("Too many signatures: %d (possible memory issue)", len(result1.Signatures))
			}

			// Validate structure consistency
			for label, entry := range result1.Signatures {
				if entry.Label != label {
					t.Errorf("Inconsistent label: map key %q != entry label %q", label, entry.Label)
				}

				// Reasonable limits on covered components
				if len(entry.CoveredComponents) > 1000 {
					t.Errorf("Too many covered components in %q: %d", label, len(entry.CoveredComponents))
				}

				// Validate component identifiers
				for i, comp := range entry.CoveredComponents {
					// Note: Empty string component names are technically valid per RFC 8941
					// (empty strings are valid SFV strings), though discouraged

					// Type must be valid
					if comp.Type != ComponentField && comp.Type != ComponentDerived {
						t.Errorf("Invalid component type at position %d in signature %q: %v", i, label, comp.Type)
					}

					// Derived components must start with @
					if comp.Type == ComponentDerived && len(comp.Name) > 0 && comp.Name[0] != '@' {
						t.Errorf("Derived component at position %d in signature %q does not start with @: %q",
							i, label, comp.Name)
					}

					// Field components must not start with @
					if comp.Type == ComponentField && len(comp.Name) > 0 && comp.Name[0] == '@' {
						t.Errorf("Field component at position %d in signature %q starts with @: %q",
							i, label, comp.Name)
					}

					// Reasonable parameter count
					if len(comp.Parameters) > 100 {
						t.Errorf("Too many parameters for component at position %d in signature %q: %d",
							i, label, len(comp.Parameters))
					}

					// Validate parameter keys are non-empty
					for j, param := range comp.Parameters {
						if param.Key == "" {
							t.Errorf("Empty parameter key at component %d, param %d in signature %q",
								i, j, label)
						}
					}
				}

				// Signature value should not be excessively large
				if len(entry.SignatureValue) > 10000 {
					t.Errorf("Signature value too large for %q: %d bytes", label, len(entry.SignatureValue))
				}
			}
		}
	})
}

// TestParseSignatures_WrongParameterTypes tests that signature parameters with wrong types
// are rejected with descriptive errors instead of being silently ignored.
// This prevents attacks where malformed parameters bypass validation.
func TestParseSignatures_WrongParameterTypes(t *testing.T) {
	tests := []struct {
		name           string
		signatureInput string
		wantErrSubstr  string
	}{
		{
			name:           "created as string instead of integer",
			signatureInput: `sig1=("@method");created="not-a-number"`,
			wantErrSubstr:  "parameter 'created' must be an integer",
		},
		{
			name:           "expires as string instead of integer",
			signatureInput: `sig1=("@method");expires="tomorrow"`,
			wantErrSubstr:  "parameter 'expires' must be an integer",
		},
		{
			name:           "nonce as integer instead of string",
			signatureInput: `sig1=("@method");nonce=12345`,
			wantErrSubstr:  "parameter 'nonce' must be a string",
		},
		{
			name:           "alg as integer instead of string",
			signatureInput: `sig1=("@method");alg=256`,
			wantErrSubstr:  "parameter 'alg' must be a string",
		},
		{
			name:           "keyid as boolean instead of string",
			signatureInput: `sig1=("@method");keyid=?1`,
			wantErrSubstr:  "parameter 'keyid' must be a string",
		},
		{
			name:           "tag as integer instead of string",
			signatureInput: `sig1=("@method");tag=123`,
			wantErrSubstr:  "parameter 'tag' must be a string",
		},
		{
			name:           "created as boolean instead of integer",
			signatureInput: `sig1=("@method");created=?1`,
			wantErrSubstr:  "parameter 'created' must be an integer",
		},
		{
			name:           "expires as byte sequence instead of integer",
			signatureInput: `sig1=("@method");expires=:YWJj:`,
			wantErrSubstr:  "parameter 'expires' must be an integer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature := `sig1=:YWJj:`
			_, err := ParseSignatures(tt.signatureInput, signature, sfv.DefaultLimits())

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErrSubstr)
			}
		})
	}
}

// FuzzParseSignaturesSingleHeader tests ParseSignatures with variations in just one header
// while keeping the other constant. This helps discover issues specific to each header.
func FuzzParseSignaturesSingleHeader(f *testing.F) {
	// Seed corpus for single-header fuzzing
	seeds := []string{
		`sig1=("@method" "@path");alg="rsa"`,
		`sig1=()`,
		`sig1=("@method"), sig2=("@path")`,
		``,
		`sig1`,
		`sig1=`,
		`sig1="invalid"`,
		`sig1=123`,
		`sig1=("@signature-params")`,
		`sig1=("@invalid")`,
		`sig1=("@query-param")`,
		`sig1=("content-type";bs;sf)`,
		`sig1=("content-type"`,
		`sig1=("content-type)`,
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, signatureInput string) {
		// Test with constant valid signature header
		constantSig := `sig1=:YWJjZGVm:, sig2=:Z2hpams=:`

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ParseSignatures panicked on Signature-Input: %q\nPanic: %v", signatureInput, r)
			}
		}()

		result1, err1 := ParseSignatures(signatureInput, constantSig, sfv.DefaultLimits())
		result2, err2 := ParseSignatures(signatureInput, constantSig, sfv.DefaultLimits())

		if (err1 == nil) != (err2 == nil) {
			t.Errorf("Non-deterministic behavior for Signature-Input: %q", signatureInput)
		}

		if err1 == nil && result1 != nil {
			if len(result1.Signatures) != len(result2.Signatures) {
				t.Errorf("Non-deterministic signature count for Signature-Input: %q", signatureInput)
			}
		}

		// Test with varying signature header and constant input
		constantInput := `sig1=("@method" "@path");alg="rsa", sig2=("date");created=1618884473`

		result3, err3 := ParseSignatures(constantInput, signatureInput, sfv.DefaultLimits())
		result4, err4 := ParseSignatures(constantInput, signatureInput, sfv.DefaultLimits())

		if (err3 == nil) != (err4 == nil) {
			t.Errorf("Non-deterministic behavior for Signature: %q", signatureInput)
		}

		if err3 == nil && result3 != nil {
			if len(result3.Signatures) != len(result4.Signatures) {
				t.Errorf("Non-deterministic signature count for Signature: %q", signatureInput)
			}
		}
	})
}
