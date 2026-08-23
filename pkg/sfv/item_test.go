package sfv

import (
	"bytes"
	"testing"
)

func TestParser_parseBareItem(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantType string // "boolean", "integer", "string", "token", "bytes"
		wantVal  any
		wantErr  bool
	}{
		{
			name:     "parse boolean true",
			input:    "?1",
			wantType: "boolean",
			wantVal:  true,
		},
		{
			name:     "parse boolean false",
			input:    "?0",
			wantType: "boolean",
			wantVal:  false,
		},
		{
			name:     "parse positive integer",
			input:    "123",
			wantType: "integer",
			wantVal:  int64(123),
		},
		{
			name:     "parse negative integer",
			input:    "-456",
			wantType: "integer",
			wantVal:  int64(-456),
		},
		{
			name:     "parse string",
			input:    `"hello world"`,
			wantType: "string",
			wantVal:  "hello world",
		},
		{
			name:     "parse token",
			input:    "example-token",
			wantType: "token",
			wantVal:  "example-token",
		},
		{
			name:     "parse byte sequence",
			input:    ":aGVsbG8=:",
			wantType: "bytes",
			wantVal:  []byte("hello"),
		},
		{
			name:     "parse asterisk token",
			input:    "*",
			wantType: "token",
			wantVal:  "*",
		},
		{
			name:    "reject invalid start",
			input:   "@invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser(tt.input, NoLimits())
			got, err := p.parseBareItem()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseBareItem() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Type-specific validation
			switch tt.wantType {
			case "boolean":
				if got != tt.wantVal.(bool) {
					t.Errorf("parseBareItem() = %v, want %v", got, tt.wantVal)
				}
			case "integer":
				if got != tt.wantVal.(int64) {
					t.Errorf("parseBareItem() = %v, want %v", got, tt.wantVal)
				}
			case "string":
				if got != tt.wantVal.(string) {
					t.Errorf("parseBareItem() = %v, want %v", got, tt.wantVal)
				}
			case "token":
				tok, ok := got.(Token)
				if !ok {
					t.Errorf("parseBareItem() = %T, want Token", got)
				} else if tok.Value != tt.wantVal.(string) {
					t.Errorf("parseBareItem() = %v, want %v", tok.Value, tt.wantVal)
				}
			case "bytes":
				if !bytes.Equal(got.([]byte), tt.wantVal.([]byte)) {
					t.Errorf("parseBareItem() = %v, want %v", got, tt.wantVal)
				}
			}
		})
	}
}

// ============================================================================
// Fuzz Tests
// ============================================================================

// FuzzParseBareItem tests the bare item parser with random inputs to discover
// edge cases, crashes, panics, or unexpected behavior.
//
// Per User Story 6 (FR-038 to FR-044):
// - Must handle all inputs without panicking or crashing
// - Must handle malformed strings (unclosed quotes, invalid escape sequences, extreme lengths)
// - Must produce deterministic results for identical inputs
func FuzzParseBareItem(f *testing.F) {
	// Seed corpus with known edge cases per FR-039
	seeds := []string{
		// Valid booleans
		`?0`,
		`?1`,

		// Valid integers
		`0`,
		`1`,
		`-1`,
		`123`,
		`-123`,
		`999999999999999`, // Max 15 digits
		`-999999999999999`,

		// Valid strings
		`""`,
		`"hello"`,
		`"hello world"`,
		`"with\"quote"`,
		`"with\\backslash"`,
		`"mixed\"and\\together"`,

		// Valid tokens
		`token`,
		`token123`,
		`token-with-dashes`,
		`token_underscores`,
		`token.dots`,
		`token:colons`,
		`token/slashes`,
		`token%percent`,
		`*token`, // Token starting with *

		// Valid byte sequences
		`:YWJj:`, // "abc" in base64
		`::`,     // Empty byte sequence
		`:VGhpcyBpcyBhIGxvbmdlciBieXRlIHNlcXVlbmNl:`,

		// Edge cases - integers
		`9999999999999999`,  // 16 digits (should error)
		`-9999999999999999`, // 16 digits negative
		`00000000000000`,    // Leading zeros
		`-0`,                // Negative zero

		// Edge cases - booleans
		`?`,     // Incomplete
		`?2`,    // Invalid value
		`?true`, // Not a boolean
		`?false`,

		// Edge cases - strings with escape sequences
		`"unclosed`,   // Missing closing quote
		`"invalid\x"`, // Invalid escape sequence
		`"trailing\\`, // Backslash at end (before closing)
		`"\\"`,        // Just escaped quote
		`"\\\\"`,      // Escaped backslash
		`"\n"`,        // Invalid escape (only \" and \\ allowed)
		`"\t"`,        // Invalid escape
		`"\r"`,        // Invalid escape
		`"\0"`,        // Invalid escape

		// Edge cases - strings with extreme lengths
		`"` + string(make([]byte, 1000)) + `"`,  // 1KB string
		`"` + string(make([]byte, 10000)) + `"`, // 10KB string

		// Edge cases - byte sequences
		`:notbase64:`, // Invalid base64 characters
		`:====:`,      // Invalid padding
		`:YWJj`,       // Missing closing colon
		`:`,           // Just opening colon
		`:YWJj::`,     // Extra colon
		`::extra`,     // Content after closing colon

		// Edge cases - tokens
		``,                 // Empty
		` `,                // Space
		`123token`,         // Token starting with digit (invalid)
		`-token`,           // Token starting with dash (invalid)
		`token with space`, // Space in token
		`token"quote`,      // Quote in token
		`token(paren`,      // Paren in token

		// Edge cases - mixed invalid
		`???`,
		`---`,
		`"""`,
		`:::`,
		`((()))`,

		// Unicode and special characters
		`"unicode→"`,
		`"emoji😀"`,
		`"\u0000"`, // Null byte (escaped)

		// Extreme nesting (for parseBareItem shouldn't nest, but test anyway)
		`(((((nested)))))`,
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// FR-040: Parser must never panic, crash, or enter infinite loops
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("parseBareItem panicked on input %q: %v", input, r)
			}
		}()

		// Parse the input
		parser1 := NewParser(input, NoLimits())
		result1, err1 := parser1.parseBareItem()

		// FR-041: Verify deterministic behavior
		parser2 := NewParser(input, NoLimits())
		result2, err2 := parser2.parseBareItem()

		// Check determinism: errors must match
		if (err1 == nil) != (err2 == nil) {
			t.Errorf("Non-deterministic error behavior for input %q:\nFirst:  %v\nSecond: %v", input, err1, err2)
		}

		// If both succeeded, results must match
		if err1 == nil && err2 == nil {
			// Type must match
			type1 := getType(result1)
			type2 := getType(result2)
			if type1 != type2 {
				t.Errorf("Non-deterministic type for input %q:\nFirst:  %s\nSecond: %s", input, type1, type2)
			}

			// Values must match (basic comparison)
			if !itemsEqual(result1, result2) {
				t.Errorf("Non-deterministic value for input %q:\nFirst:  %#v\nSecond: %#v", input, result1, result2)
			}
		}

		// Validation: basic type checking if no error
		if err1 == nil {
			// Result must be one of the valid types
			switch result1.(type) {
			case bool, int64, string, []byte, Token:
				// Valid types
			default:
				t.Errorf("Unexpected result type for input %q: %T", input, result1)
			}
		}
	})
}

// Helper to get type name
func getType(v any) string {
	switch v.(type) {
	case bool:
		return "bool"
	case int64:
		return "int64"
	case string:
		return "string"
	case []byte:
		return "[]byte"
	case Token:
		return "Token"
	default:
		return "unknown"
	}
}

// Helper to compare items
func itemsEqual(a, b any) bool {
	switch va := a.(type) {
	case bool:
		vb, ok := b.(bool)
		return ok && va == vb
	case int64:
		vb, ok := b.(int64)
		return ok && va == vb
	case string:
		vb, ok := b.(string)
		return ok && va == vb
	case []byte:
		vb, ok := b.([]byte)
		if !ok || len(va) != len(vb) {
			return false
		}
		for i := range va {
			if va[i] != vb[i] {
				return false
			}
		}
		return true
	case Token:
		vb, ok := b.(Token)
		return ok && va.Value == vb.Value
	}
	return false
}
