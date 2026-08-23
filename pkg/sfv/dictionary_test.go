package sfv

import (
	"testing"
)

func TestParser_parseDictionary(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantKeys  []string // ordered keys
		wantTypes map[string]string
		wantErr   bool
	}{
		{
			name:     "single key with inner list",
			input:    `sig1=("@method" "date")`,
			wantKeys: []string{"sig1"},
			wantTypes: map[string]string{
				"sig1": "innerlist",
			},
		},
		{
			name:     "single key with wrong inner list",
			input:    `sig1=("@method", "date")`,
			wantKeys: []string{"sig1"},
			wantErr:  true,
		},
		{
			name:     "single key with wrong inner list syntax",
			input:    `sig1=("@method)`,
			wantKeys: []string{"sig1"},
			wantErr:  true,
		},
		{
			name:     "multiple keys",
			input:    `sig1=("@method"), sig2=("@path")`,
			wantKeys: []string{"sig1", "sig2"},
			wantTypes: map[string]string{
				"sig1": "innerlist",
				"sig2": "innerlist",
			},
		},
		{
			name:     "key with item value",
			input:    `alg="rsa-pss-sha512"`,
			wantKeys: []string{"alg"},
			wantTypes: map[string]string{
				"alg": "item",
			},
		},
		{
			name:     "mixed dictionary",
			input:    `sig1=("@method");created=123, label="test"`,
			wantKeys: []string{"sig1", "label"},
			wantTypes: map[string]string{
				"sig1":  "innerlist",
				"label": "item",
			},
		},
		{
			name:     "duplicate key (last wins)",
			input:    `key=1, key=2`,
			wantKeys: []string{"key"},
			wantTypes: map[string]string{
				"key": "item",
			},
		},
		{
			name:     "OWS around comma",
			input:    `a=1  ,  b=2`,
			wantKeys: []string{"a", "b"},
		},
		{
			name:    "OWS before eq",
			input:   `a =1`,
			wantErr: true,
		},
		{
			name:    "OWS after eq",
			input:   `a= 1`,
			wantErr: true,
		},
		{
			name:    "OWS around eq",
			input:   `a = 1`,
			wantErr: true,
		},
		{
			name:    "trailing comma",
			input:   `a=1, b=2,`,
			wantErr: true,
		},
		{
			name:     "empty input",
			input:    "",
			wantErr:  false,
			wantKeys: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser(tt.input, NoLimits())
			got, err := p.ParseDictionary()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDictionary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Check keys in order
			if len(got.Keys) != len(tt.wantKeys) {
				t.Errorf("parseDictionary() keys length = %v, want %v", len(got.Keys), len(tt.wantKeys))
				return
			}

			for i, key := range tt.wantKeys {
				if got.Keys[i] != key {
					t.Errorf("parseDictionary() keys[%d] = %v, want %v", i, got.Keys[i], key)
				}
			}

			// Check value types if specified
			if tt.wantTypes != nil {
				for key, wantType := range tt.wantTypes {
					val, exists := got.Values[key]
					if !exists {
						t.Errorf("parseDictionary() missing key %q", key)
						continue
					}

					switch wantType {
					case "innerlist":
						if _, ok := val.(InnerList); !ok {
							t.Errorf("parseDictionary() key %q type = %T, want InnerList", key, val)
						}
					case "item":
						if _, ok := val.(Item); !ok {
							t.Errorf("parseDictionary() key %q type = %T, want Item", key, val)
						}
					}
				}
			}
		})
	}
}

// ============================================================================
// Fuzz Tests
// ============================================================================

// FuzzParseDictionary tests the dictionary parser with random inputs to discover
// edge cases, crashes, panics, or unexpected behavior.
//
// Per User Story 6 (FR-038 to FR-044):
// - Must handle all inputs without panicking or crashing
// - Must return either valid parsed data or an error
// - Must produce deterministic results for identical inputs
// - Must handle extremely large inputs within reasonable resource limits.
func FuzzParseDictionary(f *testing.F) {
	// Seed corpus with known edge cases per FR-039
	seeds := []string{
		// Valid cases
		`a=1`,
		`a=1, b=2`,
		`key="value"`,
		`sig1=("@method" "date");alg="ed25519"`,
		`a=?0, b=?1`,
		`a=:YWJj:`,

		// Empty and whitespace
		``,
		` `,
		`  `,
		`	`,

		// Edge cases with special characters
		`a=1,`,     // Trailing comma (should be rejected)
		`a=1,,b=2`, // Double comma
		`,a=1`,     // Leading comma
		` a=1`,     // Leading space
		`a=1 `,     // Trailing space
		`a =1`,     // Space around =
		`a= 1`,     // Space around =
		`a = 1`,    // Spaces around =

		// Invalid syntax
		`a`,     // No value
		`=1`,    // No key
		`a==1`,  // Double equals
		`a=`,    // Missing value
		`a=1=2`, // Multiple equals

		// Extreme lengths
		string(make([]byte, 1000)),  // 1KB of null bytes
		string(make([]byte, 10000)), // 10KB of null bytes

		// Special characters
		`a="\x00"`, // Null byte in string
		`a="\n"`,   // Newline
		`a="\r"`,   // Carriage return
		`a="\t"`,   // Tab

		// Malformed strings
		`a="unclosed`,   // Unclosed quote
		`a="invalid\x"`, // Invalid escape
		`a="\\`,         // Backslash at end
		`a=""`,          // Empty string

		// Malformed byte sequences
		`a=:notbase64:`, // Invalid base64
		`a=:====:`,      // Invalid base64 padding
		`a=::`,          // Empty byte sequence
		`a=:missing`,    // Missing closing colon

		// Integer edge cases
		`a=0`,
		`a=-0`,
		`a=999999999999999`,  // Max 15 digits
		`a=9999999999999999`, // 16 digits (should error)
		`a=-999999999999999`,
		`a=-9999999999999999`,

		// Boolean edge cases
		`a=?0`,
		`a=?1`,
		`a=?2`, // Invalid boolean
		`a=?`,  // Incomplete boolean

		// Token edge cases
		`a=token`,
		`a=*token`, // Token starting with *
		`a=token123`,
		`a=token-with-dashes`,
		`a=token_with_underscores`,
		`a=token.with.dots`,
		`a=token:with:colons`,
		`a=token/with/slashes`,
		`a=token%20with%20percent`,

		// Nested structures
		`a=(1 2 3)`,     // Inner list
		`a=(1 2 3);x=y`, // Inner list with parameters
		`a=();x=y`,      // Empty inner list with parameters
		`a=(((1)))`,     // Deeply nested (invalid)
		`a=(1 2 3`,
		`a=1 2 3)`,

		// Duplicate keys (last wins per RFC 8941)
		`a=1, a=2`,
		`a=1, b=2, a=3`,

		// Multiple parameters
		`a=1;x=1;y=2;z=3`,
		`a=1;x=1;x=2`, // Duplicate parameter keys

		// Mixed valid and invalid
		`a=1, b=invalid, c=3`,
		`a="valid", b=:invalid:, c=token`,
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// FR-040: Parser must never panic, crash, or enter infinite loops
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Parser panicked on input %q: %v", input, r)
			}
		}()

		// Parse the input
		parser1 := NewParser(input, NoLimits())
		result1, err1 := parser1.ParseDictionary()

		// FR-041: Verify deterministic behavior
		// Parsing the same input multiple times should produce identical results
		parser2 := NewParser(input, NoLimits())
		result2, err2 := parser2.ParseDictionary()

		// Check determinism: errors must match
		if (err1 == nil) != (err2 == nil) {
			t.Errorf("Non-deterministic error behavior for input %q:\nFirst:  %v\nSecond: %v", input, err1, err2)
		}

		// If both succeeded, results must match
		if err1 == nil && err2 == nil {
			if len(result1.Keys) != len(result2.Keys) {
				t.Errorf("Non-deterministic key count for input %q:\nFirst:  %d keys\nSecond: %d keys",
					input, len(result1.Keys), len(result2.Keys))
			}

			for i, key1 := range result1.Keys {
				if i >= len(result2.Keys) || key1 != result2.Keys[i] {
					t.Errorf("Non-deterministic keys for input %q:\nFirst:  %v\nSecond: %v",
						input, result1.Keys, result2.Keys)
					break
				}
			}
		}

		// FR-042: Memory safety check (implicit - if we got here, no memory exhaustion occurred)
		// The fuzzer will detect excessive memory usage

		// Validation: result must be valid if no error
		if err1 == nil {
			// Keys and Values must have corresponding entries
			if len(result1.Values) < len(result1.Keys) {
				t.Errorf("Inconsistent dictionary for input %q: %d keys but only %d values",
					input, len(result1.Keys), len(result1.Values))
			}

			// Each key in Keys must exist in Values map
			for _, key := range result1.Keys {
				if _, exists := result1.Values[key]; !exists {
					t.Errorf("Key %q in Keys slice but missing from Values map for input %q",
						key, input)
				}
			}
		}
	})
}
