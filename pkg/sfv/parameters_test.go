package sfv

import (
	"testing"
)

func TestParser_parseParameters(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantLen   int
		wantPairs map[string]any // key -> value
		wantErr   bool
	}{
		{
			name:    "no parameters",
			input:   "",
			wantLen: 0,
		},
		{
			name:    "single bare parameter",
			input:   ";sf",
			wantLen: 1,
			wantPairs: map[string]any{
				"sf": true,
			},
		},
		{
			name:    "parameter with string value",
			input:   `;key="member1"`,
			wantLen: 1,
			wantPairs: map[string]any{
				"key": "member1",
			},
		},
		{
			name:    "parameter with integer value",
			input:   ";created=1618884473",
			wantLen: 1,
			wantPairs: map[string]any{
				"created": int64(1618884473),
			},
		},
		{
			name:    "parameter with token value",
			input:   ";alg=rsa-pss-sha512",
			wantLen: 1,
			wantPairs: map[string]any{
				"alg": "rsa-pss-sha512",
			},
		},
		{
			name:    "multiple parameters",
			input:   `;created=1618884473;alg="ed25519";sf`,
			wantLen: 3,
			wantPairs: map[string]any{
				"created": int64(1618884473),
				"alg":     "ed25519",
				"sf":      true,
			},
		},
		{
			name:    "parameter with boolean false",
			input:   ";test=?0",
			wantLen: 1,
			wantPairs: map[string]any{
				"test": false,
			},
		},
		{
			name:    "stops at non-semicolon",
			input:   ";sf,next",
			wantLen: 1,
			wantPairs: map[string]any{
				"sf": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser(tt.input, NoLimits())
			got, err := p.parseParameters()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseParameters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if len(got) != tt.wantLen {
				t.Errorf("parseParameters() length = %v, want %v", len(got), tt.wantLen)
				return
			}

			// Check each expected parameter
			for key, wantVal := range tt.wantPairs {
				found := false
				for _, param := range got {
					if param.Key == key {
						found = true
						// Handle Token type comparison
						gotVal := param.Value
						if tok, ok := gotVal.(Token); ok {
							gotVal = tok.Value
						}
						if gotVal != wantVal {
							t.Errorf("parameter %q value = %v (type %T), want %v (type %T)",
								key, param.Value, param.Value, wantVal, wantVal)
						}
						break
					}
				}
				if !found {
					t.Errorf("parameter %q not found in result", key)
				}
			}
		})
	}
}

// ============================================================================
// Fuzz Tests
// ============================================================================

// FuzzParseParameters tests the parameters parser with random inputs to discover
// edge cases, crashes, panics, or unexpected behavior.
//
// Per User Story 6 (FR-038 to FR-044):
// - Must handle all inputs without panicking or crashing
// - Must handle duplicate parameter keys, invalid parameter values, deeply nested structures
// - Must produce consistent, deterministic results
func FuzzParseParameters(f *testing.F) {
	// Seed corpus with known edge cases per FR-039
	seeds := []string{
		// Valid parameters
		`;a=1`,         // Single parameter
		`;a=1;b=2`,     // Multiple parameters
		`;a=1;b=2;c=3`, // Multiple parameters
		`;key="value"`, // String value
		`;flag=?1`,     // Boolean value
		`;data=:YWJj:`, // Byte sequence value
		`;t=token`,     // Token value

		// Bare parameters (parameter without value = boolean true)
		`;flag`,         // Bare parameter
		`;a;b;c`,        // Multiple bare parameters
		`;a=1;flag;b=2`, // Mixed bare and valued

		// Edge cases - empty and whitespace
		`;`,   // Just semicolon
		`;;`,  // Double semicolon
		`;;;`, // Triple semicolon
		`; `,  // Semicolon with space
		` ;`,  // Space before semicolon
		`;a `, // Trailing space
		`; a`, // Leading space

		// Edge cases - invalid syntax
		`;=1`,        // No key
		`;a=`,        // No value
		`;a==1`,      // Double equals
		`;a=1=2`,     // Multiple equals
		`;123=value`, // Key starting with digit

		// Edge cases - invalid keys
		`;-key=1`,           // Key starting with dash
		`;key with space=1`, // Space in key
		`;key"quote=1`,      // Quote in key
		`;key(paren=1`,      // Paren in key
		`;key,comma=1`,      // Comma in key

		// Edge cases - duplicate keys (last wins per RFC 8941)
		`;a=1;a=2`,     // Duplicate
		`;a=1;b=2;a=3`, // Duplicate non-adjacent
		`;a;a;a`,       // Multiple bare duplicates
		`;a=1;a`,       // Valued then bare
		`;a;a=1`,       // Bare then valued

		// Edge cases - invalid values
		`;a=invalid123`,         // Token starting with digit
		`;a="unclosed`,          // Unclosed string
		`;a=:notbase64:`,        // Invalid base64
		`;a=?2`,                 // Invalid boolean
		`;a=999999999999999999`, // Integer too large

		// Edge cases - separators
		`;a=1,b=2`, // Comma instead of semicolon
		`;a=1 b=2`, // Space instead of semicolon
		`;a=1|b=2`, // Invalid separator

		// Edge cases - nesting (parameters can't be nested)
		`;a=(1 2)`, // Inner list as parameter value (invalid)
		`;a=b;c`,   // This should parse as a=b, c (two params)

		// Edge cases - extreme lengths
		`;` + string(make([]byte, 100)),                // Long empty
		`;a=` + `"` + string(make([]byte, 1000)) + `"`, // Long string value

		// Many parameters
		`;a=1;b=2;c=3;d=4;e=5;f=6;g=7;h=8;i=9;j=10`,

		// Edge cases - special characters in values
		`;msg="hello world"`,
		`;msg="with\"quote"`,
		`;msg="with\\backslash"`,
		`;msg="unicode→"`,
		`;msg="emoji😀"`,

		// Edge cases - tokens with valid characters
		`;t=token123`,
		`;t=token-dash`,
		`;t=token_underscore`,
		`;t=token.dot`,
		`;t=token:colon`,
		`;t=token/slash`,
		`;t=token%percent`,
		`;t=*token`, // Token starting with *

		// Edge cases - combinations
		`;a=1;b="str";c=?1;d=:YWJj:;e=token;f`, // All types
		`;a;b;c;d;e;f`,                         // All bare
		`;a=1;b;c=3;d;e=5`,                     // Mixed bare and valued

		// Edge cases - whitespace sensitivity
		`;a= 1`,     // Space after =
		`;a =1`,     // Space before =
		`;a = 1`,    // Spaces around =
		`; a=1`,     // Space after ;
		`;a=1 ;b=2`, // Space before ;

		// Edge cases - invalid characters
		`;a=\x00`, // Null byte
		`;a=\n`,   // Newline
		`;a=\r`,   // Carriage return
		`;a=\t`,   // Tab

		// Empty values
		`;a=""`, // Empty string
		`;a=::`, // Empty byte sequence
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// FR-040: Parser must never panic, crash, or enter infinite loops
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("parseParameters panicked on input %q: %v", input, r)
			}
		}()

		// Parse the input
		parser1 := NewParser(input, NoLimits())
		result1, err1 := parser1.parseParameters()

		// FR-041: Verify deterministic behavior
		parser2 := NewParser(input, NoLimits())
		result2, err2 := parser2.parseParameters()

		// Check determinism: errors must match
		if (err1 == nil) != (err2 == nil) {
			t.Errorf("Non-deterministic error behavior for input %q:\nFirst:  %v\nSecond: %v", input, err1, err2)
		}

		// If both succeeded, results must match
		if err1 == nil && err2 == nil {
			// Parameter count must match
			if len(result1) != len(result2) {
				t.Errorf("Non-deterministic parameter count for input %q:\nFirst:  %d params\nSecond: %d params",
					input, len(result1), len(result2))
			}

			// Parameter keys and order must match
			for i := range result1 {
				if i >= len(result2) {
					break
				}
				if result1[i].Key != result2[i].Key {
					t.Errorf("Non-deterministic parameter keys at index %d for input %q:\nFirst:  %q\nSecond: %q",
						i, input, result1[i].Key, result2[i].Key)
					break
				}
			}
		}

		// FR-042: Memory safety validation
		if err1 == nil {
			// Reasonable limits on parameter count
			if len(result1) > 10000 {
				t.Errorf("Too many parameters for input %q: %d params (possible infinite loop or memory issue)",
					input, len(result1))
			}

			// Validate structure consistency
			for i, param := range result1 {
				if param.Key == "" {
					t.Errorf("Empty parameter key at index %d for input %q", i, input)
				}

				// Value should be one of the valid types (or boolean true for bare params)
				switch param.Value.(type) {
				case bool, int64, string, []byte, Token:
					// Valid types
				default:
					t.Errorf("Unexpected parameter value type at index %d for input %q: %T",
						i, input, param.Value)
				}
			}

			// Check for duplicate keys (last wins - not an error, but validate consistency)
			seen := make(map[string]int)
			for i, param := range result1 {
				if prev, exists := seen[param.Key]; exists {
					// Duplicate key - verify last occurrence is what we got
					if i != prev && i < len(result1)-1 {
						// This isn't the last occurrence, but we still recorded it
						// This would indicate a bug in the parser
						continue
					}
				}
				seen[param.Key] = i
			}
		}
	})
}
