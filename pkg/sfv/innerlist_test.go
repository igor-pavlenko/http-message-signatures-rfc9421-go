package sfv

import (
	"testing"
)

func TestParser_parseInnerList(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantItems  []any
		wantParams int // number of parameters on the inner list
		wantErr    bool
	}{
		{
			name:      "empty inner list",
			input:     "()",
			wantItems: []any{},
		},
		{
			name:  "single token",
			input: "(hello)",
			wantItems: []any{
				"hello",
			},
		},
		{
			name:  "multiple tokens with SP",
			input: "(foo bar baz)",
			wantItems: []any{
				"foo",
				"bar",
				"baz",
			},
		},
		{
			name:  "mixed types",
			input: `("@method" "date" 123)`,
			wantItems: []any{
				"@method",
				"date",
				int64(123),
			},
		},
		{
			name:  "with item parameters",
			input: `("content-digest";sf "@authority")`,
			wantItems: []any{
				"content-digest", // First item will have ;sf parameter
				"@authority",
			},
		},
		{
			name:       "with inner list parameters",
			input:      `("foo" "bar");created=123`,
			wantItems:  []any{"foo", "bar"},
			wantParams: 1,
		},
		{
			name:    "missing closing paren",
			input:   "(",
			wantErr: true,
		},
		{
			name:    "missing opening paren",
			input:   "hello)",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser(tt.input, NoLimits())
			items, params, err := p.parseInnerList()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseInnerList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if len(items) != len(tt.wantItems) {
				t.Errorf("parseInnerList() items length = %v, want %v", len(items), len(tt.wantItems))
				return
			}

			for i, want := range tt.wantItems {
				got := items[i].Value
				// Handle Token type: compare inner value
				if tok, ok := got.(Token); ok {
					if tok.Value != want {
						t.Errorf("parseInnerList() items[%d] = %v, want %v", i, tok.Value, want)
					}
				} else if got != want {
					t.Errorf("parseInnerList() items[%d] = %v, want %v", i, got, want)
				}
			}

			if len(params) != tt.wantParams {
				t.Errorf("parseInnerList() params length = %v, want %v", len(params), tt.wantParams)
			}
		})
	}
}

// ============================================================================
// Fuzz Tests
// ============================================================================

// FuzzParseInnerList tests the inner list parser with random inputs to discover
// edge cases, crashes, panics, or unexpected behavior.
//
// Per User Story 6 (FR-038 to FR-044):
// - Must handle all inputs without panicking or crashing
// - Must handle extreme nesting levels, empty lists, and invalid item types
// - Must handle inputs within reasonable resource limits (memory, time)
func FuzzParseInnerList(f *testing.F) {
	// Seed corpus with known edge cases per FR-039
	seeds := []string{
		// Valid inner lists
		`()`,                            // Empty
		`(1)`,                           // Single item
		`(1 2 3)`,                       // Multiple items
		`("a" "b" "c")`,                 // Strings
		`(?0 ?1)`,                       // Booleans
		`(token1 token2)`,               // Tokens
		`(:YWJj: :ZGVm:)`,               // Byte sequences
		`(1 "two" token ?1 :Zm91cg==:)`, // Mixed types

		// Inner lists with parameters
		`();x=1`,          // Empty with params
		`(1);x=1`,         // Single item with params
		`(1 2 3);x=1;y=2`, // Multiple items with params

		// Inner lists with item parameters
		`(1;a=1 2;b=2)`,       // Items with their own params
		`("str";x=y)`,         // String with params
		`(token;a=1;b=2;c=3)`, // Token with multiple params

		// Edge cases - empty and whitespace
		`(  )`,     // Spaces inside
		`( )`,      // Single space
		`(	)`,      // Tab inside
		`( 1 )`,    // Spaces around item
		`( 1  2 )`, // Multiple spaces between items

		// Edge cases - unclosed/malformed
		`(`,    // Missing closing paren
		`)`,    // Missing opening paren
		`((`,   // Double opening
		`))`,   // Double closing
		`(1`,   // Unclosed
		`1)`,   // No opening
		`(1 2`, // Unclosed with items

		// Edge cases - invalid separators
		`(1,2)`,  // Comma instead of space
		`(1;2)`,  // Semicolon as separator (should be params)
		`(1|2)`,  // Invalid separator
		`(1\t2)`, // Tab separator (not SP)

		// Edge cases - nested (inner lists can't be nested per RFC 8941)
		`((1))`,         // Nested inner list (invalid)
		`(())`,          // Empty nested (invalid)
		`((1 2) (3 4))`, // Multiple nested (invalid)

		// Edge cases - extreme lengths
		`(` + string(make([]byte, 100)) + `)`, // Long empty spaces
		`(1 1 1 1 1 1 1 1 1 1)`,               // Many items

		// Edge cases - parameters
		`();`,     // Trailing semicolon
		`();;x=1`, // Double semicolon
		`();x`,    // Param without value
		`();x=`,   // Param with empty value
		`();=1`,   // No param name

		// Edge cases - invalid items inside
		`(invalid123)`, // Token starting with digit (invalid)
		`("")`,         // Empty string
		`(::)`,         // Empty byte sequence
		`(?)`,          // Incomplete boolean
		`(?2)`,         // Invalid boolean

		// Edge cases - mixed spacing
		`(1  2  3)`, // Double spaces
		`(  1)`,     // Leading space
		`(1  )`,     // Trailing space
		`( 1 2 3 )`, // Spaces all around

		// Edge cases - special characters
		`(token!)`, // Invalid token char
		`(token@)`, // Invalid token char
		`(token#)`, // Invalid token char

		// Edge cases - unicode
		`("unicode→")`,
		`("emoji😀")`,

		// Large inner lists (stress test)
		`(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20)`,

		// Complex parameters
		`(1);a=1;b="str";c=?1;d=:YWJj:;e=token`,
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// FR-040: Parser must never panic, crash, or enter infinite loops
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("parseInnerList panicked on input %q: %v", input, r)
			}
		}()

		// Parse the input
		parser1 := NewParser(input, NoLimits())
		items1, params1, err1 := parser1.parseInnerList()

		// FR-041: Verify deterministic behavior
		parser2 := NewParser(input, NoLimits())
		items2, params2, err2 := parser2.parseInnerList()

		// Check determinism: errors must match
		if (err1 == nil) != (err2 == nil) {
			t.Errorf("Non-deterministic error behavior for input %q:\nFirst:  %v\nSecond: %v", input, err1, err2)
		}

		// If both succeeded, results must match
		if err1 == nil && err2 == nil {
			// Item count must match
			if len(items1) != len(items2) {
				t.Errorf("Non-deterministic item count for input %q:\nFirst:  %d items\nSecond: %d items",
					input, len(items1), len(items2))
			}

			// Parameter count must match
			if len(params1) != len(params2) {
				t.Errorf("Non-deterministic parameter count for input %q:\nFirst:  %d params\nSecond: %d params",
					input, len(params1), len(params2))
			}
		}

		// FR-042: Memory safety validation
		if err1 == nil {
			// Reasonable limits on inner list size
			if len(items1) > 10000 {
				t.Errorf("Inner list too large for input %q: %d items (possible infinite loop or memory issue)",
					input, len(items1))
			}

			if len(params1) > 10000 {
				t.Errorf("Too many parameters for input %q: %d params (possible infinite loop or memory issue)",
					input, len(params1))
			}

			// Validate structure consistency
			for i, item := range items1 {
				if item.Value == nil {
					t.Errorf("Null item value at index %d for input %q", i, input)
				}
			}
		}
	})
}
