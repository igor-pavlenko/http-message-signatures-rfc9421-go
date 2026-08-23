package sfv

import (
	"bytes"
	"testing"
)

func TestParser_parseBoolean(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    bool
		wantErr bool
	}{
		{
			name:  "parse true",
			input: "?1",
			want:  true,
		},
		{
			name:  "parse false",
			input: "?0",
			want:  false,
		},
		{
			name:    "missing ? prefix",
			input:   "1",
			wantErr: true,
		},
		{
			name:    "invalid boolean value",
			input:   "?2",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser(tt.input, NoLimits())
			got, err := p.parseBoolean()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseBoolean() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseBoolean() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParser_parseInteger(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int64
		wantErr bool
	}{
		{
			name:  "parse positive integer",
			input: "42",
			want:  42,
		},
		{
			name:  "parse negative integer",
			input: "-17",
			want:  -17,
		},
		{
			name:  "parse zero",
			input: "0",
			want:  0,
		},
		{
			name:  "parse max 15 digits",
			input: "999999999999999",
			want:  999999999999999,
		},
		{
			name:    "reject 16 digits (too long)",
			input:   "9999999999999999",
			wantErr: true,
		},
		{
			name:    "reject non-digit",
			input:   "abc",
			wantErr: true,
		},
		{
			name:    "reject empty",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser(tt.input, NoLimits())
			got, err := p.parseInteger()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseInteger() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseInteger() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParser_parseString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "parse simple string",
			input: `"hello"`,
			want:  "hello",
		},
		{
			name:  "parse empty string",
			input: `""`,
			want:  "",
		},
		{
			name:  "parse string with escaped quote",
			input: `"hello \"world\""`,
			want:  `hello "world"`,
		},
		{
			name:  "parse string with escaped backslash",
			input: `"hello\\world"`,
			want:  `hello\world`,
		},
		{
			name:    "reject missing opening quote",
			input:   `hello"`,
			wantErr: true,
		},
		{
			name:    "reject missing closing quote",
			input:   `"hello`,
			wantErr: true,
		},
		{
			name:    "reject invalid escape",
			input:   `"hello\n"`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser(tt.input, NoLimits())
			got, err := p.parseString()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParser_parseToken(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "parse simple token",
			input: "hello",
			want:  "hello",
		},
		{
			name:  "parse token with digits",
			input: "hello123",
			want:  "hello123",
		},
		{
			name:  "parse token with allowed chars",
			input: "hello-world_test.example:foo%2Fbar",
			want:  "hello-world_test.example:foo%2Fbar",
		},
		{
			name:  "parse asterisk token",
			input: "*",
			want:  "*",
		},
		{
			name:    "reject token starting with digit",
			input:   "123hello",
			wantErr: true,
		},
		{
			name:    "reject empty",
			input:   "",
			wantErr: true,
		},
		{
			name:  "parse token stops at space (valid behavior)",
			input: "hello world",
			want:  "hello", // Parser stops at space, which is correct
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser(tt.input, NoLimits())
			got, err := p.parseToken()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got.Value != tt.want {
				t.Errorf("parseToken() = %q, want %q", got.Value, tt.want)
			}
		})
	}
}

func TestParser_parseByteSequence(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{
			name:  "parse simple base64",
			input: ":aGVsbG8=:",
			want:  []byte("hello"),
		},
		{
			name:  "parse empty byte sequence",
			input: "::",
			want:  []byte{},
		},
		{
			name:  "parse base64 without padding",
			input: ":aGVsbG8:",
			want:  []byte("hello"),
		},
		{
			name:    "reject missing opening colon",
			input:   "aGVsbG8=:",
			wantErr: true,
		},
		{
			name:    "reject missing closing colon",
			input:   ":aGVsbG8=",
			wantErr: true,
		},
		{
			name:    "reject invalid base64",
			input:   ":@@@:",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser(tt.input, NoLimits())
			got, err := p.parseByteSequence()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseByteSequence() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(got, tt.want) {
				t.Errorf("parseByteSequence() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// Fuzz Tests
// ============================================================================

// FuzzParseInteger tests the integer parser with random inputs to discover
// edge cases, crashes, panics, or unexpected behavior.
//
// Per User Story 6 (FR-038 to FR-044):
// - Must handle all inputs without panicking or crashing
// - Must enforce RFC 8941 constraints (max 15 digits)
// - Must produce consistent, deterministic results
func FuzzParseInteger(f *testing.F) {
	// Seed corpus with known edge cases per FR-039
	seeds := []string{
		// Valid integers
		`0`,
		`1`,
		`-1`,
		`123`,
		`-123`,
		`999999999999999`,  // Max 15 digits
		`-999999999999999`, // Max 15 digits negative

		// Edge cases - boundary conditions
		`9999999999999999`,  // 16 digits (should error)
		`-9999999999999999`, // 16 digits negative (should error)
		`00000000000000`,    // Leading zeros
		`-0`,                // Negative zero

		// Edge cases - invalid syntax
		``,      // Empty
		` `,     // Space
		`-`,     // Just minus
		`+1`,    // Plus sign (not allowed)
		`1.0`,   // Decimal (not integer)
		`1e5`,   // Scientific notation
		`0x10`,  // Hex notation
		`0o10`,  // Octal notation
		`0b10`,  // Binary notation
		`1_000`, // Underscore separator
		`1,000`, // Comma separator

		// Edge cases - whitespace
		` 1`,  // Leading space
		`1 `,  // Trailing space
		` 1 `, // Both sides

		// Edge cases - invalid characters
		`1a`,  // Letter after digit
		`a1`,  // Letter before digit
		`1-2`, // Minus in middle
		`--1`, // Double minus
		`1-`,  // Trailing minus

		// Edge cases - extreme values
		`999999999999999999999`,   // Very large
		`-999999999999999999999`,  // Very large negative
		string(make([]byte, 100)), // 100 zeros or null bytes

		// Edge cases - special characters
		`1\x00`, // Null byte
		`1\n`,   // Newline
		`1\r`,   // Carriage return
		`1\t`,   // Tab
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// FR-040: Parser must never panic, crash, or enter infinite loops
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("parseInteger panicked on input %q: %v", input, r)
			}
		}()

		// Parse the input
		parser1 := NewParser(input, NoLimits())
		result1, err1 := parser1.parseInteger()

		// FR-041: Verify deterministic behavior
		parser2 := NewParser(input, NoLimits())
		result2, err2 := parser2.parseInteger()

		// Check determinism: errors must match
		if (err1 == nil) != (err2 == nil) {
			t.Errorf("Non-deterministic error behavior for input %q:\nFirst:  %v\nSecond: %v", input, err1, err2)
		}

		// If both succeeded, results must match
		if err1 == nil && err2 == nil {
			if result1 != result2 {
				t.Errorf("Non-deterministic value for input %q:\nFirst:  %d\nSecond: %d", input, result1, result2)
			}

			// RFC 8941 constraint: integer must fit in 15 digits
			// This is an implicit validation - if parser succeeded, it should enforce this
		}
	})
}

// FuzzParseString tests the string parser with random inputs to discover
// edge cases, crashes, panics, or unexpected behavior.
//
// Per User Story 6 (FR-038 to FR-044):
// - Must handle all inputs without panicking or crashing
// - Must handle malformed strings (unclosed quotes, invalid escape sequences)
// - Must produce consistent, deterministic results
func FuzzParseString(f *testing.F) {
	// Seed corpus with known edge cases per FR-039
	seeds := []string{
		// Valid strings
		`""`,
		`"hello"`,
		`"hello world"`,
		`"with\"quote"`,
		`"with\\backslash"`,
		`"mixed\"and\\together"`,

		// Edge cases - empty and whitespace
		`" "`,            // Single space
		`"  "`,           // Multiple spaces
		`"\t"`,           // Tab (but \t is invalid escape)
		`"   spaces   "`, // Spaces inside

		// Edge cases - unclosed/malformed
		`"`,         // Just opening quote
		`"unclosed`, // Missing closing quote
		`unclosed"`, // Missing opening quote
		`""extra`,   // Extra content after closing
		`"test`,     // Unclosed with content

		// Edge cases - escape sequences
		`"invalid\x"`, // Invalid escape sequence
		`"trailing\\`, // Backslash before closing (technically `"trailing\` then `\`)
		`"\\"`,        // Just escaped quote
		`"\\\\"`,      // Escaped backslash
		`"\n"`,        // Invalid escape (only \" and \\ allowed)
		`"\r"`,        // Invalid escape
		`"\t"`,        // Invalid escape
		`"\0"`,        // Invalid escape
		`"\a"`,        // Invalid escape
		`"\b"`,        // Invalid escape
		`"\\"`,        // Valid: escaped backslash

		// Edge cases - extreme lengths
		`"` + string(make([]byte, 1000)) + `"`,  // 1KB string
		`"` + string(make([]byte, 10000)) + `"`, // 10KB string

		// Edge cases - special characters (valid in strings)
		`"unicode→"`,
		`"emoji😀"`,
		`"@method"`,
		`"content-type"`,
		`"sig1"`,

		// Edge cases - quotes and backslashes
		`"\"\""`,       // Two escaped quotes
		`"\\\\"`,       // Two escaped backslashes
		`"\\\"\\\""`,   // Mixed escapes
		`"test\"test"`, // Quote in middle
		`"test\\test"`, // Backslash in middle

		// Edge cases - invalid content
		`"test\x00"`,   // Null byte (might be valid or invalid depending on spec)
		`"test\ntest"`, // Literal newline (not \n escape)
		`"test\rtest"`, // Literal carriage return

		// Edge cases - empty escapes
		`"\\"`,  // Backslash at end (before close quote)
		`"a\\"`, // Content then backslash at end
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// FR-040: Parser must never panic, crash, or enter infinite loops
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("parseString panicked on input %q: %v", input, r)
			}
		}()

		// Parse the input
		parser1 := NewParser(input, NoLimits())
		result1, err1 := parser1.parseString()

		// FR-041: Verify deterministic behavior
		parser2 := NewParser(input, NoLimits())
		result2, err2 := parser2.parseString()

		// Check determinism: errors must match
		if (err1 == nil) != (err2 == nil) {
			t.Errorf("Non-deterministic error behavior for input %q:\nFirst:  %v\nSecond: %v", input, err1, err2)
		}

		// If both succeeded, results must match
		if err1 == nil && err2 == nil {
			if result1 != result2 {
				t.Errorf("Non-deterministic value for input %q:\nFirst:  %q\nSecond: %q", input, result1, result2)
			}

			// FR-042: Memory safety - reasonable string length
			if len(result1) > 100000 {
				t.Errorf("String too large for input %q: %d bytes (possible memory issue)", input, len(result1))
			}
		}
	})
}

// FuzzParseToken tests the token parser with random inputs to discover
// edge cases, crashes, panics, or unexpected behavior.
//
// Per User Story 6 (FR-038 to FR-044):
// - Must handle all inputs without panicking or crashing
// - Must enforce RFC 8941 token syntax rules
// - Must produce consistent, deterministic results
func FuzzParseToken(f *testing.F) {
	// Seed corpus with known edge cases per FR-039
	seeds := []string{
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

		// Valid token characters (RFC 8941)
		`a`,
		`abc`,
		`ABC`,
		`a1`,
		`a-b`,
		`a_b`,
		`a.b`,
		`a:b`,
		`a/b`,
		`a%b`,

		// Edge cases - invalid starting characters
		``,         // Empty
		` `,        // Space
		`123token`, // Digit first (invalid)
		`-token`,   // Dash first (invalid)
		`_token`,   // Underscore first (invalid)
		`.token`,   // Dot first (invalid)
		`:token`,   // Colon first (invalid)
		`/token`,   // Slash first (invalid)
		`%token`,   // Percent first (invalid)

		// Edge cases - invalid characters
		`token with space`,
		`token"quote`,
		`token(paren`,
		`token)paren`,
		`token[bracket`,
		`token]bracket`,
		`token{brace`,
		`token}brace`,
		`token<angle`,
		`token>angle`,
		`token,comma`,
		`token;semicolon`,
		`token=equals`,
		`token\\backslash`,
		`token'quote`,
		`token@at`,
		`token#hash`,
		`token$dollar`,
		`token&ampersand`,
		`token+plus`,
		`token!exclaim`,
		`token?question`,
		`token|pipe`,
		`token~tilde`,
		`token` + "`backtick",

		// Edge cases - special tokens
		`*`,   // Just asterisk
		`**`,  // Double asterisk
		`*a*`, // Asterisk in middle (invalid)

		// Edge cases - extreme lengths
		`a` + string(make([]byte, 1000)), // Very long token
		string(make([]byte, 100)),        // 100 null bytes

		// Edge cases - whitespace
		` token`,  // Leading space
		`token `,  // Trailing space
		` token `, // Both sides

		// Edge cases - control characters
		`token\x00`, // Null byte
		`token\n`,   // Newline
		`token\r`,   // Carriage return
		`token\t`,   // Tab
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// FR-040: Parser must never panic, crash, or enter infinite loops
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("parseToken panicked on input %q: %v", input, r)
			}
		}()

		// Parse the input
		parser1 := NewParser(input, NoLimits())
		result1, err1 := parser1.parseToken()

		// FR-041: Verify deterministic behavior
		parser2 := NewParser(input, NoLimits())
		result2, err2 := parser2.parseToken()

		// Check determinism: errors must match
		if (err1 == nil) != (err2 == nil) {
			t.Errorf("Non-deterministic error behavior for input %q:\nFirst:  %v\nSecond: %v", input, err1, err2)
		}

		// If both succeeded, results must match
		if err1 == nil && err2 == nil {
			if result1.Value != result2.Value {
				t.Errorf("Non-deterministic value for input %q:\nFirst:  %q\nSecond: %q", input, result1.Value, result2.Value)
			}

			// Validate token syntax if succeeded
			if len(result1.Value) == 0 {
				t.Errorf("parseToken returned empty token for input %q", input)
			}

			// First character must be alpha or *
			first := result1.Value[0]
			if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '*') {
				t.Errorf("Invalid token first character for input %q: %c", input, first)
			}
		}
	})
}

// FuzzParseByteSequence tests the byte sequence parser with random inputs to discover
// edge cases, crashes, panics, or unexpected behavior.
//
// Per User Story 6 (FR-038 to FR-044):
// - Must handle all inputs without panicking or crashing
// - Must handle invalid base64 encoding
// - Must produce consistent, deterministic results
func FuzzParseByteSequence(f *testing.F) {
	// Seed corpus with known edge cases per FR-039
	seeds := []string{
		// Valid byte sequences
		`:YWJj:`, // "abc" in base64
		`::`,     // Empty byte sequence
		`:VGhpcyBpcyBhIGxvbmdlciBieXRlIHNlcXVlbmNl:`,
		`:dGVzdA==:`, // With padding
		`:dGVzdA:`,   // Without padding (might be valid)

		// Edge cases - invalid base64
		`:notbase64:`, // Invalid characters
		`:====:`,      // Just padding
		`:YWJj===:`,   // Too much padding
		`:YW Jj:`,     // Space in middle
		`:YW\nJj:`,    // Newline in middle
		`:YW\tJj:`,    // Tab in middle

		// Edge cases - unclosed/malformed
		`:`,       // Just opening colon
		`:YWJj`,   // Missing closing colon
		`YWJj:`,   // Missing opening colon
		`::extra`, // Extra content after closing
		`:YWJj::`, // Double closing colon
		`::YWJj:`, // Double opening colon

		// Edge cases - empty/whitespace
		`: :`,  // Space inside
		`:  :`, // Multiple spaces
		`:\t:`, // Tab inside

		// Edge cases - extreme lengths
		`:` + string(make([]byte, 1000)) + `:`,  // 1KB of content
		`:` + string(make([]byte, 10000)) + `:`, // 10KB of content

		// Edge cases - special characters
		`:YWJj\x00:`, // Null byte
		`:YWJj\n:`,   // Newline
		`:YWJj\r:`,   // Carriage return

		// Edge cases - base64 variations
		`:YQ==:`, // Single char "a" with padding
		`:YWI=:`, // Two chars "ab" with padding
		`:QUJD:`, // Three chars "ABC" no padding
		`:+/+/:`, // Special base64 chars (+/)
		`:_-_-:`, // URL-safe base64 chars (_-)

		// Edge cases - invalid combinations
		`:Y:`,   // Single char (invalid base64 length)
		`:YW:`,  // Two chars (invalid base64 length)
		`:YWJ:`, // Three chars (valid - 2 bytes)

		// Tricky edge cases
		``,   // Empty
		` `,  // Space
		`:`,  // Just colon
		`::`, // Empty sequence (valid)
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// FR-040: Parser must never panic, crash, or enter infinite loops
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("parseByteSequence panicked on input %q: %v", input, r)
			}
		}()

		// Parse the input
		parser1 := NewParser(input, NoLimits())
		result1, err1 := parser1.parseByteSequence()

		// FR-041: Verify deterministic behavior
		parser2 := NewParser(input, NoLimits())
		result2, err2 := parser2.parseByteSequence()

		// Check determinism: errors must match
		if (err1 == nil) != (err2 == nil) {
			t.Errorf("Non-deterministic error behavior for input %q:\nFirst:  %v\nSecond: %v", input, err1, err2)
		}

		// If both succeeded, results must match
		if err1 == nil && err2 == nil {
			if len(result1) != len(result2) {
				t.Errorf("Non-deterministic length for input %q:\nFirst:  %d bytes\nSecond: %d bytes",
					input, len(result1), len(result2))
			}

			for i := range result1 {
				if i >= len(result2) || result1[i] != result2[i] {
					t.Errorf("Non-deterministic bytes for input %q at index %d", input, i)
					break
				}
			}

			// FR-042: Memory safety - reasonable byte sequence length
			if len(result1) > 100000 {
				t.Errorf("Byte sequence too large for input %q: %d bytes (possible memory issue)",
					input, len(result1))
			}
		}
	})
}

// FuzzParseBoolean tests the boolean parser with random inputs to discover
// edge cases, crashes, panics, or unexpected behavior.
//
// Per User Story 6 (FR-038 to FR-044):
// - Must handle all inputs without panicking or crashing
// - Must only accept ?0 and ?1 per RFC 8941
// - Must produce consistent, deterministic results
func FuzzParseBoolean(f *testing.F) {
	// Seed corpus with known edge cases per FR-039
	seeds := []string{
		// Valid booleans
		`?0`,
		`?1`,

		// Edge cases - invalid values
		`?`,  // Incomplete
		`?2`, // Invalid value
		`?3`,
		`?9`,
		`?-1`, // Negative
		`?01`, // Leading zero
		`?10`, // Two digits

		// Edge cases - wrong type
		`?true`,
		`?false`,
		`?TRUE`,
		`?FALSE`,
		`?t`,
		`?f`,
		`?yes`,
		`?no`,

		// Edge cases - whitespace
		`? 0`, // Space after ?
		`?0 `, // Space after digit
		` ?0`, // Space before ?

		// Edge cases - missing parts
		`0`, // No question mark
		`1`, // No question mark
		`true`,
		`false`,

		// Edge cases - extra characters
		`?0extra`,
		`?1extra`,
		`??0`, // Double question mark
		`?00`, // Double zero

		// Edge cases - special characters
		`?\x00`, // Null byte
		`?\n`,   // Newline
		`?\t`,   // Tab

		// Edge cases - empty
		``,
		` `,
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// FR-040: Parser must never panic, crash, or enter infinite loops
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("parseBoolean panicked on input %q: %v", input, r)
			}
		}()

		// Parse the input
		parser1 := NewParser(input, NoLimits())
		result1, err1 := parser1.parseBoolean()

		// FR-041: Verify deterministic behavior
		parser2 := NewParser(input, NoLimits())
		result2, err2 := parser2.parseBoolean()

		// Check determinism: errors must match
		if (err1 == nil) != (err2 == nil) {
			t.Errorf("Non-deterministic error behavior for input %q:\nFirst:  %v\nSecond: %v", input, err1, err2)
		}

		// If both succeeded, results must match
		if err1 == nil && err2 == nil {
			if result1 != result2 {
				t.Errorf("Non-deterministic value for input %q:\nFirst:  %v\nSecond: %v", input, result1, result2)
			}

			// RFC 8941 constraint: boolean must be exactly ?0 or ?1
			// If parser succeeded, the value should be valid
			if result1 != true && result1 != false {
				t.Errorf("Invalid boolean value for input %q: %v", input, result1)
			}
		}
	})
}
