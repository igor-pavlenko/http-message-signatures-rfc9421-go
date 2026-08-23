package sfv

import (
	"strings"
	"testing"
)

func TestDefaultLimits(t *testing.T) {
	limits := DefaultLimits()

	// Verify default values are set
	if limits.MaxInputLength != 65536 {
		t.Errorf("MaxInputLength = %d, want 65536", limits.MaxInputLength)
	}
	if limits.MaxStringLength != 8192 {
		t.Errorf("MaxStringLength = %d, want 8192", limits.MaxStringLength)
	}
	if limits.MaxByteSequenceLength != 16384 {
		t.Errorf("MaxByteSequenceLength = %d, want 16384", limits.MaxByteSequenceLength)
	}
	if limits.MaxDictionaryMembers != 128 {
		t.Errorf("MaxDictionaryMembers = %d, want 128", limits.MaxDictionaryMembers)
	}
	if limits.MaxInnerListMembers != 128 {
		t.Errorf("MaxInnerListMembers = %d, want 128", limits.MaxInnerListMembers)
	}
	if limits.MaxParameters != 64 {
		t.Errorf("MaxParameters = %d, want 64", limits.MaxParameters)
	}
	if limits.MaxTokenLength != 256 {
		t.Errorf("MaxTokenLength = %d, want 256", limits.MaxTokenLength)
	}
}

func TestNoLimits(t *testing.T) {
	limits := NoLimits()

	// All values should be zero (disabled)
	if limits.MaxInputLength != 0 {
		t.Errorf("MaxInputLength = %d, want 0", limits.MaxInputLength)
	}
	if limits.MaxStringLength != 0 {
		t.Errorf("MaxStringLength = %d, want 0", limits.MaxStringLength)
	}
	if limits.MaxByteSequenceLength != 0 {
		t.Errorf("MaxByteSequenceLength = %d, want 0", limits.MaxByteSequenceLength)
	}
	if limits.MaxDictionaryMembers != 0 {
		t.Errorf("MaxDictionaryMembers = %d, want 0", limits.MaxDictionaryMembers)
	}
	if limits.MaxInnerListMembers != 0 {
		t.Errorf("MaxInnerListMembers = %d, want 0", limits.MaxInnerListMembers)
	}
	if limits.MaxParameters != 0 {
		t.Errorf("MaxParameters = %d, want 0", limits.MaxParameters)
	}
	if limits.MaxTokenLength != 0 {
		t.Errorf("MaxTokenLength = %d, want 0", limits.MaxTokenLength)
	}
}

func TestParserLimits_InputLength(t *testing.T) {
	limits := Limits{MaxInputLength: 100}
	input := strings.Repeat("a", 200) + "=1"
	p := NewParser(input, limits)
	_, err := p.ParseDictionary()

	if err == nil {
		t.Fatal("expected error for input exceeding length limit")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("error = %q, want to contain 'exceeds limit'", err.Error())
	}
}

func TestParserLimits_InputLengthWithinLimit(t *testing.T) {
	limits := Limits{MaxInputLength: 100}
	input := "a=1, b=2"
	p := NewParser(input, limits)
	_, err := p.ParseDictionary()

	if err != nil {
		t.Errorf("unexpected error for input within limit: %v", err)
	}
}

func TestParserLimits_DictionaryMembers(t *testing.T) {
	limits := Limits{MaxDictionaryMembers: 3}
	input := "a=1, b=2, c=3, d=4"
	p := NewParser(input, limits)
	_, err := p.ParseDictionary()

	if err == nil {
		t.Fatal("expected error for dictionary members exceeding limit")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("error = %q, want to contain 'exceeds limit'", err.Error())
	}
}

func TestParserLimits_DictionaryMembersAtLimit(t *testing.T) {
	limits := Limits{MaxDictionaryMembers: 3}
	input := "a=1, b=2, c=3"
	p := NewParser(input, limits)
	dict, err := p.ParseDictionary()

	if err != nil {
		t.Errorf("unexpected error for dictionary at limit: %v", err)
	}
	if len(dict.Keys) != 3 {
		t.Errorf("got %d keys, want 3", len(dict.Keys))
	}
}

func TestParserLimits_InnerListMembers(t *testing.T) {
	limits := Limits{MaxInnerListMembers: 3}
	input := "sig=(a b c d)"
	p := NewParser(input, limits)
	_, err := p.ParseDictionary()

	if err == nil {
		t.Fatal("expected error for inner list members exceeding limit")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("error = %q, want to contain 'exceeds limit'", err.Error())
	}
}

func TestParserLimits_InnerListMembersAtLimit(t *testing.T) {
	limits := Limits{MaxInnerListMembers: 3}
	input := "sig=(a b c)"
	p := NewParser(input, limits)
	_, err := p.ParseDictionary()

	if err != nil {
		t.Errorf("unexpected error for inner list at limit: %v", err)
	}
}

func TestParserLimits_Parameters(t *testing.T) {
	limits := Limits{MaxParameters: 2}
	input := "sig=();a;b;c"
	p := NewParser(input, limits)
	_, err := p.ParseDictionary()

	if err == nil {
		t.Fatal("expected error for parameters exceeding limit")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("error = %q, want to contain 'exceeds limit'", err.Error())
	}
}

func TestParserLimits_ParametersAtLimit(t *testing.T) {
	limits := Limits{MaxParameters: 2}
	input := "sig=();a;b"
	p := NewParser(input, limits)
	_, err := p.ParseDictionary()

	if err != nil {
		t.Errorf("unexpected error for parameters at limit: %v", err)
	}
}

func TestParserLimits_StringLength(t *testing.T) {
	limits := Limits{MaxStringLength: 10}
	input := `key="` + strings.Repeat("a", 20) + `"`
	p := NewParser(input, limits)
	_, err := p.ParseDictionary()

	if err == nil {
		t.Fatal("expected error for string exceeding length limit")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("error = %q, want to contain 'exceeds limit'", err.Error())
	}
}

func TestParserLimits_StringLengthAtLimit(t *testing.T) {
	limits := Limits{MaxStringLength: 10}
	input := `key="` + strings.Repeat("a", 10) + `"`
	p := NewParser(input, limits)
	_, err := p.ParseDictionary()

	if err != nil {
		t.Errorf("unexpected error for string at limit: %v", err)
	}
}

func TestParserLimits_TokenLength(t *testing.T) {
	limits := Limits{MaxTokenLength: 10}
	input := strings.Repeat("a", 20) + "=1"
	p := NewParser(input, limits)
	_, err := p.ParseDictionary()

	if err == nil {
		t.Fatal("expected error for token exceeding length limit")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("error = %q, want to contain 'exceeds limit'", err.Error())
	}
}

func TestParserLimits_TokenLengthAtLimit(t *testing.T) {
	limits := Limits{MaxTokenLength: 10}
	input := strings.Repeat("a", 10) + "=1"
	p := NewParser(input, limits)
	_, err := p.ParseDictionary()

	if err != nil {
		t.Errorf("unexpected error for token at limit: %v", err)
	}
}

func TestParserLimits_ByteSequenceLength(t *testing.T) {
	limits := Limits{MaxByteSequenceLength: 5}
	// Base64 "aGVsbG8gd29ybGQ=" decodes to "hello world" (11 bytes)
	input := "key=:aGVsbG8gd29ybGQ=:"
	p := NewParser(input, limits)
	_, err := p.ParseDictionary()

	if err == nil {
		t.Fatal("expected error for byte sequence exceeding length limit")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("error = %q, want to contain 'exceeds limit'", err.Error())
	}
}

func TestParserLimits_ByteSequenceLengthAtLimit(t *testing.T) {
	limits := Limits{MaxByteSequenceLength: 11}
	// Base64 "aGVsbG8gd29ybGQ=" decodes to "hello world" (11 bytes)
	input := "key=:aGVsbG8gd29ybGQ=:"
	p := NewParser(input, limits)
	_, err := p.ParseDictionary()

	if err != nil {
		t.Errorf("unexpected error for byte sequence at limit: %v", err)
	}
}

func TestParserLimits_DefaultsAcceptNormalInput(t *testing.T) {
	// Normal input should work with default limits
	input := `sig1=("@method" "@path");alg="rsa-pss-sha512";created=1618884473;keyid="test-key"`
	p := NewParser(input, DefaultLimits())
	dict, err := p.ParseDictionary()

	if err != nil {
		t.Errorf("default limits rejected normal input: %v", err)
	}
	if len(dict.Keys) != 1 {
		t.Errorf("got %d keys, want 1", len(dict.Keys))
	}
}

func TestParserLimits_NoLimitsAcceptLargeInput(t *testing.T) {
	// Large input should work with NoLimits
	// Create a large dictionary with many members
	var parts []string
	for i := range 1000 {
		// Each key must be unique - use index to differentiate
		parts = append(parts, "key"+strings.Repeat("x", i%50)+"v"+string(rune('a'+i%26))+"=1")
	}
	input := strings.Join(parts, ", ")

	p := NewParser(input, NoLimits())
	_, err := p.ParseDictionary()

	// Just verify it doesn't error on size - actual count may vary due to duplicate handling
	if err != nil {
		t.Errorf("NoLimits rejected large input: %v", err)
	}
}

func TestParserLimits_CustomLimits(t *testing.T) {
	// Test custom limits
	limits := DefaultLimits()
	limits.MaxDictionaryMembers = 5

	input := "a=1, b=2, c=3, d=4, e=5"
	p := NewParser(input, limits)
	dict, err := p.ParseDictionary()

	if err != nil {
		t.Errorf("custom limits rejected valid input: %v", err)
	}
	if len(dict.Keys) != 5 {
		t.Errorf("got %d keys, want 5", len(dict.Keys))
	}

	// Now exceed the limit
	input = "a=1, b=2, c=3, d=4, e=5, f=6"
	p = NewParser(input, limits)
	_, err = p.ParseDictionary()

	if err == nil {
		t.Fatal("custom limits should reject input exceeding limit")
	}
}
