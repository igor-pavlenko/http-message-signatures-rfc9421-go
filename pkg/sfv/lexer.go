// Package sfv implements RFC 8941 Structured Field Values parsing.
// This is a zero-dependency implementation designed for portability.
package sfv

import "fmt"

// Parser is a character-based scanner for RFC 8941 Structured Field Values.
// It maintains an immutable input string and a current position offset.
// This design enables zero-copy parsing and is portable across languages.
type Parser struct {
	data   string // immutable input
	offset int    // current position
	limits Limits // size limits for DoS prevention
}

// NewParser creates a new parser with the specified limits.
// Use DefaultLimits() for production, NoLimits() for trusted input.
//
// Example:
//
//	parser := sfv.NewParser(headerValue, sfv.DefaultLimits())
//	dict, err := parser.ParseDictionary()
func NewParser(data string, limits Limits) *Parser {
	return &Parser{
		data:   data,
		offset: 0,
		limits: limits,
	}
}

// peek returns the current byte without advancing the offset.
// Returns 0 (EOF marker) if at or past end of input.
func (p *Parser) peek() byte {
	if p.offset >= len(p.data) {
		return 0 // EOF
	}
	return p.data[p.offset]
}

// consume checks if the current byte matches the expected byte.
// If it matches, advances the offset and returns true.
// Otherwise, returns false without advancing.
func (p *Parser) consume(expected byte) bool {
	if p.peek() == expected {
		p.offset++
		return true
	}
	return false
}

// skipOWS skips optional whitespace (OWS): SP (0x20) or HTAB (0x09).
// Used between dictionary entries per RFC 8941.
func (p *Parser) skipOWS() {
	for p.offset < len(p.data) {
		c := p.data[p.offset]
		if c == ' ' || c == '\t' {
			p.offset++
		} else {
			break
		}
	}
}

// skipSP skips only space characters (SP, 0x20), not tabs.
// Used within inner lists per RFC 8941 Section 4.2.1.2.
func (p *Parser) skipSP() {
	for p.offset < len(p.data) && p.data[p.offset] == ' ' {
		p.offset++
	}
}

// isEOF returns true if the parser is at or past the end of input.
func (p *Parser) isEOF() bool {
	return p.offset >= len(p.data)
}

// getContext returns a snippet of the input around the current offset
// for error reporting (up to 40 characters).
func (p *Parser) getContext() string {
	start := max(p.offset-20, 0)
	end := min(p.offset+20, len(p.data))

	context := p.data[start:end]
	if start > 0 {
		context = "..." + context
	}
	if end < len(p.data) {
		context = context + "..."
	}

	return context
}

// ParseError represents a parsing error with location context.
// Per research.md Section 1, errors include offset, message, and context.
type ParseError struct {
	Offset  int    // character position where error occurred
	Message string // human-readable description
	Context string // surrounding input for debugging
}

// Error returns a formatted error message per Contract ER-001.
func (e *ParseError) Error() string {
	return fmt.Sprintf("parse error at offset %d: %s (near: %q)", e.Offset, e.Message, e.Context)
}

// newParseError creates a ParseError at the current parser offset.
func (p *Parser) newParseError(message string) *ParseError {
	return &ParseError{
		Offset:  p.offset,
		Message: message,
		Context: p.getContext(),
	}
}

// checkInputLength validates input length against limits.
// Should be called at the start of top-level parse operations.
func (p *Parser) checkInputLength() error {
	if p.limits.MaxInputLength > 0 && len(p.data) > p.limits.MaxInputLength {
		return p.newParseError(fmt.Sprintf("input length %d exceeds limit %d",
			len(p.data), p.limits.MaxInputLength))
	}
	return nil
}
