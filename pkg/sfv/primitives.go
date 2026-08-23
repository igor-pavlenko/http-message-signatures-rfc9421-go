package sfv

import (
	"encoding/base64"
	"fmt"
	"strconv"
)

// Token represents an RFC 8941 token (unquoted identifier).
// Tokens are distinct from strings: they are serialized without quotes.
type Token struct {
	Value string
}

// parseBoolean parses an RFC 8941 boolean: ?0 (false) or ?1 (true).
func (p *Parser) parseBoolean() (bool, error) {
	if !p.consume('?') {
		return false, p.newParseError("expected '?' at start of boolean")
	}

	c := p.peek()
	if c == '1' {
		p.offset++
		return true, nil
	} else if c == '0' {
		p.offset++
		return false, nil
	}

	return false, p.newParseError("expected '0' or '1' after '?'")
}

// parseInteger parses an RFC 8941 integer (max 15 digits).
func (p *Parser) parseInteger() (int64, error) {
	start := p.offset

	// Check for negative sign
	if p.peek() == '-' {
		p.offset++
	}

	// Parse digits
	digitStart := p.offset
	for p.offset < len(p.data) {
		c := p.data[p.offset]
		if c >= '0' && c <= '9' {
			p.offset++
		} else {
			break
		}
	}

	if p.offset == digitStart {
		return 0, p.newParseError("expected digit in integer")
	}

	// Check 15-digit limit (RFC 8941 Section 3.3.1)
	digitCount := p.offset - digitStart
	if digitCount > 15 {
		return 0, p.newParseError("integer exceeds 15 digit limit")
	}

	valueStr := p.data[start:p.offset]
	value, err := strconv.ParseInt(valueStr, 10, 64)
	if err != nil {
		return 0, p.newParseError("invalid integer: " + err.Error())
	}

	return value, nil
}

// parseString parses an RFC 8941 string (quoted, with escape sequences).
// Only \" and \\ are valid escape sequences.
func (p *Parser) parseString() (string, error) {
	if !p.consume('"') {
		return "", p.newParseError("expected '\"' at start of string")
	}

	start := p.offset
	hasEscapes := false

	for {
		if p.isEOF() {
			return "", p.newParseError("unexpected EOF in string (missing closing quote)")
		}

		c := p.data[p.offset]

		if c == '"' {
			// End of string
			val := p.data[start:p.offset]
			p.offset++ // consume closing quote

			if !hasEscapes {
				// Optimization: zero-copy substring if no escapes
				return val, nil
			}

			// Slow path: handle escapes
			return p.decodeString(val)
		}

		if c == '\\' {
			hasEscapes = true
			p.offset++ // skip backslash
			if p.isEOF() {
				return "", p.newParseError("unexpected EOF after backslash")
			}
		} else if c < 0x20 || c > 0x7E {
			// Control characters and non-ASCII not allowed
			return "", p.newParseError("invalid character in string (must be printable ASCII)")
		}

		p.offset++

		// Check string length limit during parsing to fail fast
		if p.limits.MaxStringLength > 0 && (p.offset-start) > p.limits.MaxStringLength {
			return "", p.newParseError(fmt.Sprintf("string length %d exceeds limit %d",
				p.offset-start, p.limits.MaxStringLength))
		}
	}
}

// decodeString handles escape sequences in SFV strings.
func (p *Parser) decodeString(val string) (string, error) {
	var buf []byte
	for i := 0; i < len(val); i++ {
		c := val[i]
		if c == '\\' {
			i++
			if i >= len(val) {
				return "", p.newParseError("unexpected end of string after backslash")
			}
			escaped := val[i]
			if escaped != '"' && escaped != '\\' {
				return "", p.newParseError("invalid escape sequence")
			}
			buf = append(buf, escaped)
		} else {
			buf = append(buf, c)
		}

		if p.limits.MaxStringLength > 0 && len(buf) > p.limits.MaxStringLength {
			return "", p.newParseError(fmt.Sprintf("string length %d exceeds limit %d",
				len(buf), p.limits.MaxStringLength))
		}
	}
	return string(buf), nil
}

// parseToken parses an RFC 8941 token (unquoted identifier).
// Must start with alpha or *, followed by allowed chars.
// Returns Token type to distinguish from quoted strings.
func (p *Parser) parseToken() (Token, error) {
	start := p.offset

	if p.isEOF() {
		return Token{}, p.newParseError("expected token, got EOF")
	}

	// First character: must be alpha or *
	c := p.data[p.offset]
	if !isAlpha(c) && c != '*' {
		return Token{}, p.newParseError("token must start with letter or *")
	}
	p.offset++

	// Subsequent characters: tchar (alphanumeric or allowed punctuation)
	for p.offset < len(p.data) {
		c := p.data[p.offset]
		if isTokenChar(c) {
			p.offset++
		} else {
			break
		}
	}

	if p.offset == start {
		return Token{}, p.newParseError("empty token")
	}

	tokenLen := p.offset - start
	// Check token length limit
	if p.limits.MaxTokenLength > 0 && tokenLen > p.limits.MaxTokenLength {
		return Token{}, p.newParseError(fmt.Sprintf("token length %d exceeds limit %d",
			tokenLen, p.limits.MaxTokenLength))
	}

	return Token{Value: p.data[start:p.offset]}, nil
}

// parseByteSequence parses an RFC 8941 byte sequence (:base64:).
func (p *Parser) parseByteSequence() ([]byte, error) {
	if !p.consume(':') {
		return nil, p.newParseError("expected ':' at start of byte sequence")
	}

	start := p.offset

	// Find closing colon
	for p.offset < len(p.data) {
		c := p.data[p.offset]
		if c == ':' {
			break
		}
		// Valid base64 characters
		if !isBase64Char(c) {
			return nil, p.newParseError("invalid character in byte sequence")
		}
		p.offset++
	}

	if p.isEOF() || p.peek() != ':' {
		return nil, p.newParseError("expected closing ':' for byte sequence")
	}

	base64Str := p.data[start:p.offset]
	p.offset++ // consume closing ':'

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		// Try raw encoding (without padding)
		decoded, err = base64.RawStdEncoding.DecodeString(base64Str)
		if err != nil {
			return nil, p.newParseError("invalid base64 in byte sequence: " + err.Error())
		}
	}

	// Check decoded byte sequence length limit
	if p.limits.MaxByteSequenceLength > 0 && len(decoded) > p.limits.MaxByteSequenceLength {
		return nil, p.newParseError(fmt.Sprintf("byte sequence length %d exceeds limit %d",
			len(decoded), p.limits.MaxByteSequenceLength))
	}

	return decoded, nil
}

// Helper functions

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isTokenChar(c byte) bool {
	// RFC 8941 tchar: ALPHA / DIGIT / "_" / "-" / "." / ":" / "%" / "*" / "/"
	return isAlpha(c) || isDigit(c) || c == '_' || c == '-' || c == '.' ||
		c == ':' || c == '%' || c == '*' || c == '/'
}

func isBase64Char(c byte) bool {
	return isAlpha(c) || isDigit(c) || c == '+' || c == '/' || c == '='
}
