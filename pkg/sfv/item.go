package sfv

// parseBareItem parses an RFC 8941 bare item using 1-2 character lookahead
// to determine the type. Returns the parsed value (bool, int64, string, or []byte).
func (p *Parser) parseBareItem() (any, error) {
	if p.isEOF() {
		return nil, p.newParseError("expected bare item, got EOF")
	}

	c := p.peek()

	// Type detection via lookahead (research.md Section 1)
	switch {
	case c == '?':
		// Boolean: ?0 or ?1
		return p.parseBoolean()

	case c == '-' || (c >= '0' && c <= '9'):
		// Integer: optional '-' followed by digits
		return p.parseInteger()

	case c == '"':
		// String: quoted with escape sequences
		return p.parseString()

	case c == ':':
		// Byte sequence: :base64:
		return p.parseByteSequence()

	case c == '*' || isAlpha(c):
		// Token: starts with alpha or *
		return p.parseToken()

	default:
		return nil, p.newParseError("invalid bare item start character")
	}
}
