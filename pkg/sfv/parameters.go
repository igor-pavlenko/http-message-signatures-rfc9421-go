package sfv

import "fmt"

// Parameter represents a key-value pair for RFC 8941 parameters.
type Parameter struct {
	Key   string
	Value any // bool, int64, string, or []byte
}

// parseParameters parses RFC 8941 parameters (zero or more ;key or ;key=value).
// Preserves insertion order per FR-012.
func (p *Parser) parseParameters() ([]Parameter, error) {
	var params []Parameter

	for p.peek() == ';' {
		// Check parameter count limit before parsing next parameter
		if p.limits.MaxParameters > 0 && len(params) >= p.limits.MaxParameters {
			return nil, p.newParseError(fmt.Sprintf("parameters count %d exceeds limit %d",
				len(params)+1, p.limits.MaxParameters))
		}

		p.offset++ // consume ';'

		// Parse parameter key (token)
		keyToken, err := p.parseToken()
		if err != nil {
			return nil, err
		}

		var value any = true // Default: bare parameter = boolean true

		// Check for =value
		if p.peek() == '=' {
			p.offset++ // consume '='

			// Parse parameter value (bare item)
			// Note: parseBareItem returns Token for tokens, string for quoted strings
			value, err = p.parseBareItem()
			if err != nil {
				return nil, err
			}
		}

		params = append(params, Parameter{
			Key:   keyToken.Value,
			Value: value,
		})
	}

	return params, nil
}
