package sfv

import "fmt"

// InnerList represents an RFC 8941 inner list with parameters.
type InnerList struct {
	Items      []Item
	Parameters []Parameter
}

// List represents an RFC 8941 list (sequence of members).
// Members can be Items or InnerLists.
type List struct {
	Members []any // Each member is Item or InnerList
}

// Dictionary represents an RFC 8941 dictionary (ordered map).
// Preserves insertion order via Keys slice.
// Last instance wins for duplicate keys.
type Dictionary struct {
	Keys   []string       // Ordered keys (insertion order, duplicates removed)
	Values map[string]any // Key -> InnerList or Item
}

// ParseDictionary parses an RFC 8941 dictionary.
// Format: key1=value1, key2=value2, ...
// Values can be inner lists or items.
// This is exported for use by the parser package.
func (p *Parser) ParseDictionary() (*Dictionary, error) {
	// Check input length limit at start
	if err := p.checkInputLength(); err != nil {
		return nil, err
	}

	dict := &Dictionary{
		Keys:   make([]string, 0),
		Values: make(map[string]any),
	}

	if p.isEOF() {
		// Empty dictionary is valid
		return dict, nil
	}

	for {
		if p.isEOF() {
			break
		}

		// Check dictionary member limit before parsing next entry
		if p.limits.MaxDictionaryMembers > 0 && len(dict.Keys) >= p.limits.MaxDictionaryMembers {
			return nil, p.newParseError(fmt.Sprintf("dictionary members %d exceeds limit %d",
				len(dict.Keys)+1, p.limits.MaxDictionaryMembers))
		}

		key, value, err := p.parseDictionaryMember()
		if err != nil {
			return nil, err
		}

		// Store value (last instance wins for duplicates)
		if _, exists := dict.Values[key]; !exists {
			// New key: append to ordered keys
			dict.Keys = append(dict.Keys, key)
		}
		dict.Values[key] = value

		p.skipOWS() // Skip whitespace after value

		// Check for comma separator
		if p.peek() == ',' {
			p.offset++ // consume ','
			p.skipOWS()

			// Reject trailing comma (RFC 8941 Section 4.2.2)
			if p.isEOF() {
				return nil, p.newParseError("trailing comma in dictionary not allowed")
			}
		} else {
			// No comma: end of dictionary
			break
		}
	}

	return dict, nil
}

// parseDictionaryMember parses a single "key" or "key=value" dictionary
// entry per RFC 8941 Section 4.2.2.
func (p *Parser) parseDictionaryMember() (string, any, error) {
	keyToken, err := p.parseToken()
	if err != nil {
		return "", nil, err
	}
	key := keyToken.Value

	// RFC 8941: No OWS allowed between key and '=' or between '=' and value
	c := p.peek()
	if c == ' ' || c == '\t' {
		return "", nil, p.newParseError("whitespace not allowed before '=' in dictionary")
	}

	if c != '=' {
		// Bare key = boolean true item
		return key, Item{Value: true, Parameters: nil}, nil
	}

	p.offset++ // consume '='
	value, err := p.parseValue()
	if err != nil {
		return "", nil, err
	}
	return key, value, nil
}
