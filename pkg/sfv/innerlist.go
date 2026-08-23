package sfv

import "fmt"

// Item represents an RFC 8941 item (bare item with optional parameters).
type Item struct {
	Value      any
	Parameters []Parameter
}

// parseInnerList parses an RFC 8941 inner list: (item1 item2 ...).
// Items are separated by SP (0x20), not OWS.
// Returns the items and parameters on the inner list itself.
func (p *Parser) parseInnerList() ([]Item, []Parameter, error) {
	if !p.consume('(') {
		return nil, nil, p.newParseError("expected '(' at start of inner list")
	}

	var items []Item

	// Parse items separated by SP
	for {
		p.skipSP() // Skip spaces between items (RFC 8941: SP only, not OWS)

		if p.peek() == ')' {
			// End of inner list
			break
		}

		// Check inner list member limit before parsing next item
		if p.limits.MaxInnerListMembers > 0 && len(items) >= p.limits.MaxInnerListMembers {
			return nil, nil, p.newParseError(fmt.Sprintf("inner list members %d exceeds limit %d",
				len(items)+1, p.limits.MaxInnerListMembers))
		}

		// Parse bare item
		value, err := p.parseBareItem()
		if err != nil {
			return nil, nil, err
		}

		// Parse item parameters
		params, err := p.parseParameters()
		if err != nil {
			return nil, nil, err
		}

		items = append(items, Item{
			Value:      value,
			Parameters: params,
		})
	}

	if !p.consume(')') {
		return nil, nil, p.newParseError("expected ')' at end of inner list")
	}

	// Parse parameters on the inner list itself
	listParams, err := p.parseParameters()
	if err != nil {
		return nil, nil, err
	}

	return items, listParams, nil
}

// ParseItem parses an RFC 8941 item (bare item with optional parameters).
// This is exported for use by the base package for structured field processing.
func (p *Parser) ParseItem() (*Item, error) {
	// Parse bare item value
	value, err := p.parseBareItem()
	if err != nil {
		return nil, err
	}

	// Parse parameters
	params, err := p.parseParameters()
	if err != nil {
		return nil, err
	}

	return &Item{
		Value:      value,
		Parameters: params,
	}, nil
}
