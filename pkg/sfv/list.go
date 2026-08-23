package sfv

import "fmt"

// ParseList parses an RFC 8941 list.
// Format: member1, member2, ...
// Members can be inner lists (parenthesized) or items.
func (p *Parser) ParseList() (*List, error) {
	// Check input length limit at start
	if err := p.checkInputLength(); err != nil {
		return nil, err
	}

	list := &List{
		Members: make([]any, 0),
	}

	if p.isEOF() {
		// Empty list is valid
		return list, nil
	}

	for {
		if p.isEOF() {
			break
		}

		// Check list member limit before parsing next entry
		// Use MaxDictionaryMembers as the limit for list members
		if p.limits.MaxDictionaryMembers > 0 && len(list.Members) >= p.limits.MaxDictionaryMembers {
			return nil, p.newParseError(fmt.Sprintf("list members %d exceeds limit %d",
				len(list.Members)+1, p.limits.MaxDictionaryMembers))
		}

		member, err := p.parseValue()
		if err != nil {
			return nil, err
		}

		list.Members = append(list.Members, member)

		p.skipOWS() // Skip whitespace after member

		// Check for comma separator
		if p.peek() == ',' {
			p.offset++ // consume ','
			p.skipOWS()

			// Reject trailing comma (RFC 8941 Section 4.2.1)
			if p.isEOF() {
				return nil, p.newParseError("trailing comma in list not allowed")
			}
		} else {
			// No comma: end of list
			break
		}
	}

	return list, nil
}

// parseValue parses a single RFC 8941 value, which is either an inner
// list (parenthesized) or an item. Shared by list and dictionary parsing.
func (p *Parser) parseValue() (any, error) {
	if p.peek() == '(' {
		items, params, err := p.parseInnerList()
		if err != nil {
			return nil, err
		}
		return InnerList{
			Items:      items,
			Parameters: params,
		}, nil
	}

	itemValue, err := p.parseBareItem()
	if err != nil {
		return nil, err
	}

	itemParams, err := p.parseParameters()
	if err != nil {
		return nil, err
	}

	return Item{
		Value:      itemValue,
		Parameters: itemParams,
	}, nil
}
