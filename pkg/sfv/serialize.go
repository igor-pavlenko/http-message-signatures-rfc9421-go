package sfv

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// SerializeItem serializes an RFC 8941 Item to its canonical string representation.
// Format: bare-item[;param1=value1;param2=value2...]
func SerializeItem(item Item) (string, error) {
	var sb strings.Builder
	if err := writeItem(&sb, item); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func writeItem(sb *strings.Builder, item Item) error {
	// Serialize bare item value
	if err := writeBareItem(sb, item.Value); err != nil {
		return err
	}

	// Serialize parameters
	if len(item.Parameters) > 0 {
		if err := writeParameters(sb, item.Parameters); err != nil {
			return err
		}
	}

	return nil
}

// SerializeInnerList serializes an RFC 8941 InnerList to its canonical string representation.
// Format: (item1 item2 ...)[;param1=value1;param2=value2...]
func SerializeInnerList(innerList InnerList) (string, error) {
	var sb strings.Builder
	if err := writeInnerList(&sb, innerList); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func writeInnerList(sb *strings.Builder, innerList InnerList) error {
	sb.WriteRune('(')

	// Serialize items
	for i, item := range innerList.Items {
		if i > 0 {
			sb.WriteRune(' ')
		}

		if err := writeItem(sb, item); err != nil {
			return err
		}
	}

	sb.WriteRune(')')

	// Serialize parameters
	if len(innerList.Parameters) > 0 {
		if err := writeParameters(sb, innerList.Parameters); err != nil {
			return err
		}
	}

	return nil
}

// SerializeDictionary serializes an RFC 8941 Dictionary to its canonical string representation.
// Format: key1=value1, key2=value2, ...
func SerializeDictionary(dict *Dictionary) (string, error) {
	if len(dict.Keys) == 0 {
		return "", nil
	}

	var sb strings.Builder
	if err := writeDictionary(&sb, dict); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func writeDictionary(sb *strings.Builder, dict *Dictionary) error {
	for i, key := range dict.Keys {
		if i > 0 {
			sb.WriteString(", ")
		}

		// Write key
		sb.WriteString(key)

		value := dict.Values[key]

		// Check if value is boolean true (bare key)
		if item, ok := value.(Item); ok {
			if boolVal, isBool := item.Value.(bool); isBool && boolVal && len(item.Parameters) == 0 {
				// Bare key (boolean true with no parameters)
				continue
			}
		}

		// Write '=' and value
		sb.WriteRune('=')

		switch v := value.(type) {
		case Item:
			if err := writeItem(sb, v); err != nil {
				return err
			}

		case InnerList:
			if err := writeInnerList(sb, v); err != nil {
				return err
			}

		default:
			return fmt.Errorf("invalid dictionary value type: %T", value)
		}
	}

	return nil
}

// SerializeList serializes an RFC 8941 List to its canonical string representation.
// Format: member1, member2, ...
func SerializeList(list *List) (string, error) {
	if len(list.Members) == 0 {
		return "", nil
	}

	var sb strings.Builder
	if err := writeList(&sb, list); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func writeList(sb *strings.Builder, list *List) error {
	for i, member := range list.Members {
		if i > 0 {
			sb.WriteString(", ")
		}

		switch v := member.(type) {
		case Item:
			if err := writeItem(sb, v); err != nil {
				return err
			}

		case InnerList:
			if err := writeInnerList(sb, v); err != nil {
				return err
			}

		default:
			return fmt.Errorf("invalid list member type: %T", member)
		}
	}

	return nil
}

func writeBareItem(sb *strings.Builder, value any) error {
	switch v := value.(type) {
	case bool:
		// Boolean: ?0 or ?1
		if v {
			sb.WriteString("?1")
		} else {
			sb.WriteString("?0")
		}
		return nil

	case int64:
		// Integer: decimal representation
		sb.WriteString(strconv.FormatInt(v, 10))
		return nil

	case int:
		// Integer: decimal representation
		sb.WriteString(strconv.Itoa(v))
		return nil

	case Token:
		// Token: serialize as bare token (unquoted)
		sb.WriteString(v.Value)
		return nil

	case string:
		// String: serialize as quoted string with escape sequences
		writeString(sb, v)
		return nil

	case []byte:
		// Byte sequence: :base64:
		sb.WriteRune(':')
		encoded := base64.StdEncoding.EncodeToString(v)
		sb.WriteString(encoded)
		sb.WriteRune(':')
		return nil

	default:
		// Assume it's a token (string-like)
		if str, ok := v.(string); ok {
			sb.WriteString(str)
			return nil
		}
		return fmt.Errorf("unsupported bare item type: %T", value)
	}
}

// SerializeString serializes a string to RFC 8941 quoted string format.
// It escapes backslashes and double quotes per RFC 8941 Section 3.3.3.
func SerializeString(s string) string {
	var sb strings.Builder
	writeString(&sb, s)
	return sb.String()
}

func writeString(sb *strings.Builder, s string) {
	sb.WriteRune('"')

	for _, r := range s {
		if r == '\\' || r == '"' {
			sb.WriteRune('\\')
		}
		sb.WriteRune(r)
	}

	sb.WriteRune('"')
}

func writeParameters(sb *strings.Builder, params []Parameter) error {
	for _, param := range params {
		sb.WriteRune(';')
		sb.WriteString(param.Key)

		// Boolean true parameters can be bare
		if boolVal, ok := param.Value.(bool); ok && boolVal {
			// Bare parameter (boolean true)
			continue
		}

		// Non-true values need '=' and value
		sb.WriteRune('=')

		if err := writeBareItem(sb, param.Value); err != nil {
			return err
		}
	}

	return nil
}

// isValidToken checks if a string is a valid RFC 8941 token.
// RFC 8941 Section 3.3.4: Tokens start with alpha or * and contain alphanumeric, *, _, -, ., :, /, or %
func isValidToken(s string) bool {
	if len(s) == 0 {
		return false
	}

	// First character must be alpha or *
	first := rune(s[0])
	if !unicode.IsLetter(first) && first != '*' {
		return false
	}

	// Remaining characters must be alphanumeric or one of: * _ - . : / %
	for _, r := range s[1:] {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) &&
			r != '*' && r != '_' && r != '-' && r != '.' &&
			r != ':' && r != '/' && r != '%' {
			return false
		}
	}

	return true
}
