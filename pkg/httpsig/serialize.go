package httpsig

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/sfv"
)

func serializeSignatureInput(
	label string,
	components []parser.ComponentIdentifier,
	params parser.SignatureParams,
) (string, error) {
	if label == "" {
		return "", fmt.Errorf("signature label is required")
	}

	sigInputDict := &sfv.Dictionary{
		Keys:   []string{label},
		Values: make(map[string]any),
	}

	items := make([]sfv.Item, len(components))
	for i, comp := range components {
		items[i] = sfv.Item{
			Value:      comp.Name,
			Parameters: componentParamsToSFV(comp.Parameters),
		}
	}

	innerList := sfv.InnerList{
		Items:      items,
		Parameters: signatureParamsToSFV(params),
	}
	sigInputDict.Values[label] = innerList

	return sfv.SerializeDictionary(sigInputDict)
}

func serializeSignature(label string, signature []byte) (string, error) {
	if label == "" {
		return "", fmt.Errorf("signature label is required")
	}

	// Optimization: For a single signature label, we can avoid the overhead
	// of creating an sfv.Dictionary and use direct serialization.
	// Format: label=:base64:
	encoded := base64.StdEncoding.EncodeToString(signature)

	var sb strings.Builder
	sb.Grow(len(label) + len(encoded) + 3) // +1 for '=', +2 for ':'
	sb.WriteString(label)
	sb.WriteString("=:")
	sb.WriteString(encoded)
	sb.WriteRune(':')

	return sb.String(), nil
}

func componentParamsToSFV(params []parser.Parameter) []sfv.Parameter {
	if len(params) == 0 {
		return nil
	}

	result := make([]sfv.Parameter, len(params))
	for i, p := range params {
		result[i] = sfv.Parameter{Key: p.Key, Value: bareItemToSFV(p.Value)}
	}

	return result
}

func signatureParamsToSFV(params parser.SignatureParams) []sfv.Parameter {
	var result []sfv.Parameter

	if params.Created != nil {
		result = append(result, sfv.Parameter{Key: "created", Value: *params.Created})
	}
	if params.Expires != nil {
		result = append(result, sfv.Parameter{Key: "expires", Value: *params.Expires})
	}
	if params.Nonce != nil {
		result = append(result, sfv.Parameter{Key: "nonce", Value: *params.Nonce})
	}
	if params.Algorithm != nil {
		result = append(result, sfv.Parameter{Key: "alg", Value: *params.Algorithm})
	}
	if params.KeyID != nil {
		result = append(result, sfv.Parameter{Key: "keyid", Value: *params.KeyID})
	}
	if params.Tag != nil {
		result = append(result, sfv.Parameter{Key: "tag", Value: *params.Tag})
	}

	return result
}

func bareItemToSFV(item parser.BareItemValue) any {
	switch v := item.(type) {
	case parser.Boolean:
		return v.Value
	case parser.Integer:
		return v.Value
	case parser.String:
		return v.Value
	case parser.Token:
		return sfv.Token{Value: v.Value}
	case parser.ByteSequence:
		return v.Value
	default:
		return nil
	}
}
