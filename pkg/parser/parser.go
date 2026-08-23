package parser

import (
	"fmt"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/sfv"
)

// ParseSignatures parses RFC 9421 Signature-Input and Signature headers.
// Per Contract PS-001: Accepts RFC 8941 Dictionary format for both parameters.
// Per Contract PS-006: Returns descriptive errors, fails fast on validation errors.
// Per Contract PS-008: Thread-safe (stateless function).
//
// The limits parameter controls parser size limits for DoS prevention.
// Use sfv.DefaultLimits() for production, sfv.NoLimits() for trusted input.
//
// Example:
//
//	signatureInput := `sig1=("@method" "@path");alg="rsa-pss-sha512"`
//	signature := `sig1=:base64bytes:`
//	result, err := ParseSignatures(signatureInput, signature, sfv.DefaultLimits())
func ParseSignatures(signatureInput, signature string, limits sfv.Limits) (*ParsedSignatures, error) {
	// FR-020: Return error for empty headers
	if signatureInput == "" && signature == "" {
		return nil, fmt.Errorf("both Signature-Input and Signature headers are empty")
	}
	if signatureInput == "" {
		return nil, fmt.Errorf("header Signature-Input is empty")
	}
	if signature == "" {
		return nil, fmt.Errorf("header Signature is empty")
	}

	// T040: Parse Signature-Input header as RFC 8941 Dictionary
	inputParser := sfv.NewParser(signatureInput, limits)
	inputDict, err := inputParser.ParseDictionary()
	if err != nil {
		return nil, fmt.Errorf("failed to parse Signature-Input header: %w", err)
	}

	// T041: Parse Signature header as RFC 8941 Dictionary
	sigParser := sfv.NewParser(signature, limits)
	sigDict, err := sigParser.ParseDictionary()
	if err != nil {
		return nil, fmt.Errorf("failed to parse Signature header: %w", err)
	}

	// T042: Extract signature labels and validate label correspondence (FR-007, FR-008)
	// Contract PS-002: Every label in signatureInput must have entry in signature
	for _, label := range inputDict.Keys {
		if _, exists := sigDict.Values[label]; !exists {
			return nil, fmt.Errorf("header Signature-Input label %q has no corresponding Signature entry", label)
		}
	}

	// Contract PS-002: Every label in signature must have entry in signatureInput
	for _, label := range sigDict.Keys {
		if _, exists := inputDict.Values[label]; !exists {
			return nil, fmt.Errorf("header Signature label %q has no corresponding Signature-Input entry", label)
		}
	}

	result := &ParsedSignatures{
		Signatures: make(map[string]SignatureEntry),
	}

	// Process each signature label
	for _, label := range inputDict.Keys {
		entry, err := parseSignatureEntry(label, inputDict.Values[label], sigDict.Values[label])
		if err != nil {
			return nil, fmt.Errorf("failed to parse signature %q: %w", label, err)
		}
		result.Signatures[label] = entry
	}

	return result, nil
}

// ParseSignatureInput parses an RFC 9421 Signature-Input header.
// This is used for caching parsed metadata independently of signature values.
func ParseSignatureInput(signatureInput string, limits sfv.Limits) (*ParsedSignatures, error) {
	if signatureInput == "" {
		return nil, fmt.Errorf("header Signature-Input is empty")
	}

	inputParser := sfv.NewParser(signatureInput, limits)
	inputDict, err := inputParser.ParseDictionary()
	if err != nil {
		return nil, fmt.Errorf("failed to parse Signature-Input header: %w", err)
	}

	result := &ParsedSignatures{
		Signatures: make(map[string]SignatureEntry),
	}

	for _, label := range inputDict.Keys {
		// Extract covered components and parameters
		entry, err := parseSignatureEntryFromInput(label, inputDict.Values[label])
		if err != nil {
			return nil, fmt.Errorf("failed to parse signature input %q: %w", label, err)
		}
		result.Signatures[label] = entry
	}

	return result, nil
}

// parseSignatureEntryFromInput processes only the metadata part of a signature entry.
func parseSignatureEntryFromInput(label string, inputValue any) (SignatureEntry, error) {
	entry := SignatureEntry{
		Label: label,
	}

	inputInnerList, ok := inputValue.(sfv.InnerList)
	if !ok {
		return entry, fmt.Errorf("header Signature-Input value must be an inner list")
	}

	// Extract covered components and their parameters
	entry.CoveredComponents = make([]ComponentIdentifier, len(inputInnerList.Items))
	for i, item := range inputInnerList.Items {
		compName, ok := item.Value.(string)
		if !ok {
			return entry, fmt.Errorf("covered component must be a string, got %T", item.Value)
		}

		compType := ComponentField
		if len(compName) > 0 && compName[0] == '@' {
			compType = ComponentDerived
		}

		params := make([]Parameter, len(item.Parameters))
		for j, sfvParam := range item.Parameters {
			params[j] = Parameter{
				Key:   sfvParam.Key,
				Value: convertBareItem(sfvParam.Value),
			}
		}

		entry.CoveredComponents[i] = ComponentIdentifier{
			Name:       compName,
			Type:       compType,
			Parameters: params,
		}

		if err := validateComponentIdentifier(entry.CoveredComponents[i]); err != nil {
			return entry, fmt.Errorf("invalid component at position %d: %w", i, err)
		}
	}

	var err error
	entry.SignatureParams, err = extractSignatureParams(inputInnerList.Parameters)
	if err != nil {
		return entry, err
	}

	return entry, nil
}

// parseSignatureEntry processes a single signature entry.
func parseSignatureEntry(label string, inputValue, sigValue any) (SignatureEntry, error) {
	// Process the metadata part
	entry, err := parseSignatureEntryFromInput(label, inputValue)
	if err != nil {
		return entry, err
	}

	// T046: Decode signature value byte sequence (FR-006)
	sigItem, ok := sigValue.(sfv.Item)
	if !ok {
		return entry, fmt.Errorf("signature value must be an item")
	}

	sigBytes, ok := sigItem.Value.([]byte)
	if !ok {
		return entry, fmt.Errorf("signature value must be a byte sequence, got %T", sigItem.Value)
	}

	entry.SignatureValue = sigBytes

	return entry, nil
}

// extractSignatureParams extracts signature metadata parameters.
// Returns an error if a known parameter has an incorrect type per RFC 9421 Section 2.3.
// Unknown parameters are ignored to allow for future extensibility.
func extractSignatureParams(params []sfv.Parameter) (SignatureParams, error) {
	sp := SignatureParams{}

	for _, param := range params {
		var err error
		switch param.Key {
		case "created":
			sp.Created, err = extractIntParam(param.Key, param.Value)
		case "expires":
			sp.Expires, err = extractIntParam(param.Key, param.Value)
		case "nonce":
			sp.Nonce, err = extractStringParam(param.Key, param.Value)
		case "alg":
			sp.Algorithm, err = extractStringParam(param.Key, param.Value)
		case "keyid":
			sp.KeyID, err = extractStringParam(param.Key, param.Value)
		case "tag":
			sp.Tag, err = extractStringParam(param.Key, param.Value)
			// Unknown parameters are ignored per RFC 9421 (extensibility)
		}
		if err != nil {
			return sp, err
		}
	}

	// Algorithm is RECOMMENDED per RFC 9421 Section 2.3, but not strictly required
	// The RFC 9421 Appendix B test cases don't include 'alg', so we allow it to be empty
	// Note: Verifiers should reject signatures without 'alg' in production use

	return sp, nil
}

// extractIntParam type-asserts a signature parameter value as an integer.
func extractIntParam(key string, value any) (*int64, error) {
	val, ok := value.(int64)
	if !ok {
		return nil, fmt.Errorf("parameter '%s' must be an integer, got %T", key, value)
	}
	return &val, nil
}

// extractStringParam type-asserts a signature parameter value as a string.
func extractStringParam(key string, value any) (*string, error) {
	val, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("parameter '%s' must be a string, got %T", key, value)
	}
	return &val, nil
}

// convertBareItem converts SFV bare item to parser BareItemValue interface.
func convertBareItem(value any) BareItemValue {
	switch v := value.(type) {
	case bool:
		return Boolean{Value: v}
	case int64:
		return Integer{Value: v}
	case sfv.Token:
		// Token: unquoted identifier (preserved from parsing)
		return Token{Value: v.Value}
	case string:
		// String: quoted string value
		return String{Value: v}
	case []byte:
		return ByteSequence{Value: v}
	default:
		// Fallback: treat as string representation
		return String{Value: fmt.Sprint(v)}
	}
}
