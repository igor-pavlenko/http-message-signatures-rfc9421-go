package base

import (
	"fmt"
	"strings"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
)

// Build constructs the signature base string per RFC 9421 Section 2.5.
//
// The signature base is a canonicalized representation of the HTTP message
// components that will be cryptographically signed. It consists of:
// 1. Component lines: one per covered component
// 2. @signature-params line: metadata about the signature
//
// Parameters:
//   - msg: The HTTP message (request or response) to build the signature base from
//   - components: Ordered list of components to cover in the signature
//   - params: Signature metadata (created, expires, nonce, alg, keyid, tag)
//
// Returns:
//   - The signature base string ready for cryptographic signing
//   - Error if any component cannot be extracted or is invalid
//
// RFC 9421 Section 2.5 Format:
//
//	"component-1": value1
//	"component-2": value2
//	"@signature-params": (component-identifiers);param1=value1
//
// Example:
//
//	components := []parser.ComponentIdentifier{
//	    {Name: "@method", Type: parser.ComponentDerived},
//	    {Name: "content-type", Type: parser.ComponentField},
//	}
//	params := parser.SignatureParams{
//	    Created: ptr(time.Now().Unix()),
//	    KeyID:   ptr("my-key-id"),
//	}
//	signatureBase, err := base.Build(msg, components, params)
//
// Contract Guarantees (per contracts/builder-api.md):
//   - Output is deterministic for the same inputs
//   - No trailing newline after @signature-params
//   - Lines joined with LF (\n) character
//   - Component values preserve exact whitespace
//   - Empty component lists are valid (RFC 9421 B.2.1)
func Build(msg HTTPMessage, components []parser.ComponentIdentifier, params parser.SignatureParams) (string, error) {
	var sb strings.Builder

	for i, comp := range components {
		// Extract the component value from the HTTP message
		value, err := extractComponentValue(msg, comp)
		if err != nil {
			return "", fmt.Errorf("failed to extract component %q: %w", comp.Name, err)
		}

		// Format the component line
		if i > 0 {
			sb.WriteString("\n")
		}
		writeComponentLine(&sb, comp, value)
	}

	// Format the @signature-params line
	if len(components) > 0 {
		sb.WriteString("\n")
	}
	writeSignatureParamsLine(&sb, components, params)

	return sb.String(), nil
}
