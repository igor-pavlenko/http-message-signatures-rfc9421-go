package base

import (
	"strings"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
)

// formatComponentLine constructs a component line per RFC 9421 Section 2.5.
//
// Format: "component-identifier": component-value
//
// The component identifier includes the name and any parameters.
// The component value is the canonicalized value extracted from the HTTP message.
//
// RFC 9421 Section 2.5:
// - Component name is lowercased (for HTTP fields) or starts with @ (for derived components)
// - Component identifier is quoted
// - Colon and space separate identifier from value
// - Component value preserves exact formatting including whitespace
//
// Example:
//
//	"content-type": application/json
//	"@method": POST
//	"example-dict";key="member-key": member-value
func formatComponentLine(comp parser.ComponentIdentifier, value string) string {
	var sb strings.Builder
	writeComponentLine(&sb, comp, value)
	return sb.String()
}

func writeComponentLine(sb *strings.Builder, comp parser.ComponentIdentifier, value string) {
	// Format the component identifier (name + parameters)
	writeComponentIdentifier(sb, comp)

	// Add separator (colon + space)
	sb.WriteRune(':')
	sb.WriteRune(' ')

	// Add the component value (preserve exact formatting)
	sb.WriteString(value)
}
