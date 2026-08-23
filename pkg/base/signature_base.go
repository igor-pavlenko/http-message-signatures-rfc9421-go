package base

import (
	"strings"
)

// assembleSignatureBase joins component lines with the signature-params line per RFC 9421 Section 2.5.
//
// RFC 9421 Section 2.5 Signature Base Format:
//
//	"component-1": value1
//	"component-2": value2
//	"@signature-params": (component-identifiers);param1=value1
//
// Key Requirements:
// - Lines are joined with LF (\n) character
// - NO trailing newline after @signature-params
// - Empty component lines are allowed (RFC 9421 Appendix B.2.1)
//
// Example:
//
//	componentLines = ["\"@method\": POST", "\"@path\": /foo"]
//	signatureParamsLine = "\"@signature-params\": (\"@method\" \"@path\")"
//	Result: "\"@method\": POST\n\"@path\": /foo\n\"@signature-params\": (\"@method\" \"@path\")"
func assembleSignatureBase(componentLines []string, signatureParamsLine string) string {
	// Pre-calculate total size for efficient memory allocation
	totalSize := len(signatureParamsLine)
	for _, line := range componentLines {
		totalSize += len(line) + 1 // +1 for newline
	}

	var sb strings.Builder
	sb.Grow(totalSize)

	// Add component lines with LF separators
	for i, line := range componentLines {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(line)
	}

	// Add @signature-params line
	if len(componentLines) > 0 {
		sb.WriteString("\n")
	}
	sb.WriteString(signatureParamsLine)

	return sb.String()
}
