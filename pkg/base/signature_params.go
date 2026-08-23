package base

import (
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/sfv"
)

// formatSignatureParamsLine constructs the @signature-params line per RFC 9421 Section 2.5.
//
// The @signature-params line contains:
// 1. The covered component identifiers as an inner list
// 2. The signature metadata parameters (created, expires, nonce, alg, keyid, tag)
//
// Format: "@signature-params": (component-identifiers);param1=value1;param2=value2
//
// RFC 9421 Section 2.3: All signature parameters are optional.
// RFC 9421 Section 2.5: Parameters must appear in canonical order.
func formatSignatureParamsLine(components []parser.ComponentIdentifier, params parser.SignatureParams) string {
	var sb strings.Builder
	writeSignatureParamsLine(&sb, components, params)
	return sb.String()
}

func writeSignatureParamsLine(sb *strings.Builder, components []parser.ComponentIdentifier, params parser.SignatureParams) {
	// Start with the component name
	sb.WriteString(`"@signature-params": (`)

	// Add component identifiers
	for i, comp := range components {
		if i > 0 {
			sb.WriteString(" ")
		}
		writeComponentIdentifier(sb, comp)
	}

	sb.WriteString(")")

	// Add signature metadata parameters in canonical order
	// RFC 9421 Section 2.3 defines the order: created, expires, nonce, alg, keyid, tag
	if params.Created != nil {
		sb.WriteString(";created=")
		sb.WriteString(strconv.FormatInt(*params.Created, 10))
	}
	if params.Expires != nil {
		sb.WriteString(";expires=")
		sb.WriteString(strconv.FormatInt(*params.Expires, 10))
	}
	if params.Nonce != nil {
		sb.WriteString(`;nonce=`)
		sb.WriteString(sfv.SerializeString(*params.Nonce))
	}
	if params.Algorithm != nil {
		sb.WriteString(`;alg=`)
		sb.WriteString(sfv.SerializeString(*params.Algorithm))
	}
	if params.KeyID != nil {
		sb.WriteString(`;keyid=`)
		sb.WriteString(sfv.SerializeString(*params.KeyID))
	}
	if params.Tag != nil {
		sb.WriteString(`;tag=`)
		sb.WriteString(sfv.SerializeString(*params.Tag))
	}
}

// formatComponentIdentifier formats a component identifier with its parameters.
//
// Format: "component-name" or "component-name";param1;param2=value
//
// Component parameters (RFC 9421 Section 2.1):
// - sf: boolean (Structured Field serialization)
// - bs: boolean (Byte Sequence encoding)
// - key: string (dictionary member key)
// - req: boolean (request component from response signature)
// - tr: boolean (trailer field)
// - name: string (query parameter name for @query-param)
//
// Parameters are serialized in the order they appear in the Parameters slice.
func formatComponentIdentifier(comp parser.ComponentIdentifier) string {
	var sb strings.Builder
	writeComponentIdentifier(&sb, comp)
	return sb.String()
}

func writeComponentIdentifier(sb *strings.Builder, comp parser.ComponentIdentifier) {
	// Component name is always quoted
	sb.WriteString(`"`)
	sb.WriteString(comp.Name)
	sb.WriteString(`"`)

	// Add component parameters in the order they appear
	for _, param := range comp.Parameters {
		sb.WriteRune(';')
		sb.WriteString(param.Key)

		// Use type switch for efficient single dispatch
		switch v := param.Value.(type) {
		case parser.Boolean:
			// Boolean true parameters appear as flags (no value)
			if !v.Value {
				// Boolean false is represented with =?0
				sb.WriteString("=?0")
			}
			// Boolean true is just the flag name (no =?1)

		case parser.String:
			// String parameters appear as key="value" with proper escaping
			sb.WriteString("=")
			sb.WriteString(sfv.SerializeString(v.Value))

		case parser.Token:
			// Token parameters appear as key=token (no quotes)
			sb.WriteString("=")
			sb.WriteString(v.Value)

		case parser.Integer:
			// Integer parameters appear as key=123
			sb.WriteString("=")
			sb.WriteString(strconv.FormatInt(v.Value, 10))

		case parser.ByteSequence:
			// ByteSequence parameters appear as key=:base64:
			sb.WriteString("=:")
			sb.WriteString(base64.StdEncoding.EncodeToString(v.Value))
			sb.WriteString(":")
		}
	}
}
