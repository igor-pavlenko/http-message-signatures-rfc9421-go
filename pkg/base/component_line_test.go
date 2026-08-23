package base

import (
	"testing"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
)

// T009: Test component line formatting per RFC 9421 Section 2.5
func TestFormatComponentLine(t *testing.T) {
	t.Run("simple HTTP field", func(t *testing.T) {
		// RFC 9421 Section 2.1: HTTP fields are lowercased
		comp := parser.ComponentIdentifier{
			Name: "content-type",
			Type: parser.ComponentField,
		}
		value := "application/json"

		got := formatComponentLine(comp, value)
		want := `"content-type": application/json`

		if got != want {
			t.Errorf("formatComponentLine() = %q, want %q", got, want)
		}
	})

	t.Run("derived component", func(t *testing.T) {
		// RFC 9421 Section 2.2: Derived components start with @
		comp := parser.ComponentIdentifier{
			Name: "@method",
			Type: parser.ComponentDerived,
		}
		value := "POST"

		got := formatComponentLine(comp, value)
		want := `"@method": POST`

		if got != want {
			t.Errorf("formatComponentLine() = %q, want %q", got, want)
		}
	})

	t.Run("component with sf parameter", func(t *testing.T) {
		// RFC 9421 Section 2.1.1: sf parameter indicates Structured Field serialization
		comp := parser.ComponentIdentifier{
			Name: "content-type",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "sf", Value: parser.Boolean{Value: true}},
			},
		}
		value := "application/json"

		got := formatComponentLine(comp, value)
		want := `"content-type";sf: application/json`

		if got != want {
			t.Errorf("formatComponentLine() = %q, want %q", got, want)
		}
	})

	t.Run("component with key parameter", func(t *testing.T) {
		// RFC 9421 Section 2.1.2: key parameter extracts dictionary member
		comp := parser.ComponentIdentifier{
			Name: "example-dict",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "key", Value: parser.String{Value: "member-key"}},
			},
		}
		value := "member-value"

		got := formatComponentLine(comp, value)
		want := `"example-dict";key="member-key": member-value`

		if got != want {
			t.Errorf("formatComponentLine() = %q, want %q", got, want)
		}
	})

	t.Run("component with req parameter", func(t *testing.T) {
		// RFC 9421 Section 2.4: req parameter accesses request component from response
		comp := parser.ComponentIdentifier{
			Name: "@method",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "req", Value: parser.Boolean{Value: true}},
			},
		}
		value := "POST"

		got := formatComponentLine(comp, value)
		want := `"@method";req: POST`

		if got != want {
			t.Errorf("formatComponentLine() = %q, want %q", got, want)
		}
	})

	t.Run("component with tr parameter", func(t *testing.T) {
		// RFC 9421 Section 2.1: tr parameter indicates trailer field
		comp := parser.ComponentIdentifier{
			Name: "x-trailer",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "tr", Value: parser.Boolean{Value: true}},
			},
		}
		value := "trailer-value"

		got := formatComponentLine(comp, value)
		want := `"x-trailer";tr: trailer-value`

		if got != want {
			t.Errorf("formatComponentLine() = %q, want %q", got, want)
		}
	})

	t.Run("multi-line value with leading/trailing whitespace", func(t *testing.T) {
		// RFC 9421 Section 2.1: Values preserve exact formatting including whitespace
		comp := parser.ComponentIdentifier{
			Name: "example-field",
			Type: parser.ComponentField,
		}
		value := "  value with spaces  "

		got := formatComponentLine(comp, value)
		want := `"example-field":   value with spaces  `

		if got != want {
			t.Errorf("formatComponentLine() = %q, want %q", got, want)
		}
	})

	t.Run("empty value", func(t *testing.T) {
		// Empty values are valid per RFC 9421
		comp := parser.ComponentIdentifier{
			Name: "empty-field",
			Type: parser.ComponentField,
		}
		value := ""

		got := formatComponentLine(comp, value)
		want := `"empty-field": `

		if got != want {
			t.Errorf("formatComponentLine() = %q, want %q", got, want)
		}
	})

	t.Run("value with special characters", func(t *testing.T) {
		// Values can contain any characters except control chars
		comp := parser.ComponentIdentifier{
			Name: "special-field",
			Type: parser.ComponentField,
		}
		value := `value with "quotes" and \backslashes\`

		got := formatComponentLine(comp, value)
		want := `"special-field": value with "quotes" and \backslashes\`

		if got != want {
			t.Errorf("formatComponentLine() = %q, want %q", got, want)
		}
	})
}
