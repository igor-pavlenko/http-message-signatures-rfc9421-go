package base

import (
	"testing"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
)

// T007: Test @signature-params line formatting per RFC 9421 Section 2.5
func TestFormatSignatureParamsLine(t *testing.T) {
	t.Run("empty components list", func(t *testing.T) {
		// RFC 9421 Appendix B.2.1: minimal signature with no covered components
		var components []parser.ComponentIdentifier
		params := parser.SignatureParams{}

		got := formatSignatureParamsLine(components, params)
		want := `"@signature-params": ()`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})

	t.Run("single component no params", func(t *testing.T) {
		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
		}
		params := parser.SignatureParams{}

		got := formatSignatureParamsLine(components, params)
		want := `"@signature-params": ("@method")`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})

	t.Run("multiple components no params", func(t *testing.T) {
		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
			{Name: "@path", Type: parser.ComponentDerived},
			{Name: "content-type", Type: parser.ComponentField},
		}
		params := parser.SignatureParams{}

		got := formatSignatureParamsLine(components, params)
		want := `"@signature-params": ("@method" "@path" "content-type")`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})

	t.Run("with created timestamp", func(t *testing.T) {
		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
		}
		created := int64(1618884473)
		params := parser.SignatureParams{
			Created: &created,
		}

		got := formatSignatureParamsLine(components, params)
		want := `"@signature-params": ("@method");created=1618884473`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})

	t.Run("with expires timestamp", func(t *testing.T) {
		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
		}
		expires := int64(1618884473)
		params := parser.SignatureParams{
			Expires: &expires,
		}

		got := formatSignatureParamsLine(components, params)
		want := `"@signature-params": ("@method");expires=1618884473`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})

	t.Run("with nonce", func(t *testing.T) {
		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
		}
		nonce := "random-nonce-value"
		params := parser.SignatureParams{
			Nonce: &nonce,
		}

		got := formatSignatureParamsLine(components, params)
		want := `"@signature-params": ("@method");nonce="random-nonce-value"`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})

	t.Run("with alg", func(t *testing.T) {
		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
		}
		alg := "rsa-pss-sha512"
		params := parser.SignatureParams{
			Algorithm: &alg,
		}

		got := formatSignatureParamsLine(components, params)
		want := `"@signature-params": ("@method");alg="rsa-pss-sha512"`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})

	t.Run("with keyid", func(t *testing.T) {
		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
		}
		keyid := "test-key-rsa-pss"
		params := parser.SignatureParams{
			KeyID: &keyid,
		}

		got := formatSignatureParamsLine(components, params)
		want := `"@signature-params": ("@method");keyid="test-key-rsa-pss"`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})

	t.Run("with tag", func(t *testing.T) {
		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
		}
		tag := "custom-tag"
		params := parser.SignatureParams{
			Tag: &tag,
		}

		got := formatSignatureParamsLine(components, params)
		want := `"@signature-params": ("@method");tag="custom-tag"`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})

	t.Run("with all signature parameters", func(t *testing.T) {
		// RFC 9421 Appendix B.2.5: Full signature with all metadata
		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
			{Name: "@path", Type: parser.ComponentDerived},
		}
		created := int64(1618884473)
		expires := int64(1618884773)
		nonce := "test-nonce"
		alg := "rsa-pss-sha512"
		keyid := "test-key-rsa-pss"
		tag := "test-tag"

		params := parser.SignatureParams{
			Created:   &created,
			Expires:   &expires,
			Nonce:     &nonce,
			Algorithm: &alg,
			KeyID:     &keyid,
			Tag:       &tag,
		}

		got := formatSignatureParamsLine(components, params)
		// RFC 9421: Parameters must appear in canonical order
		want := `"@signature-params": ("@method" "@path");created=1618884473;expires=1618884773;nonce="test-nonce";alg="rsa-pss-sha512";keyid="test-key-rsa-pss";tag="test-tag"`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})

	t.Run("components with parameters", func(t *testing.T) {
		// Component identifiers can have their own parameters (sf, bs, key, req, tr)
		components := []parser.ComponentIdentifier{
			{
				Name: "content-type",
				Type: parser.ComponentField,
				Parameters: []parser.Parameter{
					{Key: "sf", Value: parser.Boolean{Value: true}},
				},
			},
			{
				Name: "example-dict",
				Type: parser.ComponentField,
				Parameters: []parser.Parameter{
					{Key: "key", Value: parser.String{Value: "member-key"}},
					{Key: "sf", Value: parser.Boolean{Value: true}},
				},
			},
		}
		params := parser.SignatureParams{}

		got := formatSignatureParamsLine(components, params)
		want := `"@signature-params": ("content-type";sf "example-dict";key="member-key";sf)`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})
}

// TestFormatComponentIdentifier tests all parameter type formatting
func TestFormatComponentIdentifier(t *testing.T) {
	t.Run("component without parameters", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name:       "content-type",
			Type:       parser.ComponentField,
			Parameters: []parser.Parameter{},
		}

		got := formatComponentIdentifier(comp)
		want := `"content-type"`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("component with boolean true parameter", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "content-type",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "sf", Value: parser.Boolean{Value: true}},
			},
		}

		got := formatComponentIdentifier(comp)
		want := `"content-type";sf`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("component with boolean false parameter", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "example-field",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "bs", Value: parser.Boolean{Value: false}},
			},
		}

		got := formatComponentIdentifier(comp)
		want := `"example-field";bs=?0`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("component with string parameter", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "example-dict",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "key", Value: parser.String{Value: "member-name"}},
			},
		}

		got := formatComponentIdentifier(comp)
		want := `"example-dict";key="member-name"`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("component with token parameter", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "example-field",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "tag", Value: parser.Token{Value: "my-token"}},
			},
		}

		got := formatComponentIdentifier(comp)
		want := `"example-field";tag=my-token`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("component with integer parameter", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "example-field",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "count", Value: parser.Integer{Value: 42}},
			},
		}

		got := formatComponentIdentifier(comp)
		want := `"example-field";count=42`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("component with negative integer parameter", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "example-field",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "offset", Value: parser.Integer{Value: -100}},
			},
		}

		got := formatComponentIdentifier(comp)
		want := `"example-field";offset=-100`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("component with byte sequence parameter", func(t *testing.T) {
		// Raw bytes "Hello World" should be base64 encoded to "SGVsbG8gV29ybGQ="
		comp := parser.ComponentIdentifier{
			Name: "example-field",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "hash", Value: parser.ByteSequence{Value: []byte("Hello World")}},
			},
		}

		got := formatComponentIdentifier(comp)
		want := `"example-field";hash=:SGVsbG8gV29ybGQ=:`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("component with multiple mixed parameters", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "complex-field",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "sf", Value: parser.Boolean{Value: true}},
				{Key: "key", Value: parser.String{Value: "member"}},
				{Key: "count", Value: parser.Integer{Value: 10}},
				{Key: "token", Value: parser.Token{Value: "abc"}},
			},
		}

		got := formatComponentIdentifier(comp)
		// Parameters should appear in the order they're defined
		want := `"complex-field";sf;key="member";count=10;token=abc`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("component with empty byte sequence", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "example-field",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "data", Value: parser.ByteSequence{Value: []byte{}}},
			},
		}

		got := formatComponentIdentifier(comp)
		want := `"example-field";data=::`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("component with empty string parameter", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "example-field",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "name", Value: parser.String{Value: ""}},
			},
		}

		got := formatComponentIdentifier(comp)
		want := `"example-field";name=""`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("component with zero integer parameter", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "example-field",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "count", Value: parser.Integer{Value: 0}},
			},
		}

		got := formatComponentIdentifier(comp)
		want := `"example-field";count=0`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("derived component with parameters", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "@query-param",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "name", Value: parser.String{Value: "search"}},
			},
		}

		got := formatComponentIdentifier(comp)
		want := `"@query-param";name="search"`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("component with req parameter", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "@method",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "req", Value: parser.Boolean{Value: true}},
			},
		}

		got := formatComponentIdentifier(comp)
		want := `"@method";req`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("component with tr parameter", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "x-trailer",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "tr", Value: parser.Boolean{Value: true}},
			},
		}

		got := formatComponentIdentifier(comp)
		want := `"x-trailer";tr`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("component with bs false parameter", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "content-type",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "bs", Value: parser.Boolean{Value: false}},
			},
		}

		got := formatComponentIdentifier(comp)
		want := `"content-type";bs=?0`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})
}

// TestSignatureParamsEscaping tests RFC 8941 string escaping to prevent parameter injection.
// This is a security regression test for the parameter injection vulnerability.
func TestSignatureParamsEscaping(t *testing.T) {
	t.Run("keyid with embedded quote", func(t *testing.T) {
		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
		}
		keyid := `my"key`
		params := parser.SignatureParams{KeyID: &keyid}

		got := formatSignatureParamsLine(components, params)
		// Quote must be escaped as \"
		want := `"@signature-params": ("@method");keyid="my\"key"`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})

	t.Run("keyid with backslash", func(t *testing.T) {
		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
		}
		keyid := `my\key`
		params := parser.SignatureParams{KeyID: &keyid}

		got := formatSignatureParamsLine(components, params)
		// Backslash must be escaped as \\
		want := `"@signature-params": ("@method");keyid="my\\key"`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})

	t.Run("keyid injection attempt", func(t *testing.T) {
		// Attacker tries to inject created parameter via keyid
		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
		}
		keyid := `key";created=9999999999`
		params := parser.SignatureParams{KeyID: &keyid}

		got := formatSignatureParamsLine(components, params)
		// The injection attempt must be escaped, not interpreted as a parameter
		want := `"@signature-params": ("@method");keyid="key\";created=9999999999"`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})

	t.Run("nonce with special characters", func(t *testing.T) {
		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
		}
		nonce := `say "hello\world"`
		params := parser.SignatureParams{Nonce: &nonce}

		got := formatSignatureParamsLine(components, params)
		// Both quotes and backslashes must be escaped
		want := `"@signature-params": ("@method");nonce="say \"hello\\world\""`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})

	t.Run("alg with quote", func(t *testing.T) {
		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
		}
		alg := `alg"test`
		params := parser.SignatureParams{Algorithm: &alg}

		got := formatSignatureParamsLine(components, params)
		want := `"@signature-params": ("@method");alg="alg\"test"`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})

	t.Run("tag with quote", func(t *testing.T) {
		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
		}
		tag := `tag"test`
		params := parser.SignatureParams{Tag: &tag}

		got := formatSignatureParamsLine(components, params)
		want := `"@signature-params": ("@method");tag="tag\"test"`

		if got != want {
			t.Errorf("formatSignatureParamsLine() = %q, want %q", got, want)
		}
	})
}

// TestComponentIdentifierEscaping tests RFC 8941 string escaping for component parameters.
func TestComponentIdentifierEscaping(t *testing.T) {
	t.Run("string parameter with embedded quote", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "@query-param",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "name", Value: parser.String{Value: `search"query`}},
			},
		}

		got := formatComponentIdentifier(comp)
		want := `"@query-param";name="search\"query"`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("string parameter with backslash", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "@query-param",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "name", Value: parser.String{Value: `path\to\file`}},
			},
		}

		got := formatComponentIdentifier(comp)
		want := `"@query-param";name="path\\to\\file"`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("string parameter injection attempt", func(t *testing.T) {
		// Attacker tries to inject a parameter via the name value
		comp := parser.ComponentIdentifier{
			Name: "@query-param",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "name", Value: parser.String{Value: `search";sf`}},
			},
		}

		got := formatComponentIdentifier(comp)
		// The injection must be escaped, sf should NOT appear as separate parameter
		want := `"@query-param";name="search\";sf"`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})

	t.Run("key parameter with both escapes", func(t *testing.T) {
		comp := parser.ComponentIdentifier{
			Name: "example-dict",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "key", Value: parser.String{Value: `member\"name`}},
			},
		}

		got := formatComponentIdentifier(comp)
		// Both quote and backslash must be escaped
		want := `"example-dict";key="member\\\"name"`

		if got != want {
			t.Errorf("formatComponentIdentifier() = %q, want %q", got, want)
		}
	})
}
