package base

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
)

// Test normalizeLineFolding function
func TestNormalizeLineFolding(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "CRLF followed by space",
			input: "line1\r\n continuation",
			want:  "line1 continuation",
		},
		{
			name:  "CRLF followed by tab",
			input: "line1\r\n\tcontinuation",
			want:  "line1 continuation",
		},
		{
			name:  "CRLF followed by multiple spaces",
			input: "line1\r\n    continuation",
			want:  "line1 continuation",
		},
		{
			name:  "LF followed by space",
			input: "line1\n continuation",
			want:  "line1 continuation",
		},
		{
			name:  "LF followed by tab",
			input: "line1\n\tcontinuation",
			want:  "line1 continuation",
		},
		{
			name:  "LF followed by multiple whitespace",
			input: "line1\n  \t  continuation",
			want:  "line1 continuation",
		},
		{
			name:  "no line folding",
			input: "simple value",
			want:  "simple value",
		},
		{
			name:  "multiple obs-fold sequences",
			input: "a\r\n b\n c",
			want:  "a b c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeLineFolding(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("normalizeLineFolding() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("normalizeLineFolding() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestNormalizeLineFolding_RejectsBareNewlines tests that bare newlines are rejected.
// This is a security regression test for signature base injection vulnerability.
func TestNormalizeLineFolding_RejectsBareNewlines(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "bare LF",
			input: "line1\nline2",
		},
		{
			name:  "bare CRLF",
			input: "line1\r\nline2",
		},
		{
			name:  "bare CR",
			input: "line1\rline2",
		},
		{
			name:  "LF at end of string",
			input: "line1\n",
		},
		{
			name:  "CRLF at end of string",
			input: "line1\r\n",
		},
		{
			name:  "injection attempt via LF",
			input: "benign\n\"@status\": 404",
		},
		{
			name:  "injection attempt via CRLF",
			input: "benign\r\n\"@method\": POST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := normalizeLineFolding(tt.input)
			if err == nil {
				t.Errorf("normalizeLineFolding(%q) should return error for bare newline", tt.input)
			}
			if err != nil && !strings.Contains(err.Error(), "not part of obs-fold") {
				t.Errorf("normalizeLineFolding(%q) error = %v, want error containing 'not part of obs-fold'", tt.input, err)
			}
		})
	}
}

// T013: Test HTTP field value extraction per RFC 9421 Section 2.1
func TestExtractHTTPFieldValue(t *testing.T) {
	t.Run("single header value", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		req.Header.Set("Content-Type", "application/json")

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "content-type",
			Type: parser.ComponentField,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "application/json"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("multiple header values", func(t *testing.T) {
		// RFC 9421 Section 2.1: Multiple field values are comma-separated
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		req.Header.Add("X-Custom", "value1")
		req.Header.Add("X-Custom", "value2")
		req.Header.Add("X-Custom", "value3")

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "x-custom",
			Type: parser.ComponentField,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "value1, value2, value3"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("header name case-insensitive", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		req.Header.Set("Content-Type", "text/html")

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "CONTENT-TYPE", // Uppercase in component
			Type: parser.ComponentField,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "text/html"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("missing header returns error", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "missing-header",
			Type: parser.ComponentField,
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error for missing header")
		}
	})

	t.Run("empty header value allowed", func(t *testing.T) {
		// RFC 9421: Empty header values are valid
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		req.Header.Set("X-Empty", "")

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "x-empty",
			Type: parser.ComponentField,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := ""
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("trailer field with tr parameter", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		req.Trailer = http.Header{
			"X-Trailer": []string{"trailer-value"},
		}

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "x-trailer",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "tr", Value: parser.Boolean{Value: true}},
			},
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "trailer-value"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("trailer field without tr parameter should use header", func(t *testing.T) {
		// Without tr parameter, should look in headers not trailers
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		req.Header.Set("X-Field", "header-value")
		req.Trailer = http.Header{
			"X-Field": []string{"trailer-value"},
		}

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "x-field",
			Type: parser.ComponentField,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "header-value"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("trims leading and trailing whitespace per RFC 9421", func(t *testing.T) {
		// RFC 9421 Section 2.1: Strip leading and trailing whitespace from each value
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		req.Header.Set("X-Spaces", "  value with spaces  ")

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "x-spaces",
			Type: parser.ComponentField,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		// Leading/trailing whitespace is trimmed, internal whitespace is preserved
		want := "value with spaces"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("missing trailer field returns error", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		req.Trailer = http.Header{}

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "missing-trailer",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "tr", Value: parser.Boolean{Value: true}},
			},
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error for missing trailer")
		}
		if err != nil && !contains(err.Error(), "trailer field") {
			t.Errorf("extractComponentValue() error = %q, should mention 'trailer field'", err.Error())
		}
	})

	t.Run("unknown component type returns error", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		msg := WrapRequest(req)

		// Create component with invalid type (using direct value instead of constant)
		comp := parser.ComponentIdentifier{
			Name: "test",
			Type: parser.ComponentType(999), // Invalid component type
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error for unknown component type")
		}
		if err != nil && !contains(err.Error(), "unknown component type") {
			t.Errorf("extractComponentValue() error = %q, should mention 'unknown component type'", err.Error())
		}
	})
}

// T015: Test derived component extraction per RFC 9421 Section 2.2
func TestExtractDerivedComponentValue(t *testing.T) {
	t.Run("@method", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://example.com/foo", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@method",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "POST"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@path", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/foo/bar?query=value", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@path",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "/foo/bar"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@authority", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com:8080/foo", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@authority",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "example.com:8080"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@scheme", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/foo", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@scheme",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "https"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@target-uri", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com:8080/foo?query=value", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@target-uri",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "https://example.com:8080/foo?query=value"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@request-target", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/foo?query=value", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@request-target",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "/foo?query=value"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@query with query string", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/foo?param=value&pet=dog", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@query",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "?param=value&pet=dog"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@query without query string", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/foo", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@query",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		// RFC 9421: @query returns "?" even when no query string
		want := "?"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@query-param with single value", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/foo?param=value&pet=dog", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@query-param",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "name", Value: parser.String{Value: "param"}},
			},
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "value"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@query-param with multiple values returns first", func(t *testing.T) {
		// RFC 9421: If multiple values exist, only first is returned
		req, _ := http.NewRequest("GET", "https://example.com/foo?param=value1&param=value2&param=value3", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@query-param",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "name", Value: parser.String{Value: "param"}},
			},
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "value1"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@query-param without name parameter returns error", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/foo?param=value", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@query-param",
			Type: parser.ComponentDerived,
			// Missing 'name' parameter
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error when @query-param missing 'name' parameter")
		}
		if err != nil && err.Error() != "@query-param requires 'name' parameter" {
			t.Errorf("extractComponentValue() error = %q, want %q", err.Error(), "@query-param requires 'name' parameter")
		}
	})

	t.Run("@query-param with missing query parameter returns error", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/foo?other=value", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@query-param",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "name", Value: parser.String{Value: "missing"}},
			},
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error when query parameter not found")
		}
	})

	t.Run("@query-param with empty value", func(t *testing.T) {
		// Query parameter with empty value: ?param=
		req, _ := http.NewRequest("GET", "https://example.com/foo?param=", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@query-param",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "name", Value: parser.String{Value: "param"}},
			},
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := ""
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@query-param with URL encoded value", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/foo?param=hello%20world", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@query-param",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "name", Value: parser.String{Value: "param"}},
			},
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		// URL decoding is handled by url.Query()
		want := "hello world"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@query on response returns error", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{},
		}

		msg := WrapResponse(resp, nil)
		comp := parser.ComponentIdentifier{
			Name: "@query",
			Type: parser.ComponentDerived,
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error for @query on response")
		}
	})

	t.Run("@query-param on response returns error", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{},
		}

		msg := WrapResponse(resp, nil)
		comp := parser.ComponentIdentifier{
			Name: "@query-param",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "name", Value: parser.String{Value: "param"}},
			},
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error for @query-param on response")
		}
	})

	t.Run("@status on request returns error", func(t *testing.T) {
		// @status is only valid for responses
		req, _ := http.NewRequest("GET", "https://example.com/", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@status",
			Type: parser.ComponentDerived,
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error for @status on request")
		}
	})

	t.Run("unknown derived component returns error", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/", nil)

		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@unknown",
			Type: parser.ComponentDerived,
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error for unknown derived component")
		}
	})

	// Test all request-only derived components on responses
	t.Run("@method on response returns error", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: http.Header{}}
		msg := WrapResponse(resp, nil)

		comp := parser.ComponentIdentifier{
			Name: "@method",
			Type: parser.ComponentDerived,
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error for @method on response")
		}
	})

	t.Run("@target-uri on response returns error", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: http.Header{}}
		msg := WrapResponse(resp, nil)

		comp := parser.ComponentIdentifier{
			Name: "@target-uri",
			Type: parser.ComponentDerived,
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error for @target-uri on response")
		}
	})

	t.Run("@authority on response returns error", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: http.Header{}}
		msg := WrapResponse(resp, nil)

		comp := parser.ComponentIdentifier{
			Name: "@authority",
			Type: parser.ComponentDerived,
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error for @authority on response")
		}
	})

	t.Run("@scheme on response returns error", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: http.Header{}}
		msg := WrapResponse(resp, nil)

		comp := parser.ComponentIdentifier{
			Name: "@scheme",
			Type: parser.ComponentDerived,
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error for @scheme on response")
		}
	})

	t.Run("@request-target on response returns error", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: http.Header{}}
		msg := WrapResponse(resp, nil)

		comp := parser.ComponentIdentifier{
			Name: "@request-target",
			Type: parser.ComponentDerived,
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error for @request-target on response")
		}
	})

	t.Run("@path on response returns error", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: http.Header{}}
		msg := WrapResponse(resp, nil)

		comp := parser.ComponentIdentifier{
			Name: "@path",
			Type: parser.ComponentDerived,
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error for @path on response")
		}
	})

	t.Run("@status works on response", func(t *testing.T) {
		resp := &http.Response{StatusCode: 404, Header: http.Header{}}
		msg := WrapResponse(resp, nil)

		comp := parser.ComponentIdentifier{
			Name: "@status",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "404"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	// RFC 9421 Section 2.4 - req parameter tests
	t.Run("req parameter on request returns error", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		msg := WrapRequest(req)

		comp := parser.ComponentIdentifier{
			Name: "@method",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "req", Value: parser.Boolean{Value: true}},
			},
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error when 'req' parameter used on request")
		}
	})

	t.Run("req parameter without related request returns error", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: http.Header{}}
		msg := WrapResponse(resp, nil) // No related request

		comp := parser.ComponentIdentifier{
			Name: "@method",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "req", Value: parser.Boolean{Value: true}},
			},
		}

		_, err := extractComponentValue(msg, comp)
		if err == nil {
			t.Error("extractComponentValue() should return error when 'req' parameter used but no related request")
		}
	})

	t.Run("req parameter extracts from related request", func(t *testing.T) {
		// Original request
		req, _ := http.NewRequest("POST", "https://example.com/foo", nil)
		req.Header.Set("Content-Type", "application/json")

		// Response with related request
		resp := &http.Response{StatusCode: 200, Header: http.Header{}}
		msg := WrapResponse(resp, req)

		tests := []struct {
			name string
			comp parser.ComponentIdentifier
			want string
		}{
			{
				name: "@method with req",
				comp: parser.ComponentIdentifier{
					Name: "@method",
					Type: parser.ComponentDerived,
					Parameters: []parser.Parameter{
						{Key: "req", Value: parser.Boolean{Value: true}},
					},
				},
				want: "POST",
			},
			{
				name: "content-type with req",
				comp: parser.ComponentIdentifier{
					Name: "content-type",
					Type: parser.ComponentField,
					Parameters: []parser.Parameter{
						{Key: "req", Value: parser.Boolean{Value: true}},
					},
				},
				want: "application/json",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := extractComponentValue(msg, tt.comp)
				if err != nil {
					t.Fatalf("extractComponentValue() error = %v", err)
				}
				if got != tt.want {
					t.Errorf("extractComponentValue() = %q, want %q", got, tt.want)
				}
			})
		}
	})

	t.Run("req parameter with additional component parameters", func(t *testing.T) {
		// Test that req parameter works with other component parameters
		// This covers the code path that filters out non-req parameters
		req, _ := http.NewRequest("GET", "https://example.com/foo?param=value", nil)
		resp := &http.Response{StatusCode: 200, Header: http.Header{}}
		msg := WrapResponse(resp, req)

		// Component with both req and name parameters (for @query-param)
		comp := parser.ComponentIdentifier{
			Name: "@query-param",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "name", Value: parser.String{Value: "param"}},
				{Key: "req", Value: parser.Boolean{Value: true}},
			},
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "value"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})
}

// ============================================================================
// Parameter Tests (SF, BS, Key parameters)
// ============================================================================

func TestParameterValidation_MutuallyExclusive(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("Test-Header", "value")
	msg := WrapRequest(req)

	comp := parser.ComponentIdentifier{
		Name: "test-header",
		Type: parser.ComponentField,
		Parameters: []parser.Parameter{
			{Key: "sf", Value: parser.Boolean{Value: true}},
			{Key: "bs", Value: parser.Boolean{Value: true}},
		},
	}

	_, err := extractHTTPFieldValue(msg, comp)
	if err == nil {
		t.Fatal("expected error for sf+bs mutual exclusion, got nil")
	}

	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected error about mutual exclusivity, got: %v", err)
	}
}

// TestParameterValidation_KeyRequiresSF tests FR-018: key parameter requires sf.
func TestParameterValidation_KeyRequiresSF(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("Test-Header", "value")
	msg := WrapRequest(req)

	comp := parser.ComponentIdentifier{
		Name: "test-header",
		Type: parser.ComponentField,
		Parameters: []parser.Parameter{
			{Key: "key", Value: parser.String{Value: "member"}},
			// Missing sf parameter
		},
	}

	_, err := extractHTTPFieldValue(msg, comp)
	if err == nil {
		t.Fatal("expected error for key without sf, got nil")
	}

	if !strings.Contains(err.Error(), "requires 'sf'") {
		t.Errorf("expected error about sf requirement, got: %v", err)
	}
}

// TestBSParameter_Base64Encoding tests FR-012: bs parameter encodes as base64 byte sequence.
func TestBSParameter_Base64Encoding(t *testing.T) {
	tests := []struct {
		name       string
		headerVal  string
		wantBase64 string // Expected base64-encoded value (without colons)
	}{
		{
			name:       "simple text",
			headerVal:  "Hello, World!",
			wantBase64: "SGVsbG8sIFdvcmxkIQ==",
		},
		{
			name:       "sha-256 digest",
			headerVal:  "sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
			wantBase64: "c2hhLTI1Nj1YNDhFOXFPb2txcXJ2ZHRzOG5PSlJKTjNPV0RVb3lXeEJmN2tidTlEQlBFPQ==",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com/", nil)
			req.Header.Set("Content-Digest", tt.headerVal)
			msg := WrapRequest(req)

			comp := parser.ComponentIdentifier{
				Name: "content-digest",
				Type: parser.ComponentField,
				Parameters: []parser.Parameter{
					{Key: "bs", Value: parser.Boolean{Value: true}},
				},
			}

			got, err := extractHTTPFieldValue(msg, comp)
			if err != nil {
				t.Fatalf("extractHTTPFieldValue() error = %v", err)
			}

			// Check wrapped in colons
			if !strings.HasPrefix(got, ":") || !strings.HasSuffix(got, ":") {
				t.Errorf("bs parameter value must be wrapped in colons, got %q", got)
			}

			// Check base64 content
			want := ":" + tt.wantBase64 + ":"
			if got != want {
				t.Errorf("extractHTTPFieldValue() = %q, want %q", got, want)
			}
		})
	}
}

// TestBSParameter_WithMultipleValues tests bs parameter with comma-joined values.
func TestBSParameter_WithMultipleValues(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	// Add multiple values for same header
	req.Header.Add("X-Example", "first")
	req.Header.Add("X-Example", "second")
	msg := WrapRequest(req)

	comp := parser.ComponentIdentifier{
		Name: "x-example",
		Type: parser.ComponentField,
		Parameters: []parser.Parameter{
			{Key: "bs", Value: parser.Boolean{Value: true}},
		},
	}

	got, err := extractHTTPFieldValue(msg, comp)
	if err != nil {
		t.Fatalf("extractHTTPFieldValue() error = %v", err)
	}

	// Should join with ", " first, then base64-encode
	// "first, second" base64 is "Zmlyc3QsIHNlY29uZA=="
	want := ":Zmlyc3QsIHNlY29uZA==:"
	if got != want {
		t.Errorf("extractHTTPFieldValue() = %q, want %q", got, want)
	}
}

// TestSFParameter_SerializesStructuredField tests that sf parameter serializes structured fields.
func TestSFParameter_SerializesStructuredField(t *testing.T) {
	tests := []struct {
		name       string
		headerVal  string
		wantOutput string
	}{
		{
			name:       "simple token",
			headerVal:  "application/json",
			wantOutput: "application/json",
		},
		{
			name:       "quoted string",
			headerVal:  `"hello world"`,
			wantOutput: `"hello world"`,
		},
		{
			name:       "integer",
			headerVal:  "42",
			wantOutput: "42",
		},
		{
			name:       "dictionary with multiple members",
			headerVal:  "a=1, b=2, c=3",
			wantOutput: "a=1, b=2, c=3",
		},
		{
			name:       "dictionary with bare key (boolean true)",
			headerVal:  "flag, other=value",
			wantOutput: "flag, other=value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com/", nil)
			req.Header.Set("Example-Field", tt.headerVal)
			msg := WrapRequest(req)

			comp := parser.ComponentIdentifier{
				Name: "example-field",
				Type: parser.ComponentField,
				Parameters: []parser.Parameter{
					{Key: "sf", Value: parser.Boolean{Value: true}},
				},
			}

			got, err := extractHTTPFieldValue(msg, comp)
			if err != nil {
				t.Fatalf("extractHTTPFieldValue() error = %v", err)
			}

			if got != tt.wantOutput {
				t.Errorf("extractHTTPFieldValue() = %q, want %q", got, tt.wantOutput)
			}
		})
	}
}

// TestKeyParameter_ExtractsDictionaryMember tests that key parameter extracts dictionary members.
func TestKeyParameter_ExtractsDictionaryMember(t *testing.T) {
	tests := []struct {
		name       string
		headerVal  string
		keyName    string
		wantOutput string
		wantError  bool
	}{
		{
			name:       "extract integer member",
			headerVal:  "a=1, b=2, c=3",
			keyName:    "b",
			wantOutput: "2",
			wantError:  false,
		},
		{
			name:       "extract string member",
			headerVal:  `a="hello world", b="test"`,
			keyName:    "a",
			wantOutput: `"hello world"`,
			wantError:  false,
		},
		{
			name:       "extract boolean member",
			headerVal:  "flag, other=value",
			keyName:    "flag",
			wantOutput: "?1",
			wantError:  false,
		},
		{
			name:       "member not found",
			headerVal:  "a=1, b=2",
			keyName:    "c",
			wantOutput: "",
			wantError:  true,
		},
		{
			name:       "extract inner list member",
			headerVal:  `a=(1 2 3), b=value`,
			keyName:    "a",
			wantOutput: "(1 2 3)",
			wantError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com/", nil)
			req.Header.Set("Example-Dict", tt.headerVal)
			msg := WrapRequest(req)

			comp := parser.ComponentIdentifier{
				Name: "example-dict",
				Type: parser.ComponentField,
				Parameters: []parser.Parameter{
					{Key: "sf", Value: parser.Boolean{Value: true}},
					{Key: "key", Value: parser.String{Value: tt.keyName}},
				},
			}

			got, err := extractHTTPFieldValue(msg, comp)

			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("extractHTTPFieldValue() error = %v", err)
			}

			if got != tt.wantOutput {
				t.Errorf("extractHTTPFieldValue() = %q, want %q", got, tt.wantOutput)
			}
		})
	}
}

// TestBuildSignatureBase_WithBSParameter tests full signature base building with bs parameter.
func TestBuildSignatureBase_WithBSParameter(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.com/data", nil)
	req.Header.Set("Content-Digest", "sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=")

	components := []parser.ComponentIdentifier{
		{
			Name: "content-digest",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "bs", Value: parser.Boolean{Value: true}},
			},
		},
	}
	params := parser.SignatureParams{}

	msg := WrapRequest(req)
	sigBase, err := Build(msg, components, params)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Signature base should contain the component line with base64-encoded value
	if !strings.Contains(sigBase, `"content-digest";bs: :`) {
		t.Errorf("signature base should contain component with bs parameter and colon-wrapped value, got:\n%s", sigBase)
	}

	// Should contain base64-encoded value
	if !strings.Contains(sigBase, "c2hhLTI1Nj1YNDhFOXFPb2txcXJ2ZHRzOG5PSlJKTjNPV0RVb3lXeEJmN2tidTlEQlBFPQ==") {
		t.Errorf("signature base should contain base64-encoded value, got:\n%s", sigBase)
	}
}

// TestServerSideRequestDerivedComponents tests that derived components
// are correctly extracted from server-side requests where URL.Scheme
// and URL.Host are empty (Go's http.Request behavior for server handlers).
func TestServerSideRequestDerivedComponents(t *testing.T) {
	t.Run("@authority from server-side request", func(t *testing.T) {
		// Server-side request: URL.Host is empty, req.Host has the value
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/foo"},
			Host:   "example.com:8080",
		}
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@authority",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "example.com:8080"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@scheme from server-side HTTPS request", func(t *testing.T) {
		// Server-side HTTPS request: URL.Scheme is empty, req.TLS is non-nil
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/foo"},
			Host:   "example.com",
			TLS:    &tls.ConnectionState{},
		}
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@scheme",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "https"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@scheme from server-side HTTP request", func(t *testing.T) {
		// Server-side HTTP request: URL.Scheme is empty, req.TLS is nil
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/foo"},
			Host:   "example.com",
			TLS:    nil,
		}
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@scheme",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "http"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@target-uri from server-side HTTPS request", func(t *testing.T) {
		// Server-side HTTPS request with query string
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/foo", RawQuery: "bar=baz"},
			Host:   "example.com",
			TLS:    &tls.ConnectionState{},
		}
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@target-uri",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "https://example.com/foo?bar=baz"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@target-uri from server-side HTTP request with port", func(t *testing.T) {
		// Server-side HTTP request with non-standard port
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/api/v1"},
			Host:   "example.com:8080",
			TLS:    nil,
		}
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@target-uri",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "http://example.com:8080/api/v1"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})
}

// TestPathPercentEncodingPreservation tests that @path and @request-target
// preserve percent-encoding in the path component per RFC 9421.
func TestPathPercentEncodingPreservation(t *testing.T) {
	t.Run("@path preserves percent-encoded slash", func(t *testing.T) {
		// %2F is an encoded forward slash - must be preserved
		req, _ := http.NewRequest("GET", "https://example.com/foo%2Fbar", nil)
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@path",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "/foo%2Fbar"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@path preserves percent-encoded space", func(t *testing.T) {
		// %20 is an encoded space - must be preserved
		req, _ := http.NewRequest("GET", "https://example.com/hello%20world", nil)
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@path",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "/hello%20world"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@request-target preserves percent-encoding in path", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/foo%2Fbar?q=test", nil)
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@request-target",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "/foo%2Fbar?q=test"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("@request-target with empty path returns slash", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com?q=test", nil)
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{
			Name: "@request-target",
			Type: parser.ComponentDerived,
		}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "/?q=test"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})
}
