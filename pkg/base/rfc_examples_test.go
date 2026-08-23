package base

import (
	"net/http"
	"strings"
	"testing"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
)

// RFC 9421 Section 2.1 - HTTP Fields Canonicalization Examples
func TestRFC9421_Section2_1_HTTPFields(t *testing.T) {
	t.Run("basic HTTP headers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://www.example.com/", nil)
		req.Header.Set("Host", "www.example.com")
		req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:56 GMT")
		req.Header.Set("X-OWS-Header", "   Leading and trailing whitespace.   ")
		req.Header.Set("X-Obs-Fold-Header", "Obsolete\n    line folding.")
		req.Header.Set("Example-Dict", "  a=1,    b=2;x=1;y=2,   c=(a   b   c)")
		req.Header.Add("Cache-Control", "max-age=60")
		req.Header.Add("Cache-Control", "    must-revalidate")

		msg := WrapRequest(req)

		tests := []struct {
			name string
			comp parser.ComponentIdentifier
			want string
		}{
			{
				name: "host",
				comp: parser.ComponentIdentifier{Name: "host", Type: parser.ComponentField},
				want: "www.example.com",
			},
			{
				name: "date",
				comp: parser.ComponentIdentifier{Name: "date", Type: parser.ComponentField},
				want: "Tue, 20 Apr 2021 02:07:56 GMT",
			},
			{
				name: "x-ows-header trims leading/trailing whitespace",
				comp: parser.ComponentIdentifier{Name: "x-ows-header", Type: parser.ComponentField},
				want: "Leading and trailing whitespace.",
			},
			{
				name: "x-obs-fold-header normalizes line folding",
				comp: parser.ComponentIdentifier{Name: "x-obs-fold-header", Type: parser.ComponentField},
				want: "Obsolete line folding.",
			},
			{
				name: "example-dict preserves internal whitespace",
				comp: parser.ComponentIdentifier{Name: "example-dict", Type: parser.ComponentField},
				want: "a=1,    b=2;x=1;y=2,   c=(a   b   c)",
			},
			{
				name: "cache-control multiple values trimmed",
				comp: parser.ComponentIdentifier{Name: "cache-control", Type: parser.ComponentField},
				want: "max-age=60, must-revalidate",
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
}

// RFC 9421 Section 2.2.1 - @method Component
func TestRFC9421_Section2_2_1_Method(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://www.example.com/path?param=value", nil)
	req.Header.Set("Host", "www.example.com")

	msg := WrapRequest(req)
	comp := parser.ComponentIdentifier{Name: "@method", Type: parser.ComponentDerived}

	got, err := extractComponentValue(msg, comp)
	if err != nil {
		t.Fatalf("extractComponentValue() error = %v", err)
	}

	want := "POST"
	if got != want {
		t.Errorf("extractComponentValue() = %q, want %q", got, want)
	}
}

// RFC 9421 Section 2.2.2 - @target-uri Component
func TestRFC9421_Section2_2_2_TargetURI(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://www.example.com/path?param=value", nil)
	req.Header.Set("Host", "www.example.com")

	msg := WrapRequest(req)
	comp := parser.ComponentIdentifier{Name: "@target-uri", Type: parser.ComponentDerived}

	got, err := extractComponentValue(msg, comp)
	if err != nil {
		t.Fatalf("extractComponentValue() error = %v", err)
	}

	want := "https://www.example.com/path?param=value"
	if got != want {
		t.Errorf("extractComponentValue() = %q, want %q", got, want)
	}
}

// RFC 9421 Section 2.2.3 - @authority Component
func TestRFC9421_Section2_2_3_Authority(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://www.example.com/path?param=value", nil)
	req.Header.Set("Host", "www.example.com")

	msg := WrapRequest(req)
	comp := parser.ComponentIdentifier{Name: "@authority", Type: parser.ComponentDerived}

	got, err := extractComponentValue(msg, comp)
	if err != nil {
		t.Fatalf("extractComponentValue() error = %v", err)
	}

	want := "www.example.com"
	if got != want {
		t.Errorf("extractComponentValue() = %q, want %q", got, want)
	}
}

// RFC 9421 Section 2.2.4 - @scheme Component
func TestRFC9421_Section2_2_4_Scheme(t *testing.T) {
	t.Run("https scheme", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://www.example.com/path?param=value", nil)
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{Name: "@scheme", Type: parser.ComponentDerived}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "https"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("http scheme", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "http://www.example.com/path?param=value", nil)
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{Name: "@scheme", Type: parser.ComponentDerived}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "http"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})
}

// RFC 9421 Section 2.2.5 - @request-target Component
func TestRFC9421_Section2_2_5_RequestTarget(t *testing.T) {
	t.Run("origin form", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://www.example.com/path?param=value", nil)
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{Name: "@request-target", Type: parser.ComponentDerived}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "/path?param=value"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("path only no query", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://www.example.com/path", nil)
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{Name: "@request-target", Type: parser.ComponentDerived}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "/path"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})
}

// RFC 9421 Section 2.2.6 - @path Component
func TestRFC9421_Section2_2_6_Path(t *testing.T) {
	t.Run("non-empty path", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://www.example.com/path?param=value", nil)
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{Name: "@path", Type: parser.ComponentDerived}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "/path"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("empty path normalized to /", func(t *testing.T) {
		// RFC 9421 Section 2.2.6: an empty path string is normalized as a single slash (/) character
		req, _ := http.NewRequest("GET", "https://www.example.com", nil)
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{Name: "@path", Type: parser.ComponentDerived}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "/"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})
}

// RFC 9421 Section 2.2.7 - @query Component
func TestRFC9421_Section2_2_7_Query(t *testing.T) {
	t.Run("query with multiple parameters", func(t *testing.T) {
		// RFC example: GET /path?param=value&foo=bar&baz=bat%2Dman
		req, _ := http.NewRequest("GET", "https://www.example.com/path?param=value&foo=bar&baz=bat%2Dman", nil)
		req.Header.Set("Host", "www.example.com")
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{Name: "@query", Type: parser.ComponentDerived}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "?param=value&foo=bar&baz=bat%2Dman"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("single query parameter", func(t *testing.T) {
		// RFC example: POST /path?queryString
		req, _ := http.NewRequest("POST", "https://www.example.com/path?queryString", nil)
		req.Header.Set("Host", "www.example.com")
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{Name: "@query", Type: parser.ComponentDerived}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "?queryString"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})

	t.Run("empty query returns ?", func(t *testing.T) {
		// RFC: If the query string is absent from the request message, the component value is the leading ? character alone
		req, _ := http.NewRequest("GET", "https://www.example.com/path", nil)
		msg := WrapRequest(req)
		comp := parser.ComponentIdentifier{Name: "@query", Type: parser.ComponentDerived}

		got, err := extractComponentValue(msg, comp)
		if err != nil {
			t.Fatalf("extractComponentValue() error = %v", err)
		}

		want := "?"
		if got != want {
			t.Errorf("extractComponentValue() = %q, want %q", got, want)
		}
	})
}

// RFC 9421 Section 2.2.8 - @query-param Component
func TestRFC9421_Section2_2_8_QueryParam(t *testing.T) {
	t.Run("basic query parameters", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://www.example.com/path?param=value&foo=bar&baz=batman&qux=", nil)
		msg := WrapRequest(req)

		tests := []struct {
			paramName string
			want      string
		}{
			{"baz", "batman"},
			{"qux", ""},
			{"param", "value"},
		}

		for _, tt := range tests {
			t.Run("param="+tt.paramName, func(t *testing.T) {
				comp := parser.ComponentIdentifier{
					Name: "@query-param",
					Type: parser.ComponentDerived,
					Parameters: []parser.Parameter{
						{Key: "name", Value: parser.String{Value: tt.paramName}},
					},
				}

				got, err := extractComponentValue(msg, comp)
				if err != nil {
					t.Fatalf("extractComponentValue() error = %v", err)
				}

				if got != tt.want {
					t.Errorf("extractComponentValue() = %q, want %q", got, tt.want)
				}
			})
		}
	})

	t.Run("complex encoded parameters", func(t *testing.T) {
		// RFC example: this%20is%20a%20big%0Amultiline%20value decoded by Go
		req, _ := http.NewRequest("GET", "https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something", nil)
		msg := WrapRequest(req)

		tests := []struct {
			paramName string
			want      string
		}{
			{"var", "this is a big\nmultiline value"},
			{"bar", "with plus whitespace"},
			{"façade\": ", "something"},
		}

		for _, tt := range tests {
			t.Run("param="+tt.paramName, func(t *testing.T) {
				comp := parser.ComponentIdentifier{
					Name: "@query-param",
					Type: parser.ComponentDerived,
					Parameters: []parser.Parameter{
						{Key: "name", Value: parser.String{Value: tt.paramName}},
					},
				}

				got, err := extractComponentValue(msg, comp)
				if err != nil {
					t.Fatalf("extractComponentValue() error = %v", err)
				}

				if got != tt.want {
					t.Errorf("extractComponentValue() = %q, want %q", got, tt.want)
				}
			})
		}
	})
}

// RFC 9421 Section 2.2.9 - @status Component
func TestRFC9421_Section2_2_9_Status(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Date": []string{"Fri, 26 Mar 2010 00:05:00 GMT"},
		},
	}

	msg := WrapResponse(resp, nil)
	comp := parser.ComponentIdentifier{Name: "@status", Type: parser.ComponentDerived}

	got, err := extractComponentValue(msg, comp)
	if err != nil {
		t.Fatalf("extractComponentValue() error = %v", err)
	}

	want := "200"
	if got != want {
		t.Errorf("extractComponentValue() = %q, want %q", got, want)
	}
}

// RFC 9421 Appendix B.2.1 - Minimal Signature
func TestRFC9421_AppendixB_2_1_MinimalSignature(t *testing.T) {
	body := strings.NewReader(`{"hello": "world"}`)
	req, _ := http.NewRequest("POST", "https://example.com/foo?param=Value&Pet=dog", body)
	req.Header.Set("Host", "example.com")
	req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "18")

	msg := WrapRequest(req)

	components := []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "@authority", Type: parser.ComponentDerived},
		{Name: "@path", Type: parser.ComponentDerived},
		{Name: "@query", Type: parser.ComponentDerived},
		{Name: "content-type", Type: parser.ComponentField},
	}

	created := int64(1618884473)
	keyid := "test-key-rsa-pss"
	params := parser.SignatureParams{
		Created: &created,
		KeyID:   &keyid,
	}

	got, err := Build(msg, components, params)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	want := `"@method": POST
"@authority": example.com
"@path": /foo
"@query": ?param=Value&Pet=dog
"content-type": application/json
"@signature-params": ("@method" "@authority" "@path" "@query" "content-type");created=1618884473;keyid="test-key-rsa-pss"`

	if got != want {
		t.Errorf("Build() signature base mismatch\nGot:\n%s\n\nWant:\n%s", got, want)
	}
}

// RFC 9421 Appendix B.2.2 - Selective Covered Components
func TestRFC9421_AppendixB_2_2_SelectiveCoverage(t *testing.T) {
	body := strings.NewReader(`{"hello": "world"}`)
	req, _ := http.NewRequest("POST", "https://example.com/foo?param=Value&Pet=dog", body)
	req.Header.Set("Host", "example.com")
	req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "18")

	msg := WrapRequest(req)

	components := []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "@authority", Type: parser.ComponentDerived},
		{Name: "@path", Type: parser.ComponentDerived},
		{Name: "@query", Type: parser.ComponentDerived},
		{Name: "date", Type: parser.ComponentField},
		{Name: "content-type", Type: parser.ComponentField},
		{Name: "content-length", Type: parser.ComponentField},
	}

	created := int64(1618884473)
	keyid := "test-key-rsa-pss"
	params := parser.SignatureParams{
		Created: &created,
		KeyID:   &keyid,
	}

	got, err := Build(msg, components, params)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	want := `"@method": POST
"@authority": example.com
"@path": /foo
"@query": ?param=Value&Pet=dog
"date": Tue, 20 Apr 2021 02:07:55 GMT
"content-type": application/json
"content-length": 18
"@signature-params": ("@method" "@authority" "@path" "@query" "date" "content-type" "content-length");created=1618884473;keyid="test-key-rsa-pss"`

	if got != want {
		t.Errorf("Build() signature base mismatch\nGot:\n%s\n\nWant:\n%s", got, want)
	}
}

// RFC 9421 Appendix B.2.4 - Signing a Response (with req parameter)
func TestRFC9421_AppendixB_2_4_ResponseSignature(t *testing.T) {
	// Original request
	originalReq, _ := http.NewRequest("POST", "https://example.com/foo?param=Value&Pet=dog", nil)
	originalReq.Header.Set("Host", "example.com")
	originalReq.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	originalReq.Header.Set("Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:")
	originalReq.Header.Set("Content-Type", "application/json")
	originalReq.Header.Set("Content-Length", "18")

	// Response
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Date":           []string{"Tue, 20 Apr 2021 02:07:56 GMT"},
			"Content-Type":   []string{"application/json"},
			"Content-Length": []string{"62"},
			"Content-Digest": []string{"sha-512=:0Y6iCBzGg5rZtoXS95Ijz03mslf6KAMCloESHObfwnHJDbkkWWQz6PhhU9kxsTbARtY2PTBOzq24uJFpHsMuAg==:"},
		},
	}

	msg := WrapResponse(resp, originalReq)

	components := []parser.ComponentIdentifier{
		{Name: "@status", Type: parser.ComponentDerived},
		{Name: "content-digest", Type: parser.ComponentField},
		{Name: "content-type", Type: parser.ComponentField},
		{
			Name: "@authority",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "req", Value: parser.Boolean{Value: true}},
			},
		},
		{
			Name: "@method",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "req", Value: parser.Boolean{Value: true}},
			},
		},
		{
			Name: "@path",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "req", Value: parser.Boolean{Value: true}},
			},
		},
		{
			Name: "content-digest",
			Type: parser.ComponentField,
			Parameters: []parser.Parameter{
				{Key: "req", Value: parser.Boolean{Value: true}},
			},
		},
	}

	created := int64(1618884479)
	keyid := "test-key-ecc-p256"
	params := parser.SignatureParams{
		Created: &created,
		KeyID:   &keyid,
	}

	got, err := Build(msg, components, params)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	want := `"@status": 200
"content-digest": sha-512=:0Y6iCBzGg5rZtoXS95Ijz03mslf6KAMCloESHObfwnHJDbkkWWQz6PhhU9kxsTbARtY2PTBOzq24uJFpHsMuAg==:
"content-type": application/json
"@authority";req: example.com
"@method";req: POST
"@path";req: /foo
"content-digest";req: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"@signature-params": ("@status" "content-digest" "content-type" "@authority";req "@method";req "@path";req "content-digest";req);created=1618884479;keyid="test-key-ecc-p256"`

	if got != want {
		t.Errorf("Build() signature base mismatch\nGot:\n%s\n\nWant:\n%s", got, want)
	}
}
