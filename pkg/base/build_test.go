package base

import (
	"net/http"
	"testing"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
)

// T017: Test Build() orchestration
func TestBuild(t *testing.T) {
	t.Run("minimal signature - no components", func(t *testing.T) {
		// RFC 9421 Appendix B.2.1: Empty covered components list is valid
		req, _ := http.NewRequest("POST", "https://example.com/foo", nil)
		msg := WrapRequest(req)

		var components []parser.ComponentIdentifier
		params := parser.SignatureParams{}

		got, err := Build(msg, components, params)
		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}

		want := `"@signature-params": ()`
		if got != want {
			t.Errorf("Build() = %q, want %q", got, want)
		}
	})

	t.Run("single derived component", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://example.com/foo", nil)
		msg := WrapRequest(req)

		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
		}
		params := parser.SignatureParams{}

		got, err := Build(msg, components, params)
		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}

		want := "\"@method\": POST\n\"@signature-params\": (\"@method\")"
		if got != want {
			t.Errorf("Build() = %q, want %q", got, want)
		}
	})

	t.Run("multiple components", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://example.com/foo?param=value", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Host", "example.com")

		msg := WrapRequest(req)

		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
			{Name: "@path", Type: parser.ComponentDerived},
			{Name: "content-type", Type: parser.ComponentField},
		}

		created := int64(1618884473)
		params := parser.SignatureParams{
			Created: &created,
		}

		got, err := Build(msg, components, params)
		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}

		expected := "\"@method\": POST\n\"@path\": /foo\n\"content-type\": application/json\n\"@signature-params\": (\"@method\" \"@path\" \"content-type\");created=1618884473"
		if got != expected {
			t.Errorf("Build() = %q, want %q", got, expected)
		}
	})

	t.Run("with all signature params", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://example.com/foo", nil)
		msg := WrapRequest(req)

		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
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

		got, err := Build(msg, components, params)
		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}

		expected := "\"@method\": POST\n\"@signature-params\": (\"@method\");created=1618884473;expires=1618884773;nonce=\"test-nonce\";alg=\"rsa-pss-sha512\";keyid=\"test-key-rsa-pss\";tag=\"test-tag\""
		if got != expected {
			t.Errorf("Build() = %q, want %q", got, expected)
		}
	})

	t.Run("missing header returns error", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		msg := WrapRequest(req)

		components := []parser.ComponentIdentifier{
			{Name: "missing-header", Type: parser.ComponentField},
		}
		params := parser.SignatureParams{}

		_, err := Build(msg, components, params)
		if err == nil {
			t.Error("Build() should return error for missing header")
		}
	})

	t.Run("invalid derived component returns error", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		msg := WrapRequest(req)

		components := []parser.ComponentIdentifier{
			{Name: "@status", Type: parser.ComponentDerived}, // Invalid for request
		}
		params := parser.SignatureParams{}

		_, err := Build(msg, components, params)
		if err == nil {
			t.Error("Build() should return error for invalid derived component")
		}
	})

	t.Run("with @query-param component", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/search?query=test&page=2", nil)
		msg := WrapRequest(req)

		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
			{Name: "@path", Type: parser.ComponentDerived},
			{
				Name: "@query-param",
				Type: parser.ComponentDerived,
				Parameters: []parser.Parameter{
					{Key: "name", Value: parser.String{Value: "query"}},
				},
			},
		}

		created := int64(1618884473)
		params := parser.SignatureParams{
			Created: &created,
		}

		got, err := Build(msg, components, params)
		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}

		expected := "\"@method\": GET\n\"@path\": /search\n\"@query-param\";name=\"query\": test\n\"@signature-params\": (\"@method\" \"@path\" \"@query-param\";name=\"query\");created=1618884473"
		if got != expected {
			t.Errorf("Build() = %q, want %q", got, expected)
		}
	})

	t.Run("with @query component", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://example.com/foo?param=value&pet=dog", nil)
		msg := WrapRequest(req)

		components := []parser.ComponentIdentifier{
			{Name: "@method", Type: parser.ComponentDerived},
			{Name: "@query", Type: parser.ComponentDerived},
		}
		params := parser.SignatureParams{}

		got, err := Build(msg, components, params)
		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}

		expected := "\"@method\": POST\n\"@query\": ?param=value&pet=dog\n\"@signature-params\": (\"@method\" \"@query\")"
		if got != expected {
			t.Errorf("Build() = %q, want %q", got, expected)
		}
	})
}

// T019: RFC 9421 Appendix B.2 test vectors
func TestBuild_RFC9421_TestVectors(t *testing.T) {
	// Test vector from RFC 9421 Appendix B.2.1: Minimal Signature
	t.Run("RFC B.2.1 - Minimal Signature", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://example.com/foo?param=value&pet=dog", nil)
		req.Header.Set("Host", "example.com")
		req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Length", "18")

		msg := WrapRequest(req)

		var components []parser.ComponentIdentifier
		params := parser.SignatureParams{}

		got, err := Build(msg, components, params)
		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}

		// RFC 9421 B.2.1: Empty covered components
		want := `"@signature-params": ()`
		if got != want {
			t.Errorf("Build() = %q\nwant %q", got, want)
		}
	})

	// Test vector from RFC 9421 Appendix B.2.2: Selective Covered Components
	t.Run("RFC B.2.2 - Selective Covered Components", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://example.com/foo?param=value&pet=dog", nil)
		req.Header.Set("Host", "example.com")
		req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Length", "18")

		msg := WrapRequest(req)

		components := []parser.ComponentIdentifier{
			{Name: "@authority", Type: parser.ComponentDerived},
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

		// RFC 9421 B.2.2 Expected signature base
		want := `"@authority": example.com
"content-type": application/json
"@signature-params": ("@authority" "content-type");created=1618884473;keyid="test-key-rsa-pss"`

		if got != want {
			t.Errorf("Build() mismatch\nGot:\n%s\n\nWant:\n%s", got, want)
		}
	})

	// Test vector from RFC 9421 Appendix B.2.3: Full Coverage
	t.Run("RFC B.2.3 - Full Coverage", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "https://example.com/foo?param=value&pet=dog", nil)
		req.Header.Set("Host", "example.com")
		req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:")
		req.Header.Set("Content-Length", "18")

		msg := WrapRequest(req)

		components := []parser.ComponentIdentifier{
			{Name: "date", Type: parser.ComponentField},
			{Name: "@method", Type: parser.ComponentDerived},
			{Name: "@path", Type: parser.ComponentDerived},
			{Name: "@authority", Type: parser.ComponentDerived},
			{Name: "content-type", Type: parser.ComponentField},
			{Name: "content-digest", Type: parser.ComponentField},
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

		// RFC 9421 B.2.3 Expected signature base
		want := `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@authority": example.com
"content-type": application/json
"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`

		if got != want {
			t.Errorf("Build() mismatch\nGot:\n%s\n\nWant:\n%s", got, want)
		}
	})
}
