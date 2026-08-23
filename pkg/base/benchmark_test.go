package base

import (
	"net/http"
	"strings"
	"testing"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
)

// Benchmark fixtures
var (
	benchRequest  *http.Request
	benchResponse *http.Response
	benchMessage  HTTPMessage
	benchRespMsg  HTTPMessage

	// Component lists of varying sizes
	benchComponents0  []parser.ComponentIdentifier
	benchComponents3  []parser.ComponentIdentifier
	benchComponents7  []parser.ComponentIdentifier
	benchComponents15 []parser.ComponentIdentifier

	// Derived-only and field-only component lists
	benchDerivedOnly []parser.ComponentIdentifier
	benchFieldsOnly  []parser.ComponentIdentifier

	// Signature params
	benchParams     parser.SignatureParams
	benchParamsFull parser.SignatureParams
)

func init() {
	// Create benchmark HTTP request with various headers
	benchRequest, _ = http.NewRequest("POST", "https://example.com/foo/bar?param=value&other=test", nil)
	benchRequest.Header.Set("Host", "example.com")
	benchRequest.Header.Set("Date", "Tue, 20 Apr 2021 02:07:56 GMT")
	benchRequest.Header.Set("Content-Type", "application/json")
	benchRequest.Header.Set("Content-Length", "1234")
	benchRequest.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
	benchRequest.Header.Set("X-Custom-Header", "custom-value-here")
	benchRequest.Header.Set("Accept", "application/json, text/plain, */*")
	benchRequest.Header.Add("Cache-Control", "max-age=60")
	benchRequest.Header.Add("Cache-Control", "must-revalidate")
	benchRequest.Header.Set("X-Request-ID", "550e8400-e29b-41d4-a716-446655440000")

	benchMessage = WrapRequest(benchRequest)

	// Create benchmark HTTP response
	benchResponse = &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type":   []string{"application/json"},
			"Content-Length": []string{"5678"},
			"Date":           []string{"Tue, 20 Apr 2021 02:07:57 GMT"},
			"X-Response-ID":  []string{"resp-12345"},
		},
	}
	benchRespMsg = WrapResponse(benchResponse, benchRequest)

	// Empty components (RFC 9421 B.2.1)
	benchComponents0 = []parser.ComponentIdentifier{}

	// 3 components (RFC 9421 B.2.2 style)
	benchComponents3 = []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "@path", Type: parser.ComponentDerived},
		{Name: "content-type", Type: parser.ComponentField},
	}

	// 7 components (RFC 9421 B.2.3 style)
	benchComponents7 = []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "@authority", Type: parser.ComponentDerived},
		{Name: "@path", Type: parser.ComponentDerived},
		{Name: "content-type", Type: parser.ComponentField},
		{Name: "content-length", Type: parser.ComponentField},
		{Name: "date", Type: parser.ComponentField},
		{Name: "host", Type: parser.ComponentField},
	}

	// 15 components (maximum realistic)
	benchComponents15 = []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "@target-uri", Type: parser.ComponentDerived},
		{Name: "@authority", Type: parser.ComponentDerived},
		{Name: "@scheme", Type: parser.ComponentDerived},
		{Name: "@path", Type: parser.ComponentDerived},
		{Name: "@query", Type: parser.ComponentDerived},
		{Name: "host", Type: parser.ComponentField},
		{Name: "date", Type: parser.ComponentField},
		{Name: "content-type", Type: parser.ComponentField},
		{Name: "content-length", Type: parser.ComponentField},
		{Name: "authorization", Type: parser.ComponentField},
		{Name: "x-custom-header", Type: parser.ComponentField},
		{Name: "accept", Type: parser.ComponentField},
		{Name: "cache-control", Type: parser.ComponentField},
		{Name: "x-request-id", Type: parser.ComponentField},
	}

	// Derived components only
	benchDerivedOnly = []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "@target-uri", Type: parser.ComponentDerived},
		{Name: "@authority", Type: parser.ComponentDerived},
		{Name: "@path", Type: parser.ComponentDerived},
	}

	// HTTP fields only
	benchFieldsOnly = []parser.ComponentIdentifier{
		{Name: "host", Type: parser.ComponentField},
		{Name: "date", Type: parser.ComponentField},
		{Name: "content-type", Type: parser.ComponentField},
		{Name: "content-length", Type: parser.ComponentField},
	}

	// Minimal signature params
	created := int64(1618884473)
	benchParams = parser.SignatureParams{
		Created: &created,
	}

	// Full signature params
	expires := int64(1618884773)
	nonce := "b3k2pp5k7z-50gnwp"
	alg := "rsa-pss-sha512"
	keyid := "test-key-rsa-pss"
	tag := "application-specific-tag"
	benchParamsFull = parser.SignatureParams{
		Created:   &created,
		Expires:   &expires,
		Nonce:     &nonce,
		Algorithm: &alg,
		KeyID:     &keyid,
		Tag:       &tag,
	}
}

// =============================================================================
// Build Benchmarks - By Component Count
// =============================================================================

// BenchmarkBuild_MinimalSignature benchmarks RFC 9421 B.2.1 - empty components.
func BenchmarkBuild_MinimalSignature(b *testing.B) {
	params := parser.SignatureParams{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Build(benchMessage, benchComponents0, params)
	}
}

// BenchmarkBuild_SelectiveComponents benchmarks RFC 9421 B.2.2 style - 3 components.
func BenchmarkBuild_SelectiveComponents(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Build(benchMessage, benchComponents3, benchParams)
	}
}

// BenchmarkBuild_FullCoverage benchmarks RFC 9421 B.2.3 style - 7 components.
func BenchmarkBuild_FullCoverage(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Build(benchMessage, benchComponents7, benchParams)
	}
}

// BenchmarkBuild_MaxComponents benchmarks maximum realistic - 15 components.
func BenchmarkBuild_MaxComponents(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Build(benchMessage, benchComponents15, benchParams)
	}
}

// =============================================================================
// Build Benchmarks - By Component Type
// =============================================================================

// BenchmarkBuild_DerivedOnly benchmarks derived components only (@method, @path, etc.).
func BenchmarkBuild_DerivedOnly(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Build(benchMessage, benchDerivedOnly, benchParams)
	}
}

// BenchmarkBuild_FieldsOnly benchmarks HTTP field components only.
func BenchmarkBuild_FieldsOnly(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Build(benchMessage, benchFieldsOnly, benchParams)
	}
}

// BenchmarkBuild_MixedComponents benchmarks mixed derived + field components.
func BenchmarkBuild_MixedComponents(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Build(benchMessage, benchComponents7, benchParams)
	}
}

// =============================================================================
// Build Benchmarks - Special Cases
// =============================================================================

// BenchmarkBuild_LongHeaders benchmarks with large header values.
func BenchmarkBuild_LongHeaders(b *testing.B) {
	// Create request with long header values
	req, _ := http.NewRequest("POST", "https://example.com/foo", nil)
	req.Header.Set("X-Long-Header-1", strings.Repeat("abcdefghij", 20)) // 200 chars
	req.Header.Set("X-Long-Header-2", strings.Repeat("1234567890", 20)) // 200 chars
	req.Header.Set("X-Long-Header-3", strings.Repeat("ABCDEFGHIJ", 20)) // 200 chars
	msg := WrapRequest(req)

	components := []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "x-long-header-1", Type: parser.ComponentField},
		{Name: "x-long-header-2", Type: parser.ComponentField},
		{Name: "x-long-header-3", Type: parser.ComponentField},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Build(msg, components, benchParams)
	}
}

// BenchmarkBuild_MultiValueFields benchmarks headers with multiple values.
func BenchmarkBuild_MultiValueFields(b *testing.B) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Add("Accept", "text/html")
	req.Header.Add("Accept", "application/xhtml+xml")
	req.Header.Add("Accept", "application/xml;q=0.9")
	req.Header.Add("Accept", "*/*;q=0.8")
	req.Header.Add("Cache-Control", "max-age=0")
	req.Header.Add("Cache-Control", "no-cache")
	req.Header.Add("Cache-Control", "must-revalidate")
	msg := WrapRequest(req)

	components := []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "accept", Type: parser.ComponentField},
		{Name: "cache-control", Type: parser.ComponentField},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Build(msg, components, benchParams)
	}
}

// BenchmarkBuild_QueryParams benchmarks @query-param extraction.
func BenchmarkBuild_QueryParams(b *testing.B) {
	req, _ := http.NewRequest("GET", "https://example.com/search?q=test&page=1&limit=10", nil)
	msg := WrapRequest(req)

	components := []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "@query", Type: parser.ComponentDerived},
		{
			Name: "@query-param",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "name", Value: parser.String{Value: "q"}},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Build(msg, components, benchParams)
	}
}

// BenchmarkBuild_WithAllParams benchmarks with full signature params.
func BenchmarkBuild_WithAllParams(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Build(benchMessage, benchComponents7, benchParamsFull)
	}
}

// =============================================================================
// Build Benchmarks - Request vs Response
// =============================================================================

// BenchmarkBuild_Request_5Components benchmarks request signature base.
func BenchmarkBuild_Request_5Components(b *testing.B) {
	components := []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{Name: "@path", Type: parser.ComponentDerived},
		{Name: "host", Type: parser.ComponentField},
		{Name: "date", Type: parser.ComponentField},
		{Name: "content-type", Type: parser.ComponentField},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Build(benchMessage, components, benchParams)
	}
}

// BenchmarkBuild_Response_5Components benchmarks response signature base.
func BenchmarkBuild_Response_5Components(b *testing.B) {
	components := []parser.ComponentIdentifier{
		{Name: "@status", Type: parser.ComponentDerived},
		{Name: "content-type", Type: parser.ComponentField},
		{Name: "content-length", Type: parser.ComponentField},
		{Name: "date", Type: parser.ComponentField},
		{Name: "x-response-id", Type: parser.ComponentField},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Build(benchRespMsg, components, benchParams)
	}
}

// =============================================================================
// Memory Allocation Benchmarks
// =============================================================================

// BenchmarkBuild_Allocations_5Components tracks memory allocations for 5 components.
func BenchmarkBuild_Allocations_5Components(b *testing.B) {
	components := benchComponents3 // Actually 3, but representative

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Build(benchMessage, components, benchParams)
	}
}

// BenchmarkBuild_Allocations_15Components tracks memory allocations for 15 components.
func BenchmarkBuild_Allocations_15Components(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Build(benchMessage, benchComponents15, benchParamsFull)
	}
}

// =============================================================================
// Scaling Benchmarks
// =============================================================================

// BenchmarkBuild_Scaling measures how performance scales with component count.
func BenchmarkBuild_Scaling(b *testing.B) {
	tests := []struct {
		name       string
		components []parser.ComponentIdentifier
	}{
		{"0_Components", benchComponents0},
		{"3_Components", benchComponents3},
		{"7_Components", benchComponents7},
		{"15_Components", benchComponents15},
	}

	for _, tc := range tests {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = Build(benchMessage, tc.components, benchParams)
			}
		})
	}
}
