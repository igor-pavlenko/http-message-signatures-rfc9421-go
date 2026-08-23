package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/digest"
)

// extra bundles the optional signature-parameter overrides a scenario may
// exercise, beyond the "created" parameter both libraries add by default.
type extra struct {
	keyID   bool // include the RFC keyid for this algorithm's key
	nonce   string
	tag     string
	expires bool // sign with expires = created + 5 minutes
}

// scenario is one logical HTTP message, signed by one library and verified
// by the other (in both directions). buildReq must return a fresh request
// on every call since signing mutates headers.
type scenario struct {
	name        string
	algID       string
	headers     []string // component names: "@"-prefixed => derived, else HTTP field
	queryParams []string // @query-param;name=... components
	extra       extra
	isResponse  bool
	buildReq    func() *http.Request
	buildResp   func(req *http.Request) *http.Response // set only when isResponse
}

func jsonBody(body string) (io.ReadCloser, int64) {
	return io.NopCloser(strings.NewReader(body)), int64(len(body))
}

// withContentDigest computes a sha-256 Content-Digest for body and sets it,
// along with Content-Length, on the given header. Both libraries only read
// this header at sign/verify time; the digest itself is computed once, here,
// with our own pkg/digest so both directions cover an identical value.
func withContentDigest(h http.Header, body string) {
	sum, err := digest.ComputeDigest([]byte(body), "sha-256")
	if err != nil {
		panic(err)
	}
	header, err := digest.FormatContentDigest(map[string][]byte{"sha-256": sum})
	if err != nil {
		panic(err)
	}
	h.Set("Content-Digest", header)
	h.Set("Content-Length", strconv.Itoa(len(body)))
}

func scenarios() []scenario {
	var all []scenario
	all = append(all, rsaPSSScenarios()...)
	all = append(all, rsaV15Scenarios()...)
	all = append(all, ecdsaP256Scenarios()...)
	all = append(all, ed25519Scenarios()...)
	all = append(all, hmacScenarios()...)
	return all
}

func rsaPSSScenarios() []scenario {
	return []scenario{
		{
			name:    "RSA-PSS-SHA512: create order",
			algID:   "rsa-pss-sha512",
			headers: []string{"@method", "@target-uri", "content-type"},
			extra:   extra{keyID: true},
			buildReq: func() *http.Request {
				body, n := jsonBody(`{"item":"widget","qty":3}`)
				req := httptest.NewRequest(http.MethodPost, "https://example.com/orders", body)
				req.ContentLength = n
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:    "RSA-PSS-SHA512: payment with Content-Digest",
			algID:   "rsa-pss-sha512",
			headers: []string{"@method", "@target-uri", "content-type", "content-length", "content-digest"},
			extra:   extra{keyID: true, expires: true},
			buildReq: func() *http.Request {
				const b = `{"amount":249.99,"currency":"USD"}`
				body, n := jsonBody(b)
				req := httptest.NewRequest(http.MethodPost, "https://example.com/payments", body)
				req.ContentLength = n
				req.Header.Set("Content-Type", "application/json")
				withContentDigest(req.Header, b)
				return req
			},
		},
		{
			name:       "RSA-PSS-SHA512: invoice lookup (response)",
			algID:      "rsa-pss-sha512",
			headers:    []string{"@status", "content-type"},
			extra:      extra{keyID: true},
			isResponse: true,
			buildReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "https://example.com/invoices/9911", nil)
			},
			buildResp: func(req *http.Request) *http.Response {
				const b = `{"invoice_id":"9911","status":"paid"}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(bytes.NewReader([]byte(b))),
					Request:    req,
				}
			},
		},
	}
}

func rsaV15Scenarios() []scenario {
	return []scenario{
		{
			name:    "RSA-v1.5-SHA256: fetch account",
			algID:   "rsa-v1_5-sha256",
			headers: []string{"@method", "@path", "@authority"},
			extra:   extra{keyID: true},
			buildReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "https://example.com/accounts/42", nil)
			},
		},
		{
			name:    "RSA-v1.5-SHA256: update profile",
			algID:   "rsa-v1_5-sha256",
			headers: []string{"@request-target", "content-type"},
			extra:   extra{nonce: "n-4f3c2a91"},
			buildReq: func() *http.Request {
				body, n := jsonBody(`{"display_name":"Ada Lovelace"}`)
				req := httptest.NewRequest(http.MethodPut, "https://example.com/accounts/42/profile", body)
				req.ContentLength = n
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
	}
}

func ecdsaP256Scenarios() []scenario {
	return []scenario{
		{
			name:    "ECDSA-P256-SHA256: health status",
			algID:   "ecdsa-p256-sha256",
			headers: []string{"@method", "@target-uri", "date"},
			buildReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "https://example.com/status", nil)
				req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
				return req
			},
		},
		{
			name:    "ECDSA-P256-SHA256: webhook notify",
			algID:   "ecdsa-p256-sha256",
			headers: []string{"@authority", "@scheme", "content-type"},
			extra:   extra{expires: true},
			buildReq: func() *http.Request {
				body, n := jsonBody(`{"event":"order.shipped","order_id":"ORD-1001"}`)
				req := httptest.NewRequest(http.MethodPost, "https://example.com/webhooks/notify", body)
				req.ContentLength = n
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:       "ECDSA-P256-SHA256: create order (response)",
			algID:      "ecdsa-p256-sha256",
			headers:    []string{"@status", "content-type", "content-length"},
			extra:      extra{keyID: true},
			isResponse: true,
			buildReq: func() *http.Request {
				body, n := jsonBody(`{"item":"widget","qty":3}`)
				req := httptest.NewRequest(http.MethodPost, "https://example.com/orders", body)
				req.ContentLength = n
				req.Header.Set("Content-Type", "application/json")
				return req
			},
			buildResp: func(req *http.Request) *http.Response {
				const b = `{"order_id":"ORD-2002","status":"created"}`
				return &http.Response{
					StatusCode: http.StatusCreated,
					Header: http.Header{
						"Content-Type":   []string{"application/json"},
						"Content-Length": []string{strconv.Itoa(len(b))},
					},
					Body:    io.NopCloser(bytes.NewReader([]byte(b))),
					Request: req,
				}
			},
		},
	}
}

func ed25519Scenarios() []scenario {
	return []scenario{
		{
			name:    "Ed25519: health check",
			algID:   "ed25519",
			headers: []string{"@method", "@target-uri"},
			buildReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "https://example.com/health", nil)
			},
		},
		{
			name:    "Ed25519: post comment",
			algID:   "ed25519",
			headers: []string{"@method", "@path", "content-type"},
			extra:   extra{tag: "example-app"},
			buildReq: func() *http.Request {
				body, n := jsonBody(`{"text":"looks good to me"}`)
				req := httptest.NewRequest(http.MethodPost, "https://example.com/comments", body)
				req.ContentLength = n
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:    "Ed25519: revoke session",
			algID:   "ed25519",
			headers: []string{"@method", "@target-uri", "@authority"},
			extra:   extra{keyID: true, nonce: "n-8b21ff10"},
			buildReq: func() *http.Request {
				return httptest.NewRequest(http.MethodDelete, "https://example.com/sessions/abc123", nil)
			},
		},
		{
			name:        "Ed25519: search with query param",
			algID:       "ed25519",
			headers:     []string{"@method", "@query"},
			queryParams: []string{"category"},
			extra:       extra{keyID: true},
			buildReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "https://example.com/search?q=widgets&category=tools", nil)
			},
		},
	}
}

func hmacScenarios() []scenario {
	return []scenario{
		{
			name:    "HMAC-SHA256: submit event",
			algID:   "hmac-sha256",
			headers: []string{"@method", "@target-uri", "content-type"},
			buildReq: func() *http.Request {
				body, n := jsonBody(`{"event":"login","user_id":"u-77"}`)
				req := httptest.NewRequest(http.MethodPost, "https://example.com/events", body)
				req.ContentLength = n
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:    "HMAC-SHA256: upload metadata with Content-Digest",
			algID:   "hmac-sha256",
			headers: []string{"@method", "@target-uri", "content-digest", "content-length"},
			extra:   extra{expires: true},
			buildReq: func() *http.Request {
				const b = `{"filename":"report.pdf","size":10240}`
				body, n := jsonBody(b)
				req := httptest.NewRequest(http.MethodPost, "https://example.com/uploads/meta", body)
				req.ContentLength = n
				req.Header.Set("Content-Type", "application/json")
				withContentDigest(req.Header, b)
				return req
			},
		},
		{
			name:        "HMAC-SHA256: list users with query param",
			algID:       "hmac-sha256",
			headers:     []string{"@method"},
			queryParams: []string{"user"},
			extra:       extra{keyID: true},
			buildReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "https://example.com/users?user=alice&sort=asc", nil)
			},
		},
		{
			name:    "HMAC-SHA256: patch settings",
			algID:   "hmac-sha256",
			headers: []string{"@method", "@authority", "content-type"},
			extra:   extra{nonce: "n-1a2b3c4d"},
			buildReq: func() *http.Request {
				body, n := jsonBody(`{"notifications":"disabled"}`)
				req := httptest.NewRequest(http.MethodPatch, "https://example.com/settings", body)
				req.ContentLength = n
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
	}
}
