package comparison

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
)

const (
	benchmarkCreatedMaxAge     = 5 * time.Minute
	benchmarkCreatedFutureSkew = time.Minute
	benchmarkLargeBodySize     = int64(10 * 1024 * 1024)
	benchmarkLargeBodyChunk    = 32 * 1024
)

// Shared test keys - generated once at init
var (
	testRSAPrivKey *rsa.PrivateKey
	testRSAPubKey  *rsa.PublicKey
	testECPrivKey  *ecdsa.PrivateKey
	testECPubKey   *ecdsa.PublicKey
	testHMACKey    []byte
	largeBodyChunk = bytes.Repeat([]byte("a"), benchmarkLargeBodyChunk)
)

func init() {
	var err error

	// Generate RSA 2048-bit key pair
	testRSAPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate RSA key: " + err.Error())
	}
	testRSAPubKey = &testRSAPrivKey.PublicKey

	// Generate ECDSA P-256 key pair
	testECPrivKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("failed to generate ECDSA key: " + err.Error())
	}
	testECPubKey = &testECPrivKey.PublicKey

	// Generate HMAC key (64 bytes - required by yaronf/httpsign)
	testHMACKey = make([]byte, 64)
	if _, err = rand.Read(testHMACKey); err != nil {
		panic("failed to generate HMAC key: " + err.Error())
	}
}

// createTestRequest creates a standard HTTP request for benchmarking
func createTestRequest() *http.Request {
	body := `{"message": "hello world", "timestamp": 1234567890}`
	req := httptest.NewRequest(
		http.MethodPost,
		"https://example.com/api/resource?param=value",
		strings.NewReader(body),
	)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "52")
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	req.Host = "example.com"
	return req
}

type repeatReader struct {
	chunk     []byte
	remaining int64
	offset    int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n := 0
	for n < len(p) {
		avail := len(r.chunk) - r.offset
		if avail > len(p)-n {
			avail = len(p) - n
		}
		copy(p[n:n+avail], r.chunk[r.offset:r.offset+avail])
		n += avail
		r.offset += avail
		if r.offset == len(r.chunk) {
			r.offset = 0
		}
	}
	r.remaining -= int64(n)
	return n, nil
}

func newLargeBodyReader() *repeatReader {
	return &repeatReader{chunk: largeBodyChunk, remaining: benchmarkLargeBodySize}
}

func newLargeBody() io.ReadCloser {
	return io.NopCloser(newLargeBodyReader())
}

func createLargeRequest() *http.Request {
	body := newLargeBody()
	req := httptest.NewRequest(
		http.MethodPost,
		"https://example.com/api/resource?param=value",
		body,
	)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", strconv.FormatInt(benchmarkLargeBodySize, 10))
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	req.Host = "example.com"
	req.ContentLength = benchmarkLargeBodySize
	return req
}

// Components to sign for IgorPavlenko
var testComponents = []parser.ComponentIdentifier{
	{Name: "@method", Type: parser.ComponentDerived},
	{Name: "@target-uri", Type: parser.ComponentDerived},
	{Name: "content-type", Type: parser.ComponentField},
}

var testDigestComponents = []parser.ComponentIdentifier{
	{Name: "@method", Type: parser.ComponentDerived},
	{Name: "@target-uri", Type: parser.ComponentDerived},
	{Name: "content-type", Type: parser.ComponentField},
	{Name: "content-length", Type: parser.ComponentField},
	{Name: "content-digest", Type: parser.ComponentField},
}

func benchmarkValidationOptions() parser.SignatureParamsValidationOptions {
	return parser.SignatureParamsValidationOptions{
		RequireCreated:          true,
		CreatedNotOlderThan:     benchmarkCreatedMaxAge,
		CreatedNotNewerThan:     benchmarkCreatedFutureSkew,
		RejectExpired:           true,
		ExpiresNotBeforeCreated: true,
	}
}
