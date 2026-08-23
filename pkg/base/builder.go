package base

import (
	"net/url"
)

// HTTPMessage provides a unified interface for accessing HTTP request and response
// components needed for signature base construction.
//
// This interface abstracts over Go's standard *http.Request and *http.Response types,
// enabling signature base building for both message types through a common API.
//
// Implementations are provided by WrapRequest and WrapResponse adapter functions.
type HTTPMessage interface {
	// IsRequest returns true if this is an HTTP request message.
	// Exactly one of IsRequest() or IsResponse() must return true.
	IsRequest() bool

	// IsResponse returns true if this is an HTTP response message.
	// Exactly one of IsRequest() or IsResponse() must return true.
	IsResponse() bool

	// Method returns the HTTP method (GET, POST, etc.) for requests.
	// The method is returned in uppercase as it appears in the request line.
	// Returns an error if called on a response message.
	Method() (string, error)

	// URL returns the complete request URL with scheme, host, path, and query.
	// Returns an error if called on a response message.
	URL() (*url.URL, error)

	// StatusCode returns the HTTP status code (200, 404, etc.) for responses.
	// Returns an error if called on a request message.
	StatusCode() (int, error)

	// HeaderValues returns all values for the specified header field.
	// Field name lookup is case-insensitive per HTTP semantics.
	// Returns empty slice if the header is not present (not an error).
	// Multiple header instances are returned in the order they appear.
	HeaderValues(name string) []string

	// TrailerValues returns all values for the specified trailer field.
	// Trailers are headers that come after the message body.
	// Field name lookup is case-insensitive per HTTP semantics.
	// Returns empty slice if the trailer is not present (not an error).
	TrailerValues(name string) []string

	// RelatedRequest returns the related request for response signatures.
	// Used when the 'req' component parameter is specified to access
	// request components from within a response signature.
	// Returns nil if no related request is available.
	RelatedRequest() HTTPMessage
}
