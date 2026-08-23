package base

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/sfv"
)

// normalizeLineFolding replaces obsolete line folding with single space.
// RFC 9421 Section 2.1: obs-fold is CRLF or LF followed by one or more whitespace characters.
// This function replaces each sequence of (CRLF|LF) + whitespace with a single space.
//
// Returns an error if bare CR, LF, or CRLF characters are found that are not part of obs-fold.
// Per RFC 7230 Section 3.2, properly formed HTTP header values must not contain bare newlines.
// Bare newlines in header values could allow signature base injection attacks.
func normalizeLineFolding(s string) (string, error) {
	// Fast path: no folding characters present (99% of cases)
	if !strings.ContainsAny(s, "\r\n") {
		return s, nil
	}

	// Slow path: build normalized string
	var result strings.Builder
	result.Grow(len(s))

	i := 0
	for i < len(s) {
		if s[i] != '\r' && s[i] != '\n' {
			result.WriteByte(s[i])
			i++
			continue
		}

		next, err := skipObsFold(s, i)
		if err != nil {
			return "", err
		}
		result.WriteByte(' ')
		i = next
	}

	return result.String(), nil
}

// skipObsFold consumes a CRLF or LF newline at s[i] together with any
// following whitespace, per the obs-fold grammar in RFC 9421 Section 2.1.
// It returns the index immediately after the fold. A newline not followed
// by whitespace is rejected: bare newlines in header values could allow
// signature base injection attacks.
func skipObsFold(s string, i int) (int, error) {
	newlineLen := 1
	kind := "LF"
	if s[i] == '\r' {
		kind = "CRLF"
		if i+1 >= len(s) || s[i+1] != '\n' {
			return 0, fmt.Errorf("invalid header value: bare CR not part of obs-fold")
		}
		newlineLen = 2
	}

	j := i + newlineLen
	if j >= len(s) || (s[j] != ' ' && s[j] != '\t') {
		return 0, fmt.Errorf("invalid header value: bare %s not part of obs-fold", kind)
	}

	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	return j, nil
}

// extractComponentValue extracts the canonicalized value for a component identifier.
//
// RFC 9421 Section 2: Component values are extracted differently based on type:
// - HTTP fields (Section 2.1): Extracted from headers/trailers with comma-join for multiple values
// - Derived components (Section 2.2): Computed from HTTP message metadata (@method, @path, etc.)
//
// RFC 9421 Section 2.4: The 'req' parameter allows accessing request components from a response signature.
//
// Returns an error if:
// - The component is not found (missing header, invalid derived component for message type)
// - The component type is unknown or unsupported
// - A derived component is not valid for the message type (e.g., @status on request)
// - The 'req' parameter is used but no related request is available
func extractComponentValue(msg HTTPMessage, comp parser.ComponentIdentifier) (string, error) {
	// 'req' parameter allows accessing request components from a response signature
	if hasReqParameter(comp) {
		return extractFromRelatedRequest(msg, comp)
	}

	switch comp.Type {
	case parser.ComponentField:
		return extractHTTPFieldValue(msg, comp)
	case parser.ComponentDerived:
		return extractDerivedComponentValue(msg, comp)
	default:
		return "", fmt.Errorf("unknown component type: %v", comp.Type)
	}
}

// hasReqParameter reports whether the component identifier carries a
// truthy 'req' parameter, per RFC 9421 Section 2.4.
func hasReqParameter(comp parser.ComponentIdentifier) bool {
	for _, param := range comp.Parameters {
		if param.Key != "req" {
			continue
		}
		boolVal, ok := param.Value.(parser.Boolean)
		return ok && boolVal.Value
	}
	return false
}

// extractFromRelatedRequest resolves a component carrying a 'req' parameter
// against the response's related request, per RFC 9421 Section 2.4.
func extractFromRelatedRequest(msg HTTPMessage, comp parser.ComponentIdentifier) (string, error) {
	if !msg.IsResponse() {
		return "", fmt.Errorf("'req' parameter is only valid for response signatures")
	}

	relatedReq := msg.RelatedRequest()
	if relatedReq == nil {
		return "", fmt.Errorf("'req' parameter specified but no related request available")
	}

	// Remove 'req' parameter before extracting from request
	compForReq := parser.ComponentIdentifier{
		Name:       comp.Name,
		Type:       comp.Type,
		Parameters: make([]parser.Parameter, 0, len(comp.Parameters)-1),
	}
	for _, param := range comp.Parameters {
		if param.Key != "req" {
			compForReq.Parameters = append(compForReq.Parameters, param)
		}
	}

	return extractComponentValue(relatedReq, compForReq)
}

// extractHTTPFieldValue extracts HTTP field values per RFC 9421 Section 2.1.
//
// RFC 9421 Section 2.1 Canonicalization Algorithm:
// 1. Create ordered list of field values in the order they occur
// 2. Strip leading and trailing whitespace from each value
// 3. Remove obsolete line folding (replace with single space)
// 4. Concatenate values with ", " (comma + space)
//
// Component Parameters (RFC 9421 Section 2.1):
//   - tr: Extract from trailers instead of headers
//   - sf: Serialize as RFC 8941 Structured Field (FR-011)
//   - bs: Encode as base64 byte sequence wrapped in :value: (FR-012)
//   - key: Extract specific dictionary member (FR-013)
func extractHTTPFieldValue(msg HTTPMessage, comp parser.ComponentIdentifier) (string, error) {
	params := parseHTTPFieldParams(comp.Parameters)

	// RFC 9421 Section 2.1.1: Validate parameter combinations (FR-017, FR-018)
	if params.useSF && params.useBS {
		return "", fmt.Errorf("component %q: 'sf' and 'bs' parameters are mutually exclusive (RFC 9421 Section 2.1.1)", comp.Name)
	}
	if params.keyName != "" && !params.useSF {
		return "", fmt.Errorf("component %q: 'key' parameter requires 'sf' parameter for structured field dictionary (RFC 9421 Section 2.1.2)", comp.Name)
	}

	// Step 1: Extract field values in order
	var values []string
	if params.isTrailer {
		values = msg.TrailerValues(comp.Name)
	} else {
		values = msg.HeaderValues(comp.Name)
	}

	// RFC 9421: Missing header is an error
	if len(values) == 0 {
		fieldType := "header"
		if params.isTrailer {
			fieldType = "trailer"
		}
		return "", fmt.Errorf("%s field %q not found", fieldType, comp.Name)
	}

	rawValue, err := canonicalizeFieldValues(values, comp.Name)
	if err != nil {
		return "", err
	}

	// Step 5: Apply parameter-specific processing

	// SF Parameter: Serialize as RFC 8941 Structured Field (FR-011)
	// This must be processed BEFORE the 'key' parameter if both are present
	if params.useSF {
		return serializeStructuredFieldValue(rawValue, comp.Name, params.keyName)
	}

	// BS Parameter: Base64-encode as byte sequence (FR-012)
	// RFC 9421 Section 2.1.3: Byte sequences are wrapped in colons :base64:
	if params.useBS {
		encoded := base64.StdEncoding.EncodeToString([]byte(rawValue))
		return ":" + encoded + ":", nil
	}

	// Default: Return raw canonicalized value (no special processing)
	return rawValue, nil
}

type httpFieldParams struct {
	isTrailer bool
	useSF     bool
	useBS     bool
	keyName   string
}

func parseHTTPFieldParams(params []parser.Parameter) httpFieldParams {
	result := httpFieldParams{}
	for _, param := range params {
		switch param.Key {
		case "tr":
			if boolVal, ok := param.Value.(parser.Boolean); ok {
				result.isTrailer = boolVal.Value
			}
		case "sf":
			if boolVal, ok := param.Value.(parser.Boolean); ok {
				result.useSF = boolVal.Value
			}
		case "bs":
			if boolVal, ok := param.Value.(parser.Boolean); ok {
				result.useBS = boolVal.Value
			}
		case "key":
			if strVal, ok := param.Value.(parser.String); ok {
				result.keyName = strVal.Value
			}
		}
	}
	return result
}

func canonicalizeFieldValues(values []string, compName string) (string, error) {
	normalizedValues := make([]string, len(values))
	for i, v := range values {
		var err error
		if v, err = normalizeLineFolding(v); err != nil {
			return "", fmt.Errorf("component %q: %w", compName, err)
		}
		normalizedValues[i] = strings.TrimSpace(v)
	}
	return strings.Join(normalizedValues, ", "), nil
}

func serializeStructuredFieldValue(rawValue, compName, keyName string) (string, error) {
	sfvParser := sfv.NewParser(rawValue, sfv.DefaultLimits())
	if keyName != "" {
		dict, err := sfvParser.ParseDictionary()
		if err != nil {
			return "", fmt.Errorf("component %q: failed to parse as structured field dictionary: %w", compName, err)
		}

		memberValue, exists := dict.Values[keyName]
		if !exists {
			return "", fmt.Errorf("component %q: dictionary member %q not found", compName, keyName)
		}

		return serializeStructuredFieldMember(compName, keyName, memberValue)
	}

	dict, dictErr := sfvParser.ParseDictionary()
	if dictErr == nil {
		serialized, err := sfv.SerializeDictionary(dict)
		if err != nil {
			return "", fmt.Errorf("component %q: failed to serialize structured field dictionary: %w", compName, err)
		}
		return serialized, nil
	}

	sfvParser = sfv.NewParser(rawValue, sfv.DefaultLimits())
	list, listErr := sfvParser.ParseList()
	if listErr == nil {
		serialized, err := sfv.SerializeList(list)
		if err != nil {
			return "", fmt.Errorf("component %q: failed to serialize structured field list: %w", compName, err)
		}
		return serialized, nil
	}

	sfvParser = sfv.NewParser(rawValue, sfv.DefaultLimits())
	item, itemErr := sfvParser.ParseItem()
	if itemErr == nil {
		serialized, err := sfv.SerializeItem(*item)
		if err != nil {
			return "", fmt.Errorf("component %q: failed to serialize structured field item: %w", compName, err)
		}
		return serialized, nil
	}

	//nolint:errorlint // Only one error can be wrapped per fmt.Errorf; wrapping itemErr as it's the last attempt
	return "", fmt.Errorf("component %q: failed to parse as structured field (dict: %v, list: %v, item: %w)", compName, dictErr, listErr, itemErr)
}

func serializeStructuredFieldMember(compName, keyName string, memberValue any) (string, error) {
	switch v := memberValue.(type) {
	case sfv.Item:
		serialized, err := sfv.SerializeItem(v)
		if err != nil {
			return "", fmt.Errorf("component %q: failed to serialize dictionary member %q: %w", compName, keyName, err)
		}
		return serialized, nil
	case sfv.InnerList:
		serialized, err := sfv.SerializeInnerList(v)
		if err != nil {
			return "", fmt.Errorf("component %q: failed to serialize dictionary member %q: %w", compName, keyName, err)
		}
		return serialized, nil
	default:
		return "", fmt.Errorf("component %q: invalid dictionary member type for %q: %T", compName, keyName, memberValue)
	}
}

// getRequestURL validates msg is a request and returns its URL.
// Returns an error with the component name if msg is not a request or URL() fails.
func getRequestURL(msg HTTPMessage, compName string) (*url.URL, error) {
	if !msg.IsRequest() {
		return nil, fmt.Errorf("%s is only valid for requests", compName)
	}
	u, err := msg.URL()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", compName, err)
	}
	return u, nil
}

// extractDerivedComponentValue extracts derived components per RFC 9421 Section 2.2.
//
// RFC 9421 Section 2.2: Derived components start with @ and are computed from
// HTTP message metadata rather than being directly present in headers.
//
// Request-only derived components:
// - @method: HTTP method (GET, POST, etc.)
// - @target-uri: Complete request URI
// - @authority: Host and port from request URI
// - @scheme: URI scheme (http, https)
// - @request-target: Path and query from request URI
// - @path: Path component only
// - @query: Query string with leading ?
// - @query-param: Single query parameter value (requires name parameter)
//
// Response-only derived components:
// - @status: HTTP status code (200, 404, etc.)
//
// Both request and response:
// - None currently defined in RFC 9421
func extractDerivedComponentValue(msg HTTPMessage, comp parser.ComponentIdentifier) (string, error) {
	switch comp.Name {
	case "@method":
		return extractMethod(msg)
	case "@target-uri":
		return extractTargetURI(msg)
	case "@authority":
		return extractAuthority(msg)
	case "@scheme":
		return extractScheme(msg)
	case "@request-target":
		return extractRequestTarget(msg)
	case "@path":
		return extractPath(msg)
	case "@query":
		return extractQuery(msg)
	case "@query-param":
		return extractQueryParam(msg, comp)
	case "@status":
		return extractStatus(msg)
	default:
		return "", fmt.Errorf("unknown derived component: %s", comp.Name)
	}
}

func extractMethod(msg HTTPMessage) (string, error) {
	if !msg.IsRequest() {
		return "", fmt.Errorf("@method is only valid for requests")
	}
	method, err := msg.Method()
	if err != nil {
		return "", fmt.Errorf("@method: %w", err)
	}
	return method, nil
}

func extractTargetURI(msg HTTPMessage) (string, error) {
	u, err := getRequestURL(msg, "@target-uri")
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func extractAuthority(msg HTTPMessage) (string, error) {
	u, err := getRequestURL(msg, "@authority")
	if err != nil {
		return "", err
	}
	return u.Host, nil
}

func extractScheme(msg HTTPMessage) (string, error) {
	u, err := getRequestURL(msg, "@scheme")
	if err != nil {
		return "", err
	}
	return u.Scheme, nil
}

func extractRequestTarget(msg HTTPMessage) (string, error) {
	u, err := getRequestURL(msg, "@request-target")
	if err != nil {
		return "", err
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		return path + "?" + u.RawQuery, nil
	}
	return path, nil
}

func extractPath(msg HTTPMessage) (string, error) {
	u, err := getRequestURL(msg, "@path")
	if err != nil {
		return "", err
	}
	path := u.EscapedPath()
	// RFC 9421 Section 2.2.6: an empty path string is normalized as a single slash (/) character
	if path == "" {
		return "/", nil
	}
	return path, nil
}

func extractQuery(msg HTTPMessage) (string, error) {
	u, err := getRequestURL(msg, "@query")
	if err != nil {
		return "", err
	}
	if u.RawQuery == "" {
		return "?", nil
	}
	return "?" + u.RawQuery, nil
}

func extractQueryParam(msg HTTPMessage, comp parser.ComponentIdentifier) (string, error) {
	// RFC 9421 Section 2.2.8: Requires 'name' parameter
	paramName := queryParamName(comp)
	if paramName == "" {
		return "", fmt.Errorf("@query-param requires 'name' parameter")
	}

	u, err := getRequestURL(msg, "@query-param")
	if err != nil {
		return "", err
	}
	values := u.Query()[paramName]
	if len(values) == 0 {
		return "", fmt.Errorf("query parameter %q not found", paramName)
	}
	// RFC 9421: Only returns first value if multiple exist
	return values[0], nil
}

// queryParamName extracts the required 'name' parameter for @query-param,
// per RFC 9421 Section 2.2.8.
func queryParamName(comp parser.ComponentIdentifier) string {
	for _, param := range comp.Parameters {
		if param.Key != "name" {
			continue
		}
		if strVal, ok := param.Value.(parser.String); ok {
			return strVal.Value
		}
	}
	return ""
}

func extractStatus(msg HTTPMessage) (string, error) {
	if !msg.IsResponse() {
		return "", fmt.Errorf("@status is only valid for responses")
	}
	statusCode, err := msg.StatusCode()
	if err != nil {
		return "", fmt.Errorf("@status: %w", err)
	}
	return strconv.Itoa(statusCode), nil
}
