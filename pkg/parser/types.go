// Package parser implements RFC 9421 HTTP Message Signatures parsing.
// This parser extracts signature metadata from Signature-Input and Signature headers
// without performing cryptographic operations.
package parser

// ParsedSignatures represents all parsed signatures from an HTTP message.
// Per Contract CT-001: Must contain at least one signature entry.
type ParsedSignatures struct {
	Signatures map[string]SignatureEntry
}

// SignatureEntry represents a single HTTP message signature with metadata.
// Per data-model.md: Complete signature entry for one label.
type SignatureEntry struct {
	Label             string                // Signature label (dictionary key)
	CoveredComponents []ComponentIdentifier // Ordered list of covered components
	SignatureParams   SignatureParams       // Signature metadata parameters
	SignatureValue    []byte                // Raw signature bytes (base64-decoded)
}

// ComponentType represents the type of a covered component.
//
// Per RFC 9421, components can be either HTTP fields (Section 2.1) or
// derived components (Section 2.2).
//
// # Component Requirements
//
// Neither derived components nor HTTP fields are universally required by RFC 9421.
// The specification is a flexible framework that allows applications to sign
// only the components meaningful to their use case.
//
// Per RFC 9421 Section 1.4, applications MUST define their own requirements:
//   - Which component identifiers are expected and required
//   - Which signature parameters must be present
//   - Allowable signature algorithms
//   - Key retrieval mechanisms
//
// # Derived Components (ComponentDerived)
//
// All derived components defined in RFC 9421 Section 2.2 are OPTIONAL at the
// specification level. Applications may require specific derived components
// based on their security needs.
//
// Available derived components:
//   - @method, @target-uri, @authority, @scheme (request only)
//   - @request-target, @path, @query, @query-param (request only)
//   - @status (response only)
//
// Note: @signature-params is auto-generated and MUST NOT appear in covered components.
// The 'req' parameter (Section 2.4) can be applied to any component to derive
// values from the request when signing a response.
//
// # HTTP Fields (ComponentField)
//
// HTTP field components are OPTIONAL at the specification level. Any HTTP field
// can be included in the signature. Common fields include:
//   - date, content-type, content-digest, authorization, etc.
//
// Applications should require fields that protect:
//   - Authentication credentials (Authorization)
//   - Message content integrity (Content-Digest)
//   - Temporal validity (Date, created parameter)
//
// # Security Considerations
//
// While no components are universally required, RFC 9421 Section 7.2.1 warns
// against insufficient coverage:
//   - Empty component lists are allowed but discouraged (see B.2.1)
//   - Applications must ensure adequate coverage for their security requirements
//   - See Section 7.2.3 for guidance on choosing components
//
// # Example Application Requirements
//
// An authorization API might require:
//   - Authorization field (protect credentials)
//   - Content-Digest field (protect message body)
//   - created parameter (prevent replay attacks)
//   - @method, @path (protect request target)
//
// A response signature might require:
//   - @status (protect status code)
//   - Content-Type, Content-Digest (protect response content)
type ComponentType int

const (
	// ComponentField represents an HTTP field component (e.g., "date", "content-type").
	//
	// HTTP fields are OPTIONAL per RFC 9421. Applications define which fields
	// are required based on their security requirements.
	//
	// Any HTTP field can be signed. The field value is canonicalized per
	// RFC 9421 Section 2.1 before inclusion in the signature base.
	ComponentField ComponentType = iota

	// ComponentDerived represents a derived component (e.g., "@method", "@path", "@status").
	//
	// Derived components are OPTIONAL per RFC 9421. Applications define which
	// derived components are required based on their security requirements.
	//
	// All derived component names start with "@" to distinguish them from
	// HTTP field names. Only components from the RFC 9421 Section 2.2 registry
	// are valid (see validator.go for the complete whitelist).
	ComponentDerived
)

// String returns a string representation of the ComponentType.
func (ct ComponentType) String() string {
	switch ct {
	case ComponentField:
		return "field"
	case ComponentDerived:
		return "derived"
	default:
		return "unknown"
	}
}

// IsDerived returns true if this is a derived component.
func (c ComponentIdentifier) IsDerived() bool {
	return c.Type == ComponentDerived
}

// IsField returns true if this is an HTTP field component.
func (c ComponentIdentifier) IsField() bool {
	return c.Type == ComponentField
}

// ComponentIdentifier identifies a covered component with optional parameters.
// Per FR-003: Name starting with "@" indicates derived component.
type ComponentIdentifier struct {
	Name       string        // Component name (e.g., "date", "@method")
	Type       ComponentType // Component type (field or derived)
	Parameters []Parameter   // Ordered list of component parameters
}

// SignatureParams contains metadata parameters for a signature.
//
// Per RFC 9421 Section 2.3, signature parameters provide metadata about
// the signature's generation and verification. The @signature-params
// component is REQUIRED as the last line of the signature base but
// MUST NOT appear in the covered components list.
//
// # Parameter Requirements
//
// ALL signature parameters are OPTIONAL at the RFC 9421 specification level.
// Applications MUST define which parameters are required per Section 1.4.
//
// Per RFC 9421 Section 2.3:
//
//   - created: RECOMMENDED but not required
//     Type: Integer (UNIX timestamp, no sub-second precision)
//     Purpose: Signature creation time
//     Security: Helps prevent replay attacks when combined with expires
//
//   - expires: OPTIONAL
//     Type: Integer (UNIX timestamp, no sub-second precision)
//     Purpose: Signature expiration time
//     Security: Limits signature validity window
//
//   - nonce: OPTIONAL
//     Type: String
//     Purpose: Random unique value for this signature
//     Security: Prevents replay attacks, especially for stateless systems
//
//   - alg: OPTIONAL (but RECOMMENDED for production)
//     Type: String
//     Purpose: Signature algorithm identifier from HTTP Signature Algorithms registry
//     Security: Critical for algorithm verification, though can be derived from key
//     Note: Official RFC 9421 test cases (Appendix B.2) omit this parameter
//
//   - keyid: OPTIONAL
//     Type: String
//     Purpose: Identifier for key material
//     Security: Enables key lookup, though keys can be known by other means
//
//   - tag: OPTIONAL
//     Type: String
//     Purpose: Application-specific signature tag
//     Use case: Distinguish signatures for different applications/protocols
//
// # Application Requirements
//
// Per RFC 9421 Section 1.4, applications MUST specify:
//   - Which parameters are required (e.g., mandate 'created' for replay protection)
//   - How to retrieve keys (e.g., via 'keyid' or pre-registration)
//   - How to determine appropriate algorithms (e.g., via 'alg' or key derivation)
//
// # Example Application Policies
//
// Authorization API might require:
//   - created: REQUIRED (prevent replay)
//   - keyid: REQUIRED (key lookup)
//   - alg: REQUIRED (explicit algorithm verification)
//   - expires: OPTIONAL (time-limited tokens)
//
// Webhook signatures might require:
//   - created: REQUIRED
//   - nonce: REQUIRED (stateless replay protection)
//   - keyid: OPTIONAL (single known key)
//
// # Implementation Note
//
// Our parser accepts signatures with ANY combination of these parameters,
// including signatures with NO parameters (as demonstrated in RFC 9421 B.2.1).
// Applications should implement their own validation logic to enforce
// required parameters.
type SignatureParams struct {
	// Created is the UNIX timestamp when the signature was created.
	// RECOMMENDED per RFC 9421 Section 2.3, but not required.
	// Nil if not present in the signature.
	Created *int64

	// Expires is the UNIX timestamp when the signature expires.
	// OPTIONAL per RFC 9421 Section 2.3.
	// Nil if not present in the signature.
	Expires *int64

	// Nonce is a random unique value for replay protection.
	// OPTIONAL per RFC 9421 Section 2.3.
	// Nil if not present in the signature.
	Nonce *string

	// Algorithm is the signature algorithm identifier.
	// OPTIONAL per RFC 9421 Section 2.3 (though RECOMMENDED for production).
	// Nil if not present in the signature.
	// Note: RFC 9421 Appendix B.2 test cases do not include this parameter.
	Algorithm *string

	// KeyID is the identifier for the key material.
	// OPTIONAL per RFC 9421 Section 2.3.
	// Nil if not present in the signature.
	KeyID *string

	// Tag is an application-specific tag for the signature.
	// OPTIONAL per RFC 9421 Section 2.3.
	// Nil if not present in the signature.
	Tag *string
}

// Parameter represents a key-value pair for component parameters.
// Per data-model.md: Component parameters like sf, key, bs, tr, req, name.
type Parameter struct {
	Key   string   // Parameter key (e.g., "sf", "key", "req")
	Value BareItem // Parameter value (bare item from RFC 8941)
}

// BareItem represents an RFC 8941 Structured Field Value bare item.
// This is a union type that can hold different primitive types.
type BareItem interface {
	isBareItem()
}

// Boolean represents a boolean bare item (?0 or ?1).
type Boolean struct {
	Value bool
}

func (Boolean) isBareItem() {}

// Integer represents an integer bare item (max 15 digits per RFC 8941).
type Integer struct {
	Value int64
}

func (Integer) isBareItem() {}

// String represents a string bare item (quoted, with escape sequences).
type String struct {
	Value string
}

func (String) isBareItem() {}

// Token represents a token bare item (unquoted identifier).
type Token struct {
	Value string
}

func (Token) isBareItem() {}

// ByteSequence represents a byte sequence bare item (:base64:).
type ByteSequence struct {
	Value []byte
}

func (ByteSequence) isBareItem() {}
