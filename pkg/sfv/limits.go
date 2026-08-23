package sfv

// Limits defines configurable size limits for SFV parsing to prevent DoS attacks.
// All limits are optional - zero value means no limit (unlimited).
type Limits struct {
	// MaxInputLength is the maximum total input string length.
	// Default: 65536 (64KB)
	MaxInputLength int

	// MaxStringLength is the maximum length of a single string value.
	// Default: 8192 (8KB)
	MaxStringLength int

	// MaxByteSequenceLength is the maximum decoded length of a byte sequence.
	// Default: 16384 (16KB) - accommodates typical signature sizes
	MaxByteSequenceLength int

	// MaxDictionaryMembers is the maximum number of dictionary entries.
	// Default: 128 - reasonable for signature headers
	MaxDictionaryMembers int

	// MaxInnerListMembers is the maximum number of items in an inner list.
	// Default: 128 - reasonable for covered components
	MaxInnerListMembers int

	// MaxParameters is the maximum number of parameters per item/inner list.
	// Default: 64
	MaxParameters int

	// MaxTokenLength is the maximum length of a token (key/identifier).
	// Default: 256
	MaxTokenLength int
}

// DefaultLimits returns sensible default limits for production use.
// These limits are generous enough for any RFC 9421 use case while
// preventing memory exhaustion attacks from malicious input.
func DefaultLimits() Limits {
	return Limits{
		MaxInputLength:        65536, // 64KB - typical max header size
		MaxStringLength:       8192,  // 8KB - generous for any use case
		MaxByteSequenceLength: 16384, // 16KB - fits RSA-4096 signatures
		MaxDictionaryMembers:  128,   // far more than typical signature count
		MaxInnerListMembers:   128,   // far more than typical covered components
		MaxParameters:         64,    // RFC 9421 defines ~6 standard params
		MaxTokenLength:        256,   // generous for header names/labels
	}
}

// NoLimits returns a Limits struct with all limits disabled (zero values).
// Use with caution - only for trusted input where DoS is not a concern.
func NoLimits() Limits {
	return Limits{}
}
