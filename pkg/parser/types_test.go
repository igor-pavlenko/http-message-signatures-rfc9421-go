package parser

import (
	"testing"
)

// T038: Test type validation and field presence

func TestParsedSignatures_NonEmpty(t *testing.T) {
	// VR-001: Signatures map must contain at least one entry
	ps := &ParsedSignatures{
		Signatures: make(map[string]SignatureEntry),
	}

	// VR-001 validation happens during parsing, not at struct creation
	// This test validates the structure can hold signatures

	// Add a signature
	ps.Signatures["sig1"] = SignatureEntry{
		Label: "sig1",
	}

	if len(ps.Signatures) != 1 {
		t.Errorf("expected 1 signature, got %d", len(ps.Signatures))
	}
}

func TestSignatureEntry_RequiredFields(t *testing.T) {
	alg := "rsa-pss-sha512"
	entry := SignatureEntry{
		Label: "sig1",
		CoveredComponents: []ComponentIdentifier{
			{Name: "@method"},
		},
		SignatureParams: SignatureParams{
			Algorithm: &alg,
		},
		SignatureValue: []byte("signature bytes"),
	}

	if entry.Label != "sig1" {
		t.Errorf("Label = %q, want %q", entry.Label, "sig1")
	}

	if len(entry.CoveredComponents) == 0 {
		t.Error("CoveredComponents should not be empty")
	}

	// Algorithm is optional per RFC 9421 Section 2.3
	// This test just checks that the field exists, not that it's populated

	if len(entry.SignatureValue) == 0 {
		t.Error("SignatureValue should not be empty")
	}
}

func TestComponentIdentifier_NameAndParameters(t *testing.T) {
	comp := ComponentIdentifier{
		Name: "content-digest",
		Parameters: []Parameter{
			{Key: "sf", Value: Boolean{Value: true}},
		},
	}

	if comp.Name != "content-digest" {
		t.Errorf("Name = %q, want %q", comp.Name, "content-digest")
	}

	if len(comp.Parameters) != 1 {
		t.Errorf("expected 1 parameter, got %d", len(comp.Parameters))
	}

	param := comp.Parameters[0]
	if param.Key != "sf" {
		t.Errorf("parameter key = %q, want %q", param.Key, "sf")
	}

	boolVal, ok := param.Value.(Boolean)
	if !ok {
		t.Errorf("parameter value type = %T, want Boolean", param.Value)
	}
	if !boolVal.Value {
		t.Error("expected boolean true")
	}
}

func TestSignatureParams_AllFields(t *testing.T) {
	created := int64(1618884473)
	expires := int64(1618884773)
	nonce := "random123"
	alg := "rsa-pss-sha512"
	keyid := "key-1"
	tag := "app-tag"

	params := SignatureParams{
		Created:   &created,
		Expires:   &expires,
		Nonce:     &nonce,
		Algorithm: &alg,
		KeyID:     &keyid,
		Tag:       &tag,
	}

	if *params.Created != created {
		t.Errorf("Created = %d, want %d", *params.Created, created)
	}

	if *params.Expires != expires {
		t.Errorf("Expires = %d, want %d", *params.Expires, expires)
	}

	if *params.Nonce != nonce {
		t.Errorf("Nonce = %q, want %q", *params.Nonce, nonce)
	}

	if params.Algorithm == nil || *params.Algorithm != "rsa-pss-sha512" {
		t.Errorf("Algorithm = %v, want %q", params.Algorithm, "rsa-pss-sha512")
	}

	if *params.KeyID != keyid {
		t.Errorf("KeyID = %q, want %q", *params.KeyID, keyid)
	}

	if *params.Tag != tag {
		t.Errorf("Tag = %q, want %q", *params.Tag, tag)
	}
}

func TestBareItem_Types(t *testing.T) {
	tests := []struct {
		name string
		item BareItem
	}{
		{"Boolean", Boolean{Value: true}},
		{"Integer", Integer{Value: 42}},
		{"String", String{Value: "hello"}},
		{"Token", Token{Value: "example"}},
		{"ByteSequence", ByteSequence{Value: []byte("data")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify interface implementation (compile-time check)
			var _ = tt.item

			// Type assertions work
			switch v := tt.item.(type) {
			case Boolean:
				if tt.name != "Boolean" {
					t.Errorf("unexpected type Boolean for %s", tt.name)
				}
				_ = v.Value
			case Integer:
				if tt.name != "Integer" {
					t.Errorf("unexpected type Integer for %s", tt.name)
				}
				_ = v.Value
			case String:
				if tt.name != "String" {
					t.Errorf("unexpected type String for %s", tt.name)
				}
				_ = v.Value
			case Token:
				if tt.name != "Token" {
					t.Errorf("unexpected type Token for %s", tt.name)
				}
				_ = v.Value
			case ByteSequence:
				if tt.name != "ByteSequence" {
					t.Errorf("unexpected type ByteSequence for %s", tt.name)
				}
				_ = v.Value
			}
		})
	}
}
