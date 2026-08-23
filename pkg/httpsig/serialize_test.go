package httpsig

import (
	"bytes"
	"testing"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/parser"
	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/sfv"
)

func TestSerializeSignatureInputAndSignature(t *testing.T) {
	created := int64(123)
	expires := int64(456)
	nonce := "n1"
	alg := "hmac-sha256"
	keyID := "kid"
	tag := "tag1"

	components := []parser.ComponentIdentifier{
		{Name: "@method", Type: parser.ComponentDerived},
		{
			Name: "@query-param",
			Type: parser.ComponentDerived,
			Parameters: []parser.Parameter{
				{Key: "name", Value: parser.String{Value: "q"}},
				{Key: "req", Value: parser.Boolean{Value: true}},
				{Key: "id", Value: parser.Integer{Value: 1}},
				{Key: "tok", Value: parser.Token{Value: "t"}},
				{Key: "bs", Value: parser.ByteSequence{Value: []byte("x")}},
			},
		},
	}

	params := parser.SignatureParams{
		Created:   &created,
		Expires:   &expires,
		Nonce:     &nonce,
		Algorithm: &alg,
		KeyID:     &keyID,
		Tag:       &tag,
	}

	sigInput, err := serializeSignatureInput("sig1", components, params)
	if err != nil {
		t.Fatalf("serializeSignatureInput() error: %v", err)
	}

	p := sfv.NewParser(sigInput, sfv.DefaultLimits())
	dict, err := p.ParseDictionary()
	if err != nil {
		t.Fatalf("ParseDictionary() error: %v", err)
	}

	raw, ok := dict.Values["sig1"]
	if !ok {
		t.Fatalf("signature input missing label")
	}

	innerList, ok := raw.(sfv.InnerList)
	if !ok {
		t.Fatalf("signature input value is not inner list")
	}

	if len(innerList.Items) != 2 {
		t.Fatalf("inner list items = %d, want 2", len(innerList.Items))
	}
	if innerList.Items[0].Value != "@method" {
		t.Fatalf("inner list item[0] = %v, want @method", innerList.Items[0].Value)
	}
	if innerList.Items[1].Value != "@query-param" {
		t.Fatalf("inner list item[1] = %v, want @query-param", innerList.Items[1].Value)
	}

	componentParamMap := map[string]any{}
	for _, param := range innerList.Items[1].Parameters {
		componentParamMap[param.Key] = param.Value
	}
	if componentParamMap["name"] != "q" {
		t.Fatalf("component param name = %v, want %q", componentParamMap["name"], "q")
	}
	if componentParamMap["req"] != true {
		t.Fatalf("component param req = %v, want true", componentParamMap["req"])
	}
	if componentParamMap["id"] != int64(1) {
		t.Fatalf("component param id = %v, want 1", componentParamMap["id"])
	}
	tok, ok := componentParamMap["tok"].(sfv.Token)
	if !ok || tok.Value != "t" {
		t.Fatalf("component param tok = %v, want token t", componentParamMap["tok"])
	}
	bs, ok := componentParamMap["bs"].([]byte)
	if !ok || !bytes.Equal(bs, []byte("x")) {
		t.Fatalf("component param bs = %v, want %q", componentParamMap["bs"], []byte("x"))
	}

	paramMap := map[string]any{}
	for _, param := range innerList.Parameters {
		paramMap[param.Key] = param.Value
	}

	if paramMap["created"] != created {
		t.Fatalf("created param = %v, want %d", paramMap["created"], created)
	}
	if paramMap["expires"] != expires {
		t.Fatalf("expires param = %v, want %d", paramMap["expires"], expires)
	}
	if paramMap["nonce"] != nonce {
		t.Fatalf("nonce param = %v, want %s", paramMap["nonce"], nonce)
	}
	if paramMap["alg"] != alg {
		t.Fatalf("alg param = %v, want %s", paramMap["alg"], alg)
	}
	if paramMap["keyid"] != keyID {
		t.Fatalf("keyid param = %v, want %s", paramMap["keyid"], keyID)
	}
	if paramMap["tag"] != tag {
		t.Fatalf("tag param = %v, want %s", paramMap["tag"], tag)
	}

	sigHeader, err := serializeSignature("sig1", []byte("abc"))
	if err != nil {
		t.Fatalf("serializeSignature() error: %v", err)
	}

	p = sfv.NewParser(sigHeader, sfv.DefaultLimits())
	dict, err = p.ParseDictionary()
	if err != nil {
		t.Fatalf("ParseDictionary() signature error: %v", err)
	}

	raw, ok = dict.Values["sig1"]
	if !ok {
		t.Fatalf("signature header missing label")
	}
	item, ok := raw.(sfv.Item)
	if !ok {
		t.Fatalf("signature header value is not item")
	}
	sigBytes, ok := item.Value.([]byte)
	if !ok {
		t.Fatalf("signature header item is not byte sequence")
	}
	if !bytes.Equal(sigBytes, []byte("abc")) {
		t.Fatalf("signature bytes = %q, want %q", sigBytes, []byte("abc"))
	}
}

func TestSerializeSignature_EmptyLabel(t *testing.T) {
	if _, err := serializeSignature("", []byte("abc")); err == nil {
		t.Fatal("serializeSignature() expected error for empty label")
	}
	if _, err := serializeSignatureInput("", nil, parser.SignatureParams{}); err == nil {
		t.Fatal("serializeSignatureInput() expected error for empty label")
	}
}

func TestComponentParamsToSFV_Empty(t *testing.T) {
	if got := componentParamsToSFV(nil); got != nil {
		t.Fatalf("componentParamsToSFV(nil) = %v, want nil", got)
	}
}
