package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/igor-pavlenko/http-message-signatures-rfc9421-go/pkg/signing"
)

// Shared key material used by every scenario, loaded from the RFC 9421
// Appendix B.1 example keys already checked into ../tests. Using the RFC's
// own keys (rather than freshly generated ones) means the cross-check output
// can be compared directly against the RFC's worked examples.
//
// Note: the RFC's dedicated RSA-PSS key (test-key-rsa-pss-*.pem) is PKCS#8
// with an RSA-PSS-specific OID that Go's crypto/x509 cannot parse (see
// ../tests/rfc_examples_test.go). Like the rest of this repo's test suite,
// rsa-pss-sha512 scenarios reuse the plain RSA key (test-key-rsa-*.pem) —
// same key, different padding scheme.
var (
	rsaPriv    *rsa.PrivateKey
	rsaPub     *rsa.PublicKey
	ecP256Priv *ecdsa.PrivateKey
	ecP256Pub  *ecdsa.PublicKey
	ed25519Pub ed25519.PublicKey
	ed25519Sec ed25519.PrivateKey
	hmacKey    []byte // RFC 9421 Appendix B.1.5 example shared secret
)

// testDataDir resolves ../tests relative to this source file, so the
// program works regardless of the caller's working directory.
func testDataDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "tests")
}

func loadKeys() error {
	dir := testDataDir()

	priv, err := loadPrivateKey(dir, "test-key-rsa-private.pem")
	if err != nil {
		return err
	}
	var ok bool
	rsaPriv, ok = priv.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("test-key-rsa-private.pem: expected *rsa.PrivateKey, got %T", priv)
	}
	rsaPub = &rsaPriv.PublicKey

	privEC, err := loadPrivateKey(dir, "test-key-ecc-p256-private.pem")
	if err != nil {
		return err
	}
	ecP256Priv, ok = privEC.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("test-key-ecc-p256-private.pem: expected *ecdsa.PrivateKey, got %T", privEC)
	}
	ecP256Pub = &ecP256Priv.PublicKey

	privEd, err := loadPrivateKey(dir, "test-key-ed25519-private.pem")
	if err != nil {
		return err
	}
	ed25519Sec, ok = privEd.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("test-key-ed25519-private.pem: expected ed25519.PrivateKey, got %T", privEd)
	}
	ed25519Pub = ed25519Sec.Public().(ed25519.PublicKey)

	secretB64, err := os.ReadFile(filepath.Join(dir, "test-shared-secret")) //nolint:gosec // test assets from known directory
	if err != nil {
		return err
	}
	hmacKey, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(secretB64)))
	if err != nil {
		return fmt.Errorf("test-shared-secret: %w", err)
	}

	return nil
}

func loadPrivateKey(dir, name string) (any, error) {
	data, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // test assets from known directory
	if err != nil {
		return nil, err
	}
	key, err := signing.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return key, nil
}

// oursSignKey returns the private key/secret in the shape pkg/signing expects.
func oursSignKey(algID string) any {
	switch algID {
	case "rsa-pss-sha512", "rsa-v1_5-sha256":
		return rsaPriv
	case "ecdsa-p256-sha256":
		return ecP256Priv
	case "ed25519":
		return ed25519Sec
	case "hmac-sha256":
		return hmacKey
	default:
		panic("unknown algorithm: " + algID)
	}
}

// oursVerifyKey returns the public key/secret in the shape pkg/signing expects.
func oursVerifyKey(algID string) any {
	switch algID {
	case "rsa-pss-sha512", "rsa-v1_5-sha256":
		return rsaPub
	case "ecdsa-p256-sha256":
		return ecP256Pub
	case "ed25519":
		return ed25519Pub
	case "hmac-sha256":
		return hmacKey
	default:
		panic("unknown algorithm: " + algID)
	}
}

// keyIDFor returns the RFC 9421 Appendix B.1 keyid conventionally
// associated with each algorithm's key material.
func keyIDFor(algID string) string {
	switch algID {
	case "rsa-pss-sha512":
		return "test-key-rsa-pss"
	case "rsa-v1_5-sha256":
		return "test-key-rsa"
	case "ecdsa-p256-sha256":
		return "test-key-ecc-p256"
	case "ed25519":
		return "test-key-ed25519"
	case "hmac-sha256":
		return "test-shared-secret"
	default:
		panic("unknown algorithm: " + algID)
	}
}
