# HTTP Message Signatures RFC 9421 - Go Implementation

Zero-dependency implementation of RFC 9421 HTTP Message Signatures with RFC 8941 Structured Field Values parsing.

## Technology Stack

- **Go**: 1.21+ (uses generics and modern stdlib features)
- **External Dependencies**: `golang.org/x/crypto` only (for SHA-3, BLAKE2b in digest package)
- **No Runtime Dependencies**: All packages except `pkg/digest` are zero-dependency

## Project Structure

```
pkg/
├── sfv/          # RFC 8941 Structured Field Values parser
├── parser/       # RFC 9421 Signature-Input/Signature header parser
├── base/         # Signature base construction
├── signing/      # Cryptographic algorithms (RSA, ECDSA, Ed25519, HMAC)
└── digest/       # Content-Digest header (SHA-2, SHA-3, BLAKE2b)
```

### Package Descriptions

| Package | Purpose | Dependencies |
|---------|---------|--------------|
| `pkg/sfv` | RFC 8941 SFV parser with DoS-prevention limits | None |
| `pkg/parser` | Parse Signature-Input/Signature headers | `pkg/sfv` |
| `pkg/base` | Build signature base from HTTP messages | `pkg/sfv`, `pkg/parser` |
| `pkg/signing` | Sign/verify with RFC 9421 algorithms | `crypto/*` stdlib |
| `pkg/digest` | Content-Digest header support | `golang.org/x/crypto` |

## Commands

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test ./... -v

# Run tests with race detector
go test ./... -race

# Run specific package tests
go test ./pkg/sfv/...
go test ./pkg/parser/...
go test ./pkg/signing/...

# Run fuzz tests (example: 30 seconds)
go test ./pkg/sfv/... -fuzz=FuzzParseDictionary -fuzztime=30s
go test ./pkg/parser/... -fuzz=FuzzParseSignatures -fuzztime=30s

# Lint (requires golangci-lint)
golangci-lint run

# Format code
gofmt -w .
goimports -w .
```

## Code Style

- Follow Go standard conventions (gofmt, goimports)
- golangci-lint configuration in `.golangci.yml`:
  - Max function length: 80 lines / 50 statements
  - Max cyclomatic complexity: 15
  - Max nesting depth: 5
- Error strings: lowercase, no punctuation
- Variable naming: camelCase, acronyms uppercase (HTTP, URL, ID)
- Package comments required on all exported packages

## Testing Requirements

### Test Organization
- 1:1 mapping: `foo.go` → `foo_test.go`
- RFC examples in dedicated `rfc_examples_test.go` files
- Table-driven tests preferred

### Test Coverage
- All public APIs must have unit tests
- Edge cases and error paths required
- RFC 9421 Appendix B test vectors implemented

### Fuzz Testing
16 fuzz tests across packages for parser robustness:
- `pkg/sfv`: Dictionary, InnerList, Parameters, Primitives, BareItem
- `pkg/parser`: ParseSignatures, ComponentIdentifier validation
- `pkg/digest`: Content-Digest parsing

## Supported Algorithms

### Signature Algorithms (pkg/signing)
| ID | Type | Notes |
|----|------|-------|
| `rsa-pss-sha512` | RSA-PSS | Recommended |
| `rsa-v1_5-sha256` | RSA PKCS#1 v1.5 | Legacy only |
| `ecdsa-p256-sha256` | ECDSA | P-256 curve |
| `ecdsa-p384-sha384` | ECDSA | P-384 curve |
| `ed25519` | EdDSA | Deterministic |
| `hmac-sha256` | HMAC | Symmetric |

### Digest Algorithms (pkg/digest)
| ID | Family | Notes |
|----|--------|-------|
| `sha-256` | SHA-2 | Default |
| `sha-512` | SHA-2 | High security |
| `sha-512/256` | SHA-2 | Truncated |
| `sha3-256` | SHA-3 | Modern |
| `sha3-512` | SHA-3 | Modern |
| `blake2b-256` | BLAKE2b | Fast |
| `blake2b-512` | BLAKE2b | Fast |

Deprecated algorithms (MD5, SHA-1, CRC32, etc.) are explicitly rejected.

## Security Features

- **DoS Prevention**: Configurable parser limits via `sfv.Limits` struct
  - `DefaultLimits()`: Production defaults (64KB input, 128 dict members, etc.)
  - `NoLimits()`: For trusted input only
- **Constant-time HMAC**: Uses `crypto/subtle.ConstantTimeCompare`
- **Parameter Validation**: Strict RFC 9421 compliance
  - `bs` and `sf` mutually exclusive
  - `bs` and `key` mutually exclusive
  - `key` requires `sf`
  - `@query-param` requires `name` parameter
  - `@signature-params` rejected in covered components

## API Examples

### Parse Signature Headers
```go
sigs, err := parser.ParseSignatures(signatureInput, signature, sfv.DefaultLimits())
for label, entry := range sigs.Signatures {
    fmt.Printf("Label: %s, Algorithm: %s\n", label, *entry.SignatureParams.Algorithm)
}
```

### Build Signature Base
```go
msg := base.WrapRequest(httpRequest)
sigBase, err := base.Build(msg, coveredComponents, signatureParams)
```

### Sign and Verify
```go
alg, _ := signing.GetAlgorithm("rsa-pss-sha512")
sig, _ := alg.Sign(sigBase, privateKey)
err := alg.Verify(sigBase, sig, publicKey)
```

### SFV Parsing with Limits
```go
p := sfv.NewParser(headerValue, sfv.DefaultLimits())
dict, err := p.ParseDictionary()
```

## RFC Compliance

- RFC 9421: HTTP Message Signatures
- RFC 8941: Structured Field Values
- RFC 8017: RSA Cryptography (PKCS#1)
- RFC 6979: Deterministic ECDSA
- RFC 8032: Ed25519
- RFC 9530: Content-Digest Header
