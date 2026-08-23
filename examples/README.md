# Cross-Check: igor-pavlenko/http-message-signatures-rfc9421-go × yaronf/httpsign

Interoperability check between this library and [yaronf/httpsign](https://github.com/yaronf/httpsign), a second independent Go implementation of
RFC 9421 (HTTP Message Signatures). Every scenario is exercised in both directions:

1. **yaronf/httpsign signs → this library verifies**
2. **this library signs → yaronf/httpsign verifies**

Both libraries sign with the RFC 9421 Appendix B.1 example keys (`../tests/test-key-*`), across all 5 algorithms both support (`rsa-pss-sha512`,
`rsa-v1_5-sha256`, `ecdsa-p256-sha256`, `ed25519`, `hmac-sha256`), covering plain and
derived components, query parameters, `Content-Digest` bodies, `created`/`expires`/`nonce`/
`tag`/`keyid` signature parameters, and request and response signing.

**Result: 32/32 checks passed.**

## Running this yourself

```bash
cd examples
go run .
```

This regenerates the results below. Keys are loaded fresh from `../tests` on each run;
nothing is cached or hardcoded, so a signature-base incompatibility introduced in either
library would show up here as a failing row.

## Results

| # | Scenario | Algorithm | yaronf/httpsign → ours | ours → yaronf/httpsign |
|---|----------|-----------|:---:|:---:|
| 1 | RSA-PSS-SHA512: create order | `rsa-pss-sha512` | ✅ pass | ✅ pass |
| 2 | RSA-PSS-SHA512: payment with Content-Digest | `rsa-pss-sha512` | ✅ pass | ✅ pass |
| 3 | RSA-PSS-SHA512: invoice lookup (response) | `rsa-pss-sha512` | ✅ pass | ✅ pass |
| 4 | RSA-v1.5-SHA256: fetch account | `rsa-v1_5-sha256` | ✅ pass | ✅ pass |
| 5 | RSA-v1.5-SHA256: update profile | `rsa-v1_5-sha256` | ✅ pass | ✅ pass |
| 6 | ECDSA-P256-SHA256: health status | `ecdsa-p256-sha256` | ✅ pass | ✅ pass |
| 7 | ECDSA-P256-SHA256: webhook notify | `ecdsa-p256-sha256` | ✅ pass | ✅ pass |
| 8 | ECDSA-P256-SHA256: create order (response) | `ecdsa-p256-sha256` | ✅ pass | ✅ pass |
| 9 | Ed25519: health check | `ed25519` | ✅ pass | ✅ pass |
| 10 | Ed25519: post comment | `ed25519` | ✅ pass | ✅ pass |
| 11 | Ed25519: revoke session | `ed25519` | ✅ pass | ✅ pass |
| 12 | Ed25519: search with query param | `ed25519` | ✅ pass | ✅ pass |
| 13 | HMAC-SHA256: submit event | `hmac-sha256` | ✅ pass | ✅ pass |
| 14 | HMAC-SHA256: upload metadata with Content-Digest | `hmac-sha256` | ✅ pass | ✅ pass |
| 15 | HMAC-SHA256: list users with query param | `hmac-sha256` | ✅ pass | ✅ pass |
| 16 | HMAC-SHA256: patch settings | `hmac-sha256` | ✅ pass | ✅ pass |

## Sample signed headers

One worked example per algorithm (from the yaronf/httpsign → ours direction):

**rsa-pss-sha512** — RSA-PSS-SHA512: create order

```http
Signature-Input: sig1=("@method" "@target-uri" "content-type");created=1787511339;alg="rsa-pss-sha512";keyid="test-key-rsa-pss"
Signature: sig1=:aDRBrPBzC+0TY3F9icBxJ7E+MAUdsbsQUd0Fmoh7DuJpPWbmmwGJmil0Tvo+W1BEbKwLXZ7XDiS53EZg2YXJy2YOY4kbN2v4IB6/IWdzBYxFqWI+jy2cPgxvOkZQhneTOpPExvrK6yNzMcVs2YGmlFoEsbloHh/Itk5TTViA0x0LJIwWr6D5O4J18Vxcts7n6opt7Uemk9tOF4Ew2qyojMN2NPyNHZa6KrjMCrvX5cRvPqlujkXpg8mjdB1B5OPAzgSIKIuINzGqQrlRTRlf4zCnfIyRKQ2J7g5XtzCPwrdmG/UqgjXNRLFbXuayVSlQ2QxVHbVX6UbVJZvTe81etA==:
```

**rsa-v1_5-sha256** — RSA-v1.5-SHA256: fetch account

```http
Signature-Input: sig1=("@method" "@path" "@authority");created=1787511339;alg="rsa-v1_5-sha256";keyid="test-key-rsa"
Signature: sig1=:NuN4wHZuCkc6TlRkFvhVl6wyWoY2LIEZg0t5KLQSQ3HWDsRsFtWNbA360DMNDk6C46BkY3Mley/Nl6jwX++0UjOrck3mEdmBvE8Cy2fRjEk7ZOTXt4/AhGATY8UyO86NwcLZ02F320ObN+FD1gacOkSx6NL4zhaCu7PxT3ebzCFtaKzq7eZENc+6AMlXSp51T7p5IQP2JNDnPt7X7lnBbRVd+euoHvEpamewJX+h8YC50Zv68w9Imli6RA1PXR6T/dYNRvqfzQhqc/apPIDJsobVUqplqwvCb3Y+EjazPiYsoF82kxlqVIobQFFQ5P7x6TSvZNNY9LvoJb9kGP/QZA==:
```

**ecdsa-p256-sha256** — ECDSA-P256-SHA256: health status

```http
Signature-Input: sig1=("@method" "@target-uri" "date");created=1787511339;alg="ecdsa-p256-sha256"
Signature: sig1=:NNcRqX1vqfZ4eXkDnSwDkR2OwYLbCXFFh0Bro+ueQ/idb8mHa1WKDdwMUdq+Is4nqW26iNl0tnC6m1q7C9CiAg==:
```

**ed25519** — Ed25519: health check

```http
Signature-Input: sig1=("@method" "@target-uri");created=1787511339;alg="ed25519"
Signature: sig1=:fz0ZaGQkB1oySb8cHWtuD6RIG65LsqFRVplb2lVAOp33JIu7UfzNdTWjgjXeDU3iBmvMy9vzvPviQBnyd6TJCQ==:
```

**hmac-sha256** — HMAC-SHA256: submit event

```http
Signature-Input: sig1=("@method" "@target-uri" "content-type");created=1787511339;alg="hmac-sha256"
Signature: sig1=:N3eqV/AVBsNhPpwy4tXLMxQ96+oxl5+6B+7y4+v+cng=:
```

## Notes

This cross-check caught a real interoperability bug during development: this library's ECDSA signer/verifier used Go's `ecdsa.SignASN1`/`VerifyASN1`, which produces variable-length ASN.1 DER signatures. RFC 9421 §3.3.4/§3.3.5 require a fixed-length big-endian `r || s` concatenation instead (64 bytes for P-256, 96 for P-384) — the same encoding yaronf/httpsign uses. Every ECDSA scenario above failed in both directions until `pkg/signing/ecdsa.go` was fixed to encode/decode raw `r || s`. It's a good illustration of why this cross-check exists: a library can pass its own RFC test vectors (by re-encoding them to whatever format it happens to use internally) while still being unable to talk to any other implementation.

