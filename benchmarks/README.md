# HTTP Message Signatures Library Benchmarks

Benchmark comparison of Go implementations of RFC 9421 HTTP Message Signatures.

## Libraries Compared

| Library | Import Path |
|---------|-------------|
| **igor-pavlenko** | `github.com/igor-pavlenko/http-message-signatures-rfc9421-go` |
| yaronf/httpsign | `github.com/yaronf/httpsign` v0.5.2 |
| remitly-oss/httpsig-go | `github.com/remitly-oss/httpsig-go` v1.2.2 |
| common-fate/httpsig | `github.com/common-fate/httpsig` v0.2.1 |

## Benchmark Environment

- **Go Version**: 1.27.0
- **OS**: macOS (Darwin)
- **Architecture**: arm64 (Apple Silicon)
- **CPU**: Apple M2

## Methodology

All benchmarks measure equivalent full-flow operations:
- **Sign**: Build signature base → crypto sign → serialize headers → attach to request
- **Verify**: Parse headers → rebuild signature base → crypto verify

**Components signed**: `@method`, `@target-uri`, `content-type` (identical across all libraries)
**Validation**: `created` required, max age 5 minutes, future skew 1 minute (applied across all libraries)
**Reporting**: median of 5 runs (`go test -bench=. -benchmem -count=5`)
**Large-body digest benchmark**: 10MB request body, HMAC signing with `content-digest` + `content-length`

**Verifier caching**: igor-pavlenko's `Verifier` does not cache Signature-Input parsing
between calls — each `VerifyRequest`/`VerifyResponse` call fully re-parses the
headers it's given, same as the other three libraries. An earlier revision cached
the parse on the `Verifier` struct, which inflated Verify-side numbers in a way
that wasn't representative (real traffic sends distinct Signature-Input per
request) and was unsafe if a single `Verifier` were reused across concurrent
goroutines, a normal pattern for an HTTP server. That cache was removed for
correctness; see commit `514b021`.

**ECDSA encoding**: igor-pavlenko's ECDSA signatures use RFC 9421's required
fixed-length `r||s` concatenation rather than Go's ASN.1 DER encoding — DER
signatures were unverifiable by any conformant RFC 9421 implementation. This
was fixed in commit `b8e49c8`; the numbers below reflect the raw-concat path.
Measured cost is within noise of the earlier DER numbers — avoiding ASN.1
marshaling doesn't move the needle much against the dominant P-256 scalar
multiplication cost.

## Results

Verify-side numbers below reflect `Verifier`'s current, concurrency-safe
behavior — see the Verifier caching note under Methodology. ECDSA numbers
reflect the raw `r||s` encoding — see the ECDSA encoding note above.

### Sign Performance (ns/op, lower is better)

| Algorithm | igor-pavlenko | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | 865,057 | 868,062 | **861,428** | 862,980 |
| ECDSA-P256-SHA256 | **25,373** | 28,308 | 27,663 | 29,678 |
| HMAC-SHA256 | **2,357** | 4,431 | 4,639 | 6,133 |

RSA-PSS-SHA512 signing is dominated by the underlying `crypto/rsa` PSS
operation itself (all four libraries call into the same stdlib primitive), so
the four implementations land within noise of each other (<1% apart) rather
than showing a meaningful gap.

### HMAC + Content-Digest (10MB) Sign Performance

| Metric | igor-pavlenko | yaronf | remitly | common-fate |
|--------|----------|--------|---------|-------------|
| ns/op | **4,311,291** | 6,653,874 | 5,425,723 | 5,347,823 |
| MB/s | **2,432** | 1,576 | 1,933 | 1,961 |
| B/op | **8,857** | 54,541,529 | 33,570,689 | 33,572,261 |
| allocs/op | **55** | 172 | 184 | 182 |

### Sign Memory (B/op, lower is better)

| Algorithm | igor-pavlenko | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **8,923** | 12,058 | 12,185 | 14,389 |
| ECDSA-P256-SHA256 | **13,557** | 17,145 | 17,071 | 19,239 |
| HMAC-SHA256 | **7,594** | 10,729 | 11,154 | 14,758 |

### Sign Allocations (allocs/op, lower is better)

| Algorithm | igor-pavlenko | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **44** | 107 | 119 | 126 |
| ECDSA-P256-SHA256 | **100** | 173 | 174 | 181 |
| HMAC-SHA256 | **42** | 105 | 116 | 124 |

### Verify Performance (ns/op, lower is better)

| Algorithm | igor-pavlenko | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **30,709** | 35,341 | 33,519 | 33,486 |
| ECDSA-P256-SHA256 | **58,243** | 63,296 | 60,676 | 60,309 |
| HMAC-SHA256 | **2,381** | 6,487 | 3,440 | 5,283 |

### Verify Memory (B/op, lower is better)

| Algorithm | igor-pavlenko | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **5,688** | 11,541 | 6,939 | 9,248 |
| ECDSA-P256-SHA256 | **5,208** | 10,244 | 6,362 | 8,712 |
| HMAC-SHA256 | **4,408** | 9,412 | 5,658 | 8,888 |

### Verify Allocations (allocs/op, lower is better)

| Algorithm | igor-pavlenko | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **58** | 184 | 119 | 126 |
| ECDSA-P256-SHA256 | **67** | 190 | 125 | 133 |
| HMAC-SHA256 | **50** | 176 | 111 | 118 |

## Visual Summary

Bars are scaled per algorithm to the slowest library (40 columns).

```
Sign (ns/op, lower is better)
  RSA-PSS-SHA512
    igor-pavlenko ######################################## 865057
    yaronf        ######################################## 868062
    remitly       ######################################## 861428
    common-fate   ######################################## 862980

  ECDSA-P256-SHA256
    igor-pavlenko ##################################       25373
    yaronf        ######################################## 28308
    remitly       #####################################    27663
    common-fate   ######################################## 29678

  HMAC-SHA256
    igor-pavlenko ###############                          2357
    yaronf        #############################            4431
    remitly       ##############################           4639
    common-fate   ######################################## 6133

Sign HMAC + Content-Digest (10MB)
    igor-pavlenko ##########################               4311291
    yaronf        ######################################## 6653874
    remitly       #################################        5425723
    common-fate   ################################         5347823

Verify (ns/op, lower is better)
  RSA-PSS-SHA512
    igor-pavlenko ###################################      30709
    yaronf        ######################################## 35341
    remitly       ######################################   33519
    common-fate   ######################################## 33486

  ECDSA-P256-SHA256
    igor-pavlenko #####################################    58243
    yaronf        ######################################## 63296
    remitly       ######################################   60676
    common-fate   ######################################## 60309

  HMAC-SHA256
    igor-pavlenko ###############                          2381
    yaronf        ######################################## 6487
    remitly       #####################                    3440
    common-fate   #################################        5283
```

## Key Observations

### Performance
- **RSA-PSS Sign**: all four libraries land within ~1% of each other — the RSA-PSS
  `crypto/rsa` call dominates cost, leaving no meaningful gap between implementations.
- **RSA-PSS Verify**: igor-pavlenko ~8-13% faster
- **ECDSA Sign**: igor-pavlenko ~8-15% faster
- **ECDSA Verify**: igor-pavlenko ~3-8% faster
- **HMAC Sign**: igor-pavlenko ~1.9-2.6x faster
- **HMAC Verify**: igor-pavlenko ~1.4-2.7x faster

### Memory Efficiency
- igor-pavlenko uses **1.3x-1.9x less memory** than alternatives in the sign-side hot path,
  and **1.2x-2.1x less** on verify.
- igor-pavlenko makes **1.7x-3.0x fewer allocations** when signing and **1.9x-3.5x fewer**
  when verifying.
- large-body digest: igor-pavlenko stays **~9 KB/op** vs **33-55 MB/op** for others (full body buffering).
- Verify-side memory/allocation savings are smaller than in previous results because
  `Verifier` no longer caches Signature-Input parsing between calls (see note above) —
  each call now does the full parse, same as the other libraries.

## Running Benchmarks

```bash
cd benchmarks/comparison
go test -bench=. -benchmem -count=5
go test -bench=BenchmarkSign_HMAC_ContentDigest_10MB -benchmem -count=5
```
