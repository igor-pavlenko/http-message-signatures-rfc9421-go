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

## Results

Verify-side numbers below reflect `Verifier`'s current, concurrency-safe
behavior — see the Verifier caching note under Methodology.

### Sign Performance (ns/op, lower is better)

| Algorithm | igor-pavlenko | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | 858,725 | **858,405** | 859,531 | 860,759 |
| ECDSA-P256-SHA256 | **24,873** | 27,923 | 27,378 | 28,950 |
| HMAC-SHA256 | **2,289** | 4,354 | 4,585 | 6,053 |

RSA-PSS-SHA512 signing is dominated by the underlying `crypto/rsa` PSS
operation itself (all four libraries call into the same stdlib primitive), so
the four implementations land within noise of each other (<0.3% apart) rather
than showing a meaningful gap.

### HMAC + Content-Digest (10MB) Sign Performance

| Metric | igor-pavlenko | yaronf | remitly | common-fate |
|--------|----------|--------|---------|-------------|
| ns/op | **4,254,302** | 6,483,419 | 5,356,249 | 5,276,643 |
| MB/s | **2,465** | 1,617 | 1,958 | 1,987 |
| B/op | **8,857** | 54,541,529 | 33,570,723 | 33,572,268 |
| allocs/op | **55** | 172 | 184 | 182 |

### Sign Memory (B/op, lower is better)

| Algorithm | igor-pavlenko | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **8,923** | 12,058 | 12,186 | 14,389 |
| ECDSA-P256-SHA256 | **13,300** | 17,145 | 17,071 | 19,239 |
| HMAC-SHA256 | **7,594** | 10,729 | 11,153 | 14,757 |

### Sign Allocations (allocs/op, lower is better)

| Algorithm | igor-pavlenko | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **44** | 107 | 119 | 126 |
| ECDSA-P256-SHA256 | **95** | 173 | 174 | 181 |
| HMAC-SHA256 | **42** | 105 | 116 | 124 |

### Verify Performance (ns/op, lower is better)

| Algorithm | igor-pavlenko | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **30,578** | 34,868 | 31,999 | 33,165 |
| ECDSA-P256-SHA256 | **57,480** | 61,433 | 58,888 | 60,234 |
| HMAC-SHA256 | **2,168** | 5,881 | 3,391 | 5,241 |

### Verify Memory (B/op, lower is better)

| Algorithm | igor-pavlenko | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **5,688** | 11,541 | 6,939 | 9,248 |
| ECDSA-P256-SHA256 | **4,504** | 10,244 | 6,362 | 8,712 |
| HMAC-SHA256 | **4,408** | 9,412 | 5,658 | 8,888 |

### Verify Allocations (allocs/op, lower is better)

| Algorithm | igor-pavlenko | yaronf | remitly | common-fate |
|-----------|----------|--------|---------|-------------|
| RSA-PSS-SHA512 | **58** | 184 | 119 | 126 |
| ECDSA-P256-SHA256 | **54** | 190 | 125 | 133 |
| HMAC-SHA256 | **50** | 176 | 111 | 118 |

## Visual Summary

Bars are scaled per algorithm to the slowest library (40 columns).

```
Sign (ns/op, lower is better)
  RSA-PSS-SHA512
    igor-pavlenko ######################################## 858725
    yaronf        ######################################## 858405
    remitly       ######################################## 859531
    common-fate   ######################################## 860759

  ECDSA-P256-SHA256
    igor-pavlenko ##################################       24873
    yaronf        ######################################## 27923
    remitly       ######################################   27378
    common-fate   ######################################## 28950

  HMAC-SHA256
    igor-pavlenko ###############                          2289
    yaronf        #############################            4354
    remitly       ##############################           4585
    common-fate   ######################################## 6053

Sign HMAC + Content-Digest (10MB)
    igor-pavlenko ##########################               4254302
    yaronf        ######################################## 6483419
    remitly       #################################        5356249
    common-fate   #################################        5276643

Verify (ns/op, lower is better)
  RSA-PSS-SHA512
    igor-pavlenko ###################################      30578
    yaronf        ######################################## 34868
    remitly       #####################################    31999
    common-fate   ######################################## 33165

  ECDSA-P256-SHA256
    igor-pavlenko #####################################    57480
    yaronf        ######################################## 61433
    remitly       ######################################   58888
    common-fate   ######################################## 60234

  HMAC-SHA256
    igor-pavlenko ###############                          2168
    yaronf        ######################################## 5881
    remitly       #######################                  3391
    common-fate   ####################################     5241
```

## Key Observations

### Performance
- **RSA-PSS Sign**: all four libraries land within ~0.3% of each other — the RSA-PSS
  `crypto/rsa` call dominates cost, leaving no meaningful gap between implementations.
- **RSA-PSS Verify**: igor-pavlenko ~5-14% faster
- **ECDSA Sign**: igor-pavlenko ~10-16% faster
- **ECDSA Verify**: igor-pavlenko ~2-7% faster
- **HMAC Sign**: igor-pavlenko ~1.9-2.6x faster
- **HMAC Verify**: igor-pavlenko ~1.6-2.7x faster

### Memory Efficiency
- igor-pavlenko uses **1.2x-2.3x less memory** than alternatives in the hot path.
- igor-pavlenko makes **1.8x-3.5x fewer allocations** during signing and verification.
- large-body digest: igor-pavlenko stays **~9 KB/op** vs **33-54 MB/op** for others (full body buffering).
- Verify-side memory/allocation savings are smaller than in previous results because
  `Verifier` no longer caches Signature-Input parsing between calls (see note above) —
  each call now does the full parse, same as the other libraries.

## Running Benchmarks

```bash
cd benchmarks/comparison
go test -bench=. -benchmem -count=5
go test -bench=BenchmarkSign_HMAC_ContentDigest_10MB -benchmem -count=5
```
