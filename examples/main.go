// Command examples cross-checks this library against yaronf/httpsign
// (https://github.com/yaronf/httpsign): every scenario below is signed by
// one library and verified by the other, in both directions, using the
// RFC 9421 Appendix B.1 example keys from ../tests. Run with:
//
//	cd examples && go run .
//
// It regenerates README.md in this directory with the results.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// readmePath resolves README.md next to this source file, so the output
// lands in examples/ regardless of the caller's working directory (e.g.
// `go run ./examples` from the repo root must not overwrite the top-level
// README.md).
func readmePath() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "README.md")
}

func main() {
	if err := loadKeys(); err != nil {
		fmt.Fprintln(os.Stderr, "failed to load RFC test keys:", err)
		os.Exit(1)
	}

	var results []checkResult
	failures := 0
	for _, s := range scenarios() {
		r1 := runTheirsSignOursVerify(s)
		r2 := runOursSignTheirsVerify(s)
		results = append(results, r1, r2)
		if !r1.ok {
			failures++
		}
		if !r2.ok {
			failures++
		}
	}

	report := renderReport(results)
	if err := os.WriteFile(readmePath(), []byte(report), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "failed to write README.md:", err)
		os.Exit(1)
	}

	fmt.Printf("%d checks, %d passed, %d failed\n", len(results), len(results)-failures, failures)
	fmt.Println("wrote examples/README.md")
	if failures > 0 {
		os.Exit(1)
	}
}

func renderReport(results []checkResult) string {
	var b strings.Builder

	pass := 0
	for _, r := range results {
		if r.ok {
			pass++
		}
	}

	b.WriteString("# Cross-Check: igor-pavlenko/http-message-signatures-rfc9421-go × yaronf/httpsign\n\n")
	b.WriteString("Interoperability check between this library and [yaronf/httpsign]" +
		"(https://github.com/yaronf/httpsign), a second independent Go implementation of\n" +
		"RFC 9421 (HTTP Message Signatures). Every scenario is exercised in both directions:\n\n")
	b.WriteString("1. **yaronf/httpsign signs → this library verifies**\n")
	b.WriteString("2. **this library signs → yaronf/httpsign verifies**\n\n")
	b.WriteString(fmt.Sprintf("Both libraries sign with the RFC 9421 Appendix B.1 example keys "+
		"(`../tests/test-key-*`), across all 5 algorithms both support (`rsa-pss-sha512`,\n"+
		"`rsa-v1_5-sha256`, `ecdsa-p256-sha256`, `ed25519`, `hmac-sha256`), covering plain and\n"+
		"derived components, query parameters, `Content-Digest` bodies, `created`/`expires`/`nonce`/\n"+
		"`tag`/`keyid` signature parameters, and request and response signing.\n\n"+
		"**Result: %d/%d checks passed.**\n\n", pass, len(results)))

	b.WriteString("## Running this yourself\n\n```bash\ncd examples\ngo run .\n```\n\n" +
		"This regenerates the results below. Keys are loaded fresh from `../tests` on each run;\n" +
		"nothing is cached or hardcoded, so a signature-base incompatibility introduced in either\n" +
		"library would show up here as a failing row.\n\n")

	b.WriteString("## Results\n\n")
	b.WriteString("| # | Scenario | Algorithm | yaronf/httpsign → ours | ours → yaronf/httpsign |\n")
	b.WriteString("|---|----------|-----------|:---:|:---:|\n")

	for i := 0; i < len(results); i += 2 {
		r1, r2 := results[i], results[i+1]
		b.WriteString(fmt.Sprintf("| %d | %s | `%s` | %s | %s |\n",
			i/2+1, r1.scenario, r1.algID, statusCell(r1), statusCell(r2)))
	}
	b.WriteString("\n")

	if failed := failuresSection(results); failed != "" {
		b.WriteString("## Failures\n\n")
		b.WriteString(failed)
		b.WriteString("\n")
	}

	b.WriteString(sampleHeadersSection(results))

	b.WriteString("## Notes\n\n")
	b.WriteString("This cross-check caught a real interoperability bug during development: " +
		"this library's ECDSA signer/verifier used Go's `ecdsa.SignASN1`/`VerifyASN1`, which " +
		"produces variable-length ASN.1 DER signatures. RFC 9421 §3.3.4/§3.3.5 require a " +
		"fixed-length big-endian `r || s` concatenation instead (64 bytes for P-256, 96 for " +
		"P-384) — the same encoding yaronf/httpsign uses. Every ECDSA scenario above failed in " +
		"both directions until `pkg/signing/ecdsa.go` was fixed to encode/decode raw `r || s`. " +
		"It's a good illustration of why this cross-check exists: a library can pass its own " +
		"RFC test vectors (by re-encoding them to whatever format it happens to use internally) " +
		"while still being unable to talk to any other implementation.\n\n")

	return b.String()
}

func statusCell(r checkResult) string {
	if r.ok {
		return "✅ pass"
	}
	return "❌ fail"
}

func failuresSection(results []checkResult) string {
	var b strings.Builder
	for _, r := range results {
		if r.ok {
			continue
		}
		b.WriteString(fmt.Sprintf("- **%s** (`%s`, %s): %s\n", r.scenario, r.algID, r.direction, r.errMsg))
	}
	return b.String()
}

// sampleHeadersSection embeds a handful of full Signature-Input/Signature
// pairs, one per algorithm, so the README shows real interoperable output
// rather than just pass/fail.
func sampleHeadersSection(results []checkResult) string {
	seen := map[string]bool{}
	var b strings.Builder
	b.WriteString("## Sample signed headers\n\n")
	b.WriteString("One worked example per algorithm (from the yaronf/httpsign → ours direction):\n\n")
	for _, r := range results {
		if !r.ok || seen[r.algID] || !strings.HasPrefix(r.direction, "yaronf") {
			continue
		}
		seen[r.algID] = true
		b.WriteString(fmt.Sprintf("**%s** — %s\n\n", r.algID, r.scenario))
		b.WriteString("```http\n")
		b.WriteString("Signature-Input: " + r.sigInput + "\n")
		b.WriteString("Signature: " + r.signature + "\n")
		b.WriteString("```\n\n")
	}
	return b.String()
}
