package base

import (
	"testing"
)

// T011: Test signature base assembly per RFC 9421 Section 2.5
func TestAssembleSignatureBase(t *testing.T) {
	t.Run("single component line", func(t *testing.T) {
		componentLines := []string{
			`"@method": POST`,
		}
		signatureParamsLine := `"@signature-params": ("@method")`

		got := assembleSignatureBase(componentLines, signatureParamsLine)
		want := "\"@method\": POST\n\"@signature-params\": (\"@method\")"

		if got != want {
			t.Errorf("assembleSignatureBase() = %q, want %q", got, want)
		}
	})

	t.Run("multiple component lines", func(t *testing.T) {
		componentLines := []string{
			`"@method": POST`,
			`"@path": /foo`,
			`"content-type": application/json`,
		}
		signatureParamsLine := `"@signature-params": ("@method" "@path" "content-type")`

		got := assembleSignatureBase(componentLines, signatureParamsLine)
		want := "\"@method\": POST\n\"@path\": /foo\n\"content-type\": application/json\n\"@signature-params\": (\"@method\" \"@path\" \"content-type\")"

		if got != want {
			t.Errorf("assembleSignatureBase() = %q, want %q", got, want)
		}
	})

	t.Run("empty component lines", func(t *testing.T) {
		// RFC 9421 Appendix B.2.1: Minimal signature with no covered components
		var componentLines []string
		signatureParamsLine := `"@signature-params": ()`

		got := assembleSignatureBase(componentLines, signatureParamsLine)
		want := `"@signature-params": ()`

		if got != want {
			t.Errorf("assembleSignatureBase() = %q, want %q", got, want)
		}
	})

	t.Run("component lines with empty values", func(t *testing.T) {
		componentLines := []string{
			`"empty-field": `,
			`"@method": GET`,
		}
		signatureParamsLine := `"@signature-params": ("empty-field" "@method")`

		got := assembleSignatureBase(componentLines, signatureParamsLine)
		want := "\"empty-field\": \n\"@method\": GET\n\"@signature-params\": (\"empty-field\" \"@method\")"

		if got != want {
			t.Errorf("assembleSignatureBase() = %q, want %q", got, want)
		}
	})

	t.Run("with signature metadata", func(t *testing.T) {
		componentLines := []string{
			`"@method": POST`,
		}
		signatureParamsLine := `"@signature-params": ("@method");created=1618884473;keyid="test-key-rsa-pss"`

		got := assembleSignatureBase(componentLines, signatureParamsLine)
		want := "\"@method\": POST\n\"@signature-params\": (\"@method\");created=1618884473;keyid=\"test-key-rsa-pss\""

		if got != want {
			t.Errorf("assembleSignatureBase() = %q, want %q", got, want)
		}
	})

	t.Run("no trailing newline", func(t *testing.T) {
		// RFC 9421 Section 2.5: No trailing newline after @signature-params
		componentLines := []string{
			`"@method": POST`,
			`"@path": /foo`,
		}
		signatureParamsLine := `"@signature-params": ("@method" "@path")`

		got := assembleSignatureBase(componentLines, signatureParamsLine)

		// Verify no trailing newline
		if len(got) > 0 && got[len(got)-1] == '\n' {
			t.Error("assembleSignatureBase() should not have trailing newline")
		}

		// Verify correct line count (2 component lines + 1 signature-params = 3 lines, 2 newlines)
		newlineCount := 0
		for _, ch := range got {
			if ch == '\n' {
				newlineCount++
			}
		}
		if newlineCount != 2 {
			t.Errorf("assembleSignatureBase() has %d newlines, want 2", newlineCount)
		}
	})

	t.Run("RFC 9421 Appendix B.2.5 example", func(t *testing.T) {
		// Full example from RFC with multiple components and all metadata
		componentLines := []string{
			`"date": Sun, 05 Jan 2014 21:31:40 GMT`,
			`"@method": POST`,
			`"@path": /foo`,
			`"@authority": example.com`,
			`"content-type": application/json`,
			`"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:`,
			`"content-length": 18`,
		}
		signatureParamsLine := `"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`

		got := assembleSignatureBase(componentLines, signatureParamsLine)

		// Verify it joins with LF and has no trailing newline
		expectedNewlineCount := len(componentLines) // One less than line count

		actualNewlineCount := 0
		for _, ch := range got {
			if ch == '\n' {
				actualNewlineCount++
			}
		}

		if actualNewlineCount != expectedNewlineCount {
			t.Errorf("assembleSignatureBase() has %d newlines, want %d", actualNewlineCount, expectedNewlineCount)
		}

		// Verify no trailing newline
		if len(got) > 0 && got[len(got)-1] == '\n' {
			t.Error("assembleSignatureBase() should not have trailing newline")
		}

		// Verify it contains all expected lines
		if !contains(got, `"date": Sun, 05 Jan 2014 21:31:40 GMT`) {
			t.Error("missing date line")
		}
		if !contains(got, `"@method": POST`) {
			t.Error("missing @method line")
		}
		if !contains(got, `"@signature-params": ("date" "@method"`) {
			t.Error("missing @signature-params line")
		}
	})
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || len(s) > len(substr)+1 && containsAt(s, substr, 1)))
}

func containsAt(s, substr string, start int) bool {
	if start+len(substr) > len(s) {
		return false
	}
	if s[start:start+len(substr)] == substr {
		return true
	}
	if start+len(substr) < len(s) {
		return containsAt(s, substr, start+1)
	}
	return false
}
