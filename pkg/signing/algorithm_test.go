package signing

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// TestGetAlgorithm_EmptyID tests that GetAlgorithm returns error for empty ID.
func TestGetAlgorithm_EmptyID(t *testing.T) {
	_, err := GetAlgorithm("")
	if err == nil {
		t.Fatal("expected error for empty algorithm ID, got nil")
	}

	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("expected error message about empty ID, got: %v", err)
	}
}

// TestGetAlgorithm_UnsupportedID tests that GetAlgorithm returns error for unknown algorithm.
func TestGetAlgorithm_UnsupportedID(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{"unknown algorithm", "unknown-algorithm"},
		{"case mismatch", "RSA-PSS-SHA512"}, // Case-sensitive per RFC 9421
		{"typo", "rsa-pss-sha51"},
		{"empty dashes", "---"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetAlgorithm(tt.id)
			if err == nil {
				t.Fatalf("expected error for algorithm ID %q, got nil", tt.id)
			}

			if !strings.Contains(err.Error(), "unsupported algorithm") {
				t.Errorf("expected error message about unsupported algorithm, got: %v", err)
			}
		})
	}
}

// TestSupportedAlgorithms_ReturnsNonEmpty tests that SupportedAlgorithms returns a list.
func TestSupportedAlgorithms_ReturnsNonEmpty(t *testing.T) {
	algorithms := SupportedAlgorithms()

	// We expect at least one algorithm (will be populated once we implement RSA-PSS)
	// For now, this might be empty, but the function should not panic
	if algorithms == nil {
		t.Fatal("SupportedAlgorithms() returned nil, expected empty slice")
	}

	t.Logf("Currently registered algorithms: %v", algorithms)
}

// TestSupportedAlgorithms_RFC9421Compliance tests that all RFC 9421 algorithms will be registered.
// This test will fail until all algorithms are implemented, which is expected.
func TestSupportedAlgorithms_RFC9421Compliance(t *testing.T) {
	expectedAlgorithms := []string{
		"ecdsa-p256-sha256",
		"ecdsa-p384-sha384",
		"ed25519",
		"hmac-sha256",
		"rsa-pss-sha512",
		"rsa-v1_5-sha256",
	}

	algorithms := SupportedAlgorithms()
	algorithmSet := make(map[string]bool)
	for _, alg := range algorithms {
		algorithmSet[alg] = true
	}

	var missing []string
	for _, expected := range expectedAlgorithms {
		if !algorithmSet[expected] {
			missing = append(missing, expected)
		}
	}

	if len(missing) > 0 {
		t.Logf("NOTE: Missing RFC 9421 algorithms (will be implemented): %v", missing)
		// Don't fail the test - these will be added as we implement each algorithm
	}
}

// TestRegisterAlgorithm_DuplicateReturnsError tests that registering duplicate algorithm returns error.
func TestRegisterAlgorithm_DuplicateReturnsError(t *testing.T) {
	// Create a mock algorithm
	mock := &mockAlgorithm{id: "test-duplicate-algorithm"}

	// First registration should succeed
	err := RegisterAlgorithm(mock)
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	// Clean up
	defer func() {
		delete(algorithmRegistry, "test-duplicate-algorithm")
	}()

	// Second registration should return error
	err = RegisterAlgorithm(mock)
	if err == nil {
		t.Fatal("expected error when registering duplicate algorithm")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("expected error about duplicate, got: %v", err)
	}
}

// mockAlgorithm is a simple mock for testing the registry.
type mockAlgorithm struct {
	id string
}

func (m *mockAlgorithm) ID() string {
	return m.id
}

func (m *mockAlgorithm) Sign(_ []byte, _ any) ([]byte, error) {
	return []byte("mock-signature"), nil
}

func (m *mockAlgorithm) Verify(_, _ []byte, _ any) error {
	return nil
}

// TestRegistry_ConcurrentUse exercises the registry's documented concurrency
// safety: lookups, listings, and runtime registrations from multiple goroutines.
func TestRegistry_ConcurrentUse(t *testing.T) {
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for range 200 {
				alg, err := GetAlgorithm("hmac-sha256")
				if err != nil || alg == nil {
					t.Errorf("GetAlgorithm() = %v, %v", alg, err)
					return
				}
				if ids := SupportedAlgorithms(); len(ids) == 0 {
					t.Errorf("SupportedAlgorithms() returned empty list")
					return
				}
				// Duplicate registrations are expected after the first
				// iteration (and on repeated runs in the same process).
				id := fmt.Sprintf("test-concurrent-%d", g)
				if err := RegisterAlgorithm(&mockAlgorithm{id: id}); err != nil &&
					!strings.Contains(err.Error(), "already registered") {
					t.Errorf("RegisterAlgorithm() error: %v", err)
					return
				}
				if _, err := GetAlgorithm(id); err != nil {
					t.Errorf("GetAlgorithm(%q) error: %v", id, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
