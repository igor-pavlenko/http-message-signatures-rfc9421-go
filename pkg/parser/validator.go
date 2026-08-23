package parser

import (
	"fmt"
)

// validDerivedComponents is the whitelist of RFC 9421 Section 2.2 derived components.
// Per VR-041: @signature-params MUST NOT appear in covered components (it's auto-generated).
var validDerivedComponents = map[string]bool{
	"@method":         true, // RFC 9421 Section 2.2.1
	"@target-uri":     true, // RFC 9421 Section 2.2.2
	"@authority":      true, // RFC 9421 Section 2.2.3
	"@scheme":         true, // RFC 9421 Section 2.2.4
	"@request-target": true, // RFC 9421 Section 2.2.5
	"@path":           true, // RFC 9421 Section 2.2.6
	"@query":          true, // RFC 9421 Section 2.2.7
	"@query-param":    true, // RFC 9421 Section 2.2.8 (requires 'name' parameter)
	"@status":         true, // RFC 9421 Section 2.2.9
}

// reservedDerivedComponents are derived components that must NOT be in covered components.
var reservedDerivedComponents = map[string]bool{
	"@signature-params": true, // RFC 9421 Section 2.3 - auto-generated, not user-specified
}

// validateComponentIdentifier validates a component identifier per RFC 9421.
func validateComponentIdentifier(comp ComponentIdentifier) error {
	if comp.Type == ComponentDerived {
		// Check if it's a reserved component (FR-025, VR-041)
		if reservedDerivedComponents[comp.Name] {
			return fmt.Errorf("component %q must not appear in covered components (auto-generated)", comp.Name)
		}

		// Check if it's a valid derived component from RFC 9421 whitelist
		if !validDerivedComponents[comp.Name] {
			return fmt.Errorf("invalid derived component %q: not in RFC 9421 Section 2.2 registry", comp.Name)
		}

		// Validate required parameters for specific components
		if err := validateDerivedComponentParameters(comp); err != nil {
			return err
		}
	}

	// Validate parameter combinations (FR-024)
	if err := validateParameterCombinations(comp); err != nil {
		return err
	}

	return nil
}

// validateDerivedComponentParameters validates required parameters for specific derived components.
func validateDerivedComponentParameters(comp ComponentIdentifier) error {
	switch comp.Name {
	case "@query-param":
		// RFC 9421 Section 2.2.8: @query-param requires 'name' parameter
		hasName := false
		for _, param := range comp.Parameters {
			if param.Key == "name" {
				hasName = true
				break
			}
		}
		if !hasName {
			return fmt.Errorf("derived component %q requires 'name' parameter", comp.Name)
		}
	}
	return nil
}

// validateParameterCombinations validates parameter combinations per FR-024.
func validateParameterCombinations(comp ComponentIdentifier) error {
	hasBS := false
	hasSF := false
	hasKey := false

	for _, param := range comp.Parameters {
		switch param.Key {
		case "bs":
			hasBS = true
		case "sf":
			hasSF = true
		case "key":
			hasKey = true
		}
	}

	// VR-035: bs and sf are mutually exclusive
	if hasBS && hasSF {
		return fmt.Errorf("component %q has invalid parameter combination: 'bs' and 'sf' are mutually exclusive", comp.Name)
	}

	// VR-036: bs and key are mutually exclusive
	if hasBS && hasKey {
		return fmt.Errorf("component %q has invalid parameter combination: 'bs' and 'key' are mutually exclusive", comp.Name)
	}

	// VR-037: key requires sf (key is used to extract dictionary member from structured field)
	if hasKey && !hasSF {
		return fmt.Errorf("component %q has invalid parameter combination: 'key' parameter requires 'sf' parameter", comp.Name)
	}

	return nil
}
