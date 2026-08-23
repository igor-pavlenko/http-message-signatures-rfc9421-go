package parser

import (
	"strings"
	"testing"
)

// TestValidateComponentIdentifier_ValidDerivedComponents tests all valid RFC 9421 derived components.
func TestValidateComponentIdentifier_ValidDerivedComponents(t *testing.T) {
	validComponents := []string{
		"@method",
		"@target-uri",
		"@authority",
		"@scheme",
		"@request-target",
		"@path",
		"@query",
		"@status",
	}

	for _, name := range validComponents {
		t.Run(name, func(t *testing.T) {
			comp := ComponentIdentifier{
				Name: name,
				Type: ComponentDerived,
			}

			err := validateComponentIdentifier(comp)
			if err != nil {
				t.Errorf("validateComponentIdentifier(%q) unexpected error: %v", name, err)
			}
		})
	}
}

// TestValidateComponentIdentifier_InvalidDerivedComponents tests rejection of unknown derived component names.
func TestValidateComponentIdentifier_InvalidDerivedComponents(t *testing.T) {
	invalidComponents := []string{
		"@invalid",
		"@custom-header",
		"@foo",
		"@bar-baz",
		"@unknown-component",
	}

	for _, name := range invalidComponents {
		t.Run(name, func(t *testing.T) {
			comp := ComponentIdentifier{
				Name: name,
				Type: ComponentDerived,
			}

			err := validateComponentIdentifier(comp)
			if err == nil {
				t.Errorf("validateComponentIdentifier(%q) expected error for invalid derived component", name)
			}

			if !strings.Contains(err.Error(), "not in RFC 9421") {
				t.Errorf("error should mention RFC 9421 registry, got: %v", err)
			}
		})
	}
}

// TestValidateComponentIdentifier_ReservedComponents tests rejection of @signature-params.
func TestValidateComponentIdentifier_ReservedComponents(t *testing.T) {
	comp := ComponentIdentifier{
		Name: "@signature-params",
		Type: ComponentDerived,
	}

	err := validateComponentIdentifier(comp)
	if err == nil {
		t.Fatal("validateComponentIdentifier(@signature-params) expected error, got nil")
	}
	if !strings.Contains(err.Error(), "auto-generated") {
		t.Errorf("error should mention auto-generated, got: %v", err)
	}
}

// TestValidateComponentIdentifier_QueryParamRequiresName tests @query-param validation.
func TestValidateComponentIdentifier_QueryParamRequiresName(t *testing.T) {
	tests := []struct {
		name       string
		parameters []Parameter
		wantErr    bool
	}{
		{
			name: "with name parameter",
			parameters: []Parameter{
				{Key: "name", Value: String{Value: "search"}},
			},
			wantErr: false,
		},
		{
			name:       "without name parameter",
			parameters: []Parameter{},
			wantErr:    true,
		},
		{
			name: "with other parameters but no name",
			parameters: []Parameter{
				{Key: "sf", Value: Boolean{Value: true}},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comp := ComponentIdentifier{
				Name:       "@query-param",
				Type:       ComponentDerived,
				Parameters: tt.parameters,
			}

			err := validateComponentIdentifier(comp)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateComponentIdentifier() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && !strings.Contains(err.Error(), "requires 'name'") {
				t.Errorf("error should mention required 'name' parameter, got: %v", err)
			}
		})
	}
}

// TestValidateParameterCombinations_BsAndSfMutuallyExclusive tests FR-024 validation.
func TestValidateParameterCombinations_BsAndSfMutuallyExclusive(t *testing.T) {
	comp := ComponentIdentifier{
		Name: "content-digest",
		Type: ComponentField,
		Parameters: []Parameter{
			{Key: "bs", Value: Boolean{Value: true}},
			{Key: "sf", Value: Boolean{Value: true}},
		},
	}

	err := validateComponentIdentifier(comp)
	if err == nil {
		t.Fatal("expected error for bs+sf combination")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should mention mutually exclusive, got: %v", err)
	}
}

// TestValidateParameterCombinations_BsAndKeyMutuallyExclusive tests FR-024 validation.
func TestValidateParameterCombinations_BsAndKeyMutuallyExclusive(t *testing.T) {
	comp := ComponentIdentifier{
		Name: "example-dict",
		Type: ComponentField,
		Parameters: []Parameter{
			{Key: "bs", Value: Boolean{Value: true}},
			{Key: "key", Value: String{Value: "member"}},
		},
	}

	err := validateComponentIdentifier(comp)
	if err == nil {
		t.Fatal("expected error for bs+key combination")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should mention mutually exclusive, got: %v", err)
	}
}

// TestValidateParameterCombinations_KeyRequiresSf tests VR-037: key requires sf parameter.
func TestValidateParameterCombinations_KeyRequiresSf(t *testing.T) {
	comp := ComponentIdentifier{
		Name: "example-dict",
		Type: ComponentField,
		Parameters: []Parameter{
			{Key: "key", Value: String{Value: "member"}},
		},
	}

	err := validateComponentIdentifier(comp)
	if err == nil {
		t.Fatal("expected error for key without sf")
	}
	if !strings.Contains(err.Error(), "'key' parameter requires 'sf'") {
		t.Errorf("error should mention key requires sf, got: %v", err)
	}
}

// TestValidateParameterCombinations_ValidCombinations tests allowed parameter combinations.
func TestValidateParameterCombinations_ValidCombinations(t *testing.T) {
	validCombinations := []struct {
		name   string
		params []Parameter
	}{
		{
			name: "sf only",
			params: []Parameter{
				{Key: "sf", Value: Boolean{Value: true}},
			},
		},
		{
			name: "bs only",
			params: []Parameter{
				{Key: "bs", Value: Boolean{Value: true}},
			},
		},
		{
			name: "sf and key together (allowed)",
			params: []Parameter{
				{Key: "sf", Value: Boolean{Value: true}},
				{Key: "key", Value: String{Value: "member"}},
			},
		},
		{
			name: "req and tr together (allowed)",
			params: []Parameter{
				{Key: "req", Value: Boolean{Value: true}},
				{Key: "tr", Value: Boolean{Value: true}},
			},
		},
	}

	for _, tt := range validCombinations {
		t.Run(tt.name, func(t *testing.T) {
			comp := ComponentIdentifier{
				Name:       "test-field",
				Type:       ComponentField,
				Parameters: tt.params,
			}

			err := validateComponentIdentifier(comp)
			if err != nil {
				t.Errorf("validateComponentIdentifier() unexpected error for valid combination: %v", err)
			}
		})
	}
}

// TestValidateComponentIdentifier_HTTPFieldsAlwaysValid tests that HTTP fields are not restricted.
func TestValidateComponentIdentifier_HTTPFieldsAlwaysValid(t *testing.T) {
	// HTTP fields can be arbitrary (not from a whitelist)
	httpFields := []string{
		"date",
		"content-type",
		"x-custom-header",
		"my-arbitrary-header",
		"authorization",
	}

	for _, name := range httpFields {
		t.Run(name, func(t *testing.T) {
			comp := ComponentIdentifier{
				Name: name,
				Type: ComponentField,
			}

			err := validateComponentIdentifier(comp)
			if err != nil {
				t.Errorf("validateComponentIdentifier(%q) unexpected error for HTTP field: %v", name, err)
			}
		})
	}
}

// ============================================================================
// Fuzz Tests
// ============================================================================

// FuzzValidateComponentIdentifier tests the component identifier validation with random inputs
// to discover edge cases in validation logic.
//
// This fuzzer tests:
// - Derived component whitelist validation (FR-013, VR-041)
// - Reserved component detection (@signature-params)
// - Required parameter validation (@query-param needs 'name')
// - Parameter combination validation (bs/sf, bs/key mutual exclusivity)
func FuzzValidateComponentIdentifier(f *testing.F) {
	// Seed corpus with valid and invalid component identifiers
	seeds := []struct {
		name      string
		compType  ComponentType
		paramKeys []string
		paramVals []string
	}{
		// Valid derived components
		{"@method", ComponentDerived, nil, nil},
		{"@target-uri", ComponentDerived, nil, nil},
		{"@authority", ComponentDerived, nil, nil},
		{"@scheme", ComponentDerived, nil, nil},
		{"@request-target", ComponentDerived, nil, nil},
		{"@path", ComponentDerived, nil, nil},
		{"@query", ComponentDerived, nil, nil},
		{"@status", ComponentDerived, nil, nil},

		// Valid @query-param with 'name' parameter
		{"@query-param", ComponentDerived, []string{"name"}, []string{"foo"}},
		{"@query-param", ComponentDerived, []string{"name", "sf"}, []string{"bar", "true"}},

		// Valid field components
		{"content-type", ComponentField, nil, nil},
		{"date", ComponentField, nil, nil},
		{"content-digest", ComponentField, []string{"key"}, []string{"sha-256"}},
		{"content-type", ComponentField, []string{"sf"}, []string{"true"}},
		{"content-type", ComponentField, []string{"bs"}, []string{"true"}},

		// Invalid - reserved component
		{"@signature-params", ComponentDerived, nil, nil},

		// Invalid - unknown derived component
		{"@custom", ComponentDerived, nil, nil},
		{"@invalid", ComponentDerived, nil, nil},
		{"@unknown-component", ComponentDerived, nil, nil},
		{"@", ComponentDerived, nil, nil},

		// Invalid - @query-param without 'name'
		{"@query-param", ComponentDerived, nil, nil},
		{"@query-param", ComponentDerived, []string{"sf"}, []string{"true"}},

		// Invalid - mutually exclusive parameters (bs and sf)
		{"content-type", ComponentField, []string{"bs", "sf"}, []string{"true", "true"}},
		{"date", ComponentField, []string{"sf", "bs"}, []string{"true", "true"}},

		// Invalid - mutually exclusive parameters (bs and key)
		{"content-digest", ComponentField, []string{"bs", "key"}, []string{"true", "sha-256"}},
		{"content-type", ComponentField, []string{"key", "bs"}, []string{"foo", "true"}},

		// Valid - non-exclusive combinations
		{"content-type", ComponentField, []string{"sf", "key"}, []string{"true", "foo"}},
		{"date", ComponentField, []string{"req"}, []string{"true"}},
		{"content-type", ComponentField, []string{"tr"}, []string{"true"}},

		// Edge cases - empty name
		{"", ComponentDerived, nil, nil},
		{"", ComponentField, nil, nil},

		// Edge cases - many parameters
		{"content-type", ComponentField, []string{"a", "b", "c", "d", "e"}, []string{"1", "2", "3", "4", "5"}},

		// Edge cases - special characters in names
		{"content-type!", ComponentField, nil, nil},
		{"@method!", ComponentDerived, nil, nil},
		{"header@name", ComponentField, nil, nil},

		// Edge cases - case sensitivity
		{"@METHOD", ComponentDerived, nil, nil},
		{"@Method", ComponentDerived, nil, nil},
		{"Content-Type", ComponentField, nil, nil},

		// Edge cases - whitespace
		{" @method", ComponentDerived, nil, nil},
		{"@method ", ComponentDerived, nil, nil},
		{" content-type ", ComponentField, nil, nil},
	}

	for _, seed := range seeds {
		// Convert to fuzzer input format
		paramKeysStr := ""
		paramValsStr := ""
		if len(seed.paramKeys) > 0 {
			for i, k := range seed.paramKeys {
				if i > 0 {
					paramKeysStr += ","
					paramValsStr += ","
				}
				paramKeysStr += k
				if i < len(seed.paramVals) {
					paramValsStr += seed.paramVals[i]
				}
			}
		}
		f.Add(seed.name, int(seed.compType), paramKeysStr, paramValsStr)
	}

	f.Fuzz(func(t *testing.T, name string, compTypeInt int, paramKeysStr, paramValsStr string) {
		// Parser must never panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("validateComponentIdentifier panicked on input:\nName: %q\nType: %d\nParamKeys: %q\nParamVals: %q\nPanic: %v",
					name, compTypeInt, paramKeysStr, paramValsStr, r)
			}
		}()

		// Convert int to ComponentType (with bounds checking)
		var compType ComponentType
		switch compTypeInt % 2 {
		case 0:
			compType = ComponentField
		case 1:
			compType = ComponentDerived
		}

		// Parse parameter strings
		var params []Parameter
		if paramKeysStr != "" {
			keys := splitByComma(paramKeysStr)
			vals := splitByComma(paramValsStr)

			params = make([]Parameter, len(keys))
			for i, key := range keys {
				val := ""
				if i < len(vals) {
					val = vals[i]
				}
				params[i] = Parameter{
					Key:   key,
					Value: String{Value: val},
				}
			}
		}

		comp := ComponentIdentifier{
			Name:       name,
			Type:       compType,
			Parameters: params,
		}

		// Validate the component
		err1 := validateComponentIdentifier(comp)

		// Verify deterministic behavior
		err2 := validateComponentIdentifier(comp)

		// Check determinism: errors must match
		if (err1 == nil) != (err2 == nil) {
			t.Errorf("Non-deterministic error behavior:\nComponent: %+v\nFirst:  %v\nSecond: %v",
				comp, err1, err2)
		}

		if err1 != nil && err2 != nil {
			// Error messages should be identical
			if err1.Error() != err2.Error() {
				t.Errorf("Non-deterministic error messages:\nComponent: %+v\nFirst:  %v\nSecond: %v",
					comp, err1, err2)
			}
		}

		// Validation logic checks
		if err1 == nil {
			// If validation succeeded, verify invariants
			if comp.Type == ComponentDerived {
				// Must be a valid derived component or validation failed
				if reservedDerivedComponents[comp.Name] {
					t.Errorf("Validation allowed reserved component: %q", comp.Name)
				}

				if !validDerivedComponents[comp.Name] && comp.Name != "" {
					t.Errorf("Validation allowed invalid derived component: %q", comp.Name)
				}

				// @query-param must have 'name' parameter
				if comp.Name == "@query-param" {
					hasName := false
					for _, param := range comp.Parameters {
						if param.Key == "name" {
							hasName = true
							break
						}
					}
					if !hasName {
						t.Errorf("Validation allowed @query-param without 'name' parameter")
					}
				}
			}

			// Check parameter mutual exclusivity
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

			if hasBS && hasSF {
				t.Errorf("Validation allowed mutually exclusive 'bs' and 'sf' parameters")
			}
			if hasBS && hasKey {
				t.Errorf("Validation allowed mutually exclusive 'bs' and 'key' parameters")
			}
		}
	})
}

// FuzzValidateDerivedComponentParameters tests derived component parameter validation
func FuzzValidateDerivedComponentParameters(f *testing.F) {
	seeds := []struct {
		name      string
		paramKeys []string
		paramVals []string
	}{
		// Valid
		{"@query-param", []string{"name"}, []string{"foo"}},
		{"@query-param", []string{"name", "sf"}, []string{"bar", "true"}},
		{"@method", nil, nil},
		{"@path", []string{"req"}, []string{"true"}},

		// Invalid - @query-param without name
		{"@query-param", nil, nil},
		{"@query-param", []string{"sf"}, []string{"true"}},
		{"@query-param", []string{"key"}, []string{"foo"}},

		// Other components (should all be valid)
		{"@method", []string{"random"}, []string{"param"}},
		{"@authority", []string{"a", "b"}, []string{"1", "2"}},
	}

	for _, seed := range seeds {
		paramKeysStr := ""
		paramValsStr := ""
		if len(seed.paramKeys) > 0 {
			for i, k := range seed.paramKeys {
				if i > 0 {
					paramKeysStr += ","
					paramValsStr += ","
				}
				paramKeysStr += k
				if i < len(seed.paramVals) {
					paramValsStr += seed.paramVals[i]
				}
			}
		}
		f.Add(seed.name, paramKeysStr, paramValsStr)
	}

	f.Fuzz(func(t *testing.T, name, paramKeysStr, paramValsStr string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("validateDerivedComponentParameters panicked on input:\nName: %q\nParams: %q=%q\nPanic: %v",
					name, paramKeysStr, paramValsStr, r)
			}
		}()

		// Parse parameters
		var params []Parameter
		if paramKeysStr != "" {
			keys := splitByComma(paramKeysStr)
			vals := splitByComma(paramValsStr)

			params = make([]Parameter, len(keys))
			for i, key := range keys {
				val := ""
				if i < len(vals) {
					val = vals[i]
				}
				params[i] = Parameter{
					Key:   key,
					Value: String{Value: val},
				}
			}
		}

		comp := ComponentIdentifier{
			Name:       name,
			Type:       ComponentDerived,
			Parameters: params,
		}

		err1 := validateDerivedComponentParameters(comp)
		err2 := validateDerivedComponentParameters(comp)

		if (err1 == nil) != (err2 == nil) {
			t.Errorf("Non-deterministic behavior for %q with params %q", name, paramKeysStr)
		}

		// Verify @query-param validation
		if name == "@query-param" {
			hasName := false
			for _, param := range params {
				if param.Key == "name" {
					hasName = true
					break
				}
			}

			if !hasName && err1 == nil {
				t.Errorf("validateDerivedComponentParameters allowed @query-param without 'name' parameter")
			}
			if hasName && err1 != nil {
				t.Errorf("validateDerivedComponentParameters rejected valid @query-param with 'name' parameter: %v", err1)
			}
		}
	})
}

// FuzzValidateParameterCombinations tests parameter combination validation
func FuzzValidateParameterCombinations(f *testing.F) {
	seeds := []struct {
		name      string
		paramKeys []string
	}{
		// Valid combinations
		{"content-type", []string{}},
		{"content-type", []string{"sf"}},
		{"content-type", []string{"bs"}},
		{"content-type", []string{"sf", "key"}},
		{"content-type", []string{"req", "tr"}},

		// Invalid - bs and sf
		{"content-type", []string{"bs", "sf"}},
		{"content-type", []string{"sf", "bs"}},
		{"content-type", []string{"bs", "sf", "key"}},

		// Invalid - bs and key
		{"content-type", []string{"bs", "key"}},
		{"content-type", []string{"key", "bs"}},
		{"content-type", []string{"bs", "key", "sf"}},

		// Invalid - key without sf (VR-037)
		{"content-type", []string{"key"}},

		// Edge cases - duplicates
		{"content-type", []string{"sf", "sf"}},
		{"content-type", []string{"bs", "bs"}},
		{"content-type", []string{"key", "key"}},

		// Edge cases - many parameters
		{"content-type", []string{"a", "b", "c", "d", "e", "f", "g"}},
		{"content-type", []string{"sf", "req", "tr", "name"}},
	}

	for _, seed := range seeds {
		paramKeysStr := ""
		for i, k := range seed.paramKeys {
			if i > 0 {
				paramKeysStr += ","
			}
			paramKeysStr += k
		}
		f.Add(seed.name, paramKeysStr)
	}

	f.Fuzz(func(t *testing.T, name, paramKeysStr string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("validateParameterCombinations panicked on input:\nName: %q\nParams: %q\nPanic: %v",
					name, paramKeysStr, r)
			}
		}()

		// Parse parameters
		var params []Parameter
		if paramKeysStr != "" {
			keys := splitByComma(paramKeysStr)
			params = make([]Parameter, len(keys))
			for i, key := range keys {
				params[i] = Parameter{
					Key:   key,
					Value: Boolean{Value: true},
				}
			}
		}

		comp := ComponentIdentifier{
			Name:       name,
			Type:       ComponentField,
			Parameters: params,
		}

		err1 := validateParameterCombinations(comp)
		err2 := validateParameterCombinations(comp)

		if (err1 == nil) != (err2 == nil) {
			t.Errorf("Non-deterministic behavior for %q with params %q", name, paramKeysStr)
		}

		// Verify mutual exclusivity validation
		hasBS := false
		hasSF := false
		hasKey := false
		for _, param := range params {
			switch param.Key {
			case "bs":
				hasBS = true
			case "sf":
				hasSF = true
			case "key":
				hasKey = true
			}
		}

		if hasBS && hasSF && err1 == nil {
			t.Errorf("validateParameterCombinations allowed mutually exclusive 'bs' and 'sf'")
		}
		if hasBS && hasKey && err1 == nil {
			t.Errorf("validateParameterCombinations allowed mutually exclusive 'bs' and 'key'")
		}
		if hasKey && !hasSF && err1 == nil {
			t.Errorf("validateParameterCombinations allowed 'key' without required 'sf'")
		}
		if !hasBS && !hasSF && !hasKey && err1 != nil {
			t.Errorf("validateParameterCombinations rejected valid parameter combination: %v", err1)
		}
		if hasBS && !hasSF && !hasKey && err1 != nil {
			t.Errorf("validateParameterCombinations rejected valid 'bs' only: %v", err1)
		}
		if hasSF && !hasBS && err1 != nil {
			t.Errorf("validateParameterCombinations rejected valid 'sf' combination: %v", err1)
		}
		if hasKey && hasSF && !hasBS && err1 != nil {
			t.Errorf("validateParameterCombinations rejected valid 'key' with 'sf' combination: %v", err1)
		}
	})
}

// splitByComma is a helper function to split comma-separated strings
func splitByComma(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	current := ""
	for _, ch := range s {
		if ch == ',' {
			result = append(result, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" || len(result) > 0 {
		result = append(result, current)
	}
	return result
}
