package filter_test

import (
	"testing"

	"github.com/elimity-com/scim/filter"
	"github.com/elimity-com/scim/schema"
)

const (
	coreUserURI   = "urn:ietf:params:scim:schemas:core:2.0:User"
	enterpriseURI = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
)

func boundaryValidator(t *testing.T, expr string) filter.Validator {
	t.Helper()
	validator, err := filter.NewValidator(expr, schema.CoreUserSchema(), schema.ExtensionEnterpriseUser())
	if err != nil {
		t.Fatalf("failed to parse filter %q: %v", expr, err)
	}
	return validator
}

// TestValidator_Validate_FailClosed makes sure unknown attributes, illegal sub-paths and incompatible operators are
// rejected during validation instead of being accepted and silently failing to match during evaluation.
func TestValidator_Validate_FailClosed(t *testing.T) {
	for _, expr := range []string{
		// Unknown top-level attribute.
		`bogus eq "x"`,
		// Unknown attribute inside a value path value filter.
		`emails[type eq "work" and bogus co "x"]`,
		// Unknown top-level attribute of a value path.
		`bogus[attr eq "x"]`,
		// Illegal sub-path on a simple attribute.
		`userName.bogus eq "x"`,
		// Unknown sub-attribute on a complex attribute.
		`name.bogus eq "x"`,
		// Unknown sub-attribute inside a value path value filter.
		`emails[bogus eq "x"]`,
		// Ordering operators are not supported on boolean attributes.
		`active gt true`,
		// The same rule must be enforced on sub-attributes inside a value path.
		`emails[primary gt true]`,
		// A value path can only target a multi-valued attribute.
		`name[familyName eq "x"]`,
		// An extension uri prefix must not resolve against a core attribute.
		enterpriseURI + `:userName eq "x"`,
		// A core uri prefix must not resolve against an extension attribute.
		coreUserURI + `:employeeNumber eq "x"`,
		// Unknown extension schema uri.
		`urn:ietf:params:scim:schemas:extension:bogus:2.0:User:userName eq "x"`,
		// Unknown attribute must still be rejected when wrapped in a logical/not expression.
		`userName eq "x" and bogus pr`,
		`not (bogus pr)`,
	} {
		validator := boundaryValidator(t, expr)
		if err := validator.Validate(); err == nil {
			t.Errorf("filter %q should fail validation", expr)
		} else {
			t.Logf("filter %q rejected: %v", expr, err)
		}
	}
}

// TestValidator_Validate_OrderingOperatorOnBinarySubType covers the binary type, which the core User schema does not
// expose directly.
func TestValidator_Validate_OrderingOperatorOnBinarySubType(t *testing.T) {
	ref := schema.Schema{
		Attributes: []schema.CoreAttribute{
			schema.SimpleCoreAttribute(schema.SimpleBinaryParams(schema.BinaryParams{
				Name: "bin",
			})),
		},
	}
	for _, op := range []string{"gt", "lt", "ge", "le"} {
		expr := `bin ` + op + ` "aGVsbG8="`
		validator, err := filter.NewValidator(expr, ref)
		if err != nil {
			t.Fatalf("failed to parse filter %q: %v", expr, err)
		}
		if err := validator.Validate(); err == nil {
			t.Errorf("filter %q should fail validation", expr)
		}
	}
}

// TestPathValidator_Boundaries covers PATCH paths, which share the attribute resolution with filter validation.
func TestPathValidator_Boundaries(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, path := range []string{
			`emails`,
			`emails[type eq "work"]`,
			`emails[type eq "work"].display`,
			`name.familyName`,
			coreUserURI + `:emails[type eq "work"]`,
			enterpriseURI + `:employeeNumber`,
			enterpriseURI + `:manager.displayName`,
		} {
			validator, err := filter.NewPathValidator(path, schema.CoreUserSchema(), schema.ExtensionEnterpriseUser())
			if err != nil {
				t.Fatalf("failed to parse path %q: %v", path, err)
			}
			if err := validator.Validate(); err != nil {
				t.Errorf("path %q should be valid: %v", path, err)
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, path := range []string{
			// Unknown top-level attribute.
			`bogus`,
			// Illegal sub-path.
			`userName.bogus`,
			`name.bogus`,
			// Unknown attribute inside the value expression.
			`emails[bogus eq "work"]`,
			// Incompatible operator on a boolean sub-attribute inside the value expression.
			`emails[primary gt true]`,
			// Trailing sub-attribute that does not exist.
			`emails[type eq "work"].bogus`,
			// Extension uri prefix resolving against a core attribute.
			enterpriseURI + `:userName`,
			// Core uri prefix resolving against an extension attribute.
			coreUserURI + `:employeeNumber`,
		} {
			validator, err := filter.NewPathValidator(path, schema.CoreUserSchema(), schema.ExtensionEnterpriseUser())
			if err != nil {
				t.Fatalf("failed to parse path %q: %v", path, err)
			}
			if err := validator.Validate(); err == nil {
				t.Errorf("path %q should fail validation", path)
			}
		}
	})
}

// TestValidator_Validate_Accepted keeps the valid multi-valued and extension schema filters working.
func TestValidator_Validate_Accepted(t *testing.T) {
	for _, expr := range []string{
		// Simple attribute expression.
		`userName eq "john"`,
		// Sub-attribute expression.
		`name.familyName co "d"`,
		// Multi-valued complex attribute value path.
		`emails[type eq "work"]`,
		`emails[type eq "work" and value co "@example.com"]`,
		`emails[type eq "work"] or ims[type eq "xmpp"]`,
		// Value path combined with an outer expression.
		`userName eq "Employee" and emails[type eq "work" and value co "@example.com"]`,
		// Negated value filter.
		`emails[not (type eq "home")]`,
		// Explicit core schema uri prefix.
		coreUserURI + `:userName sw "a"`,
		coreUserURI + `:name.familyName co "d"`,
		// Extension schema uri prefix on extension attributes, including a sub-attribute.
		enterpriseURI + `:organization eq "Elimity"`,
		enterpriseURI + `:manager.displayName eq "di-wu"`,
		// Present operator.
		`title pr`,
	} {
		validator := boundaryValidator(t, expr)
		if err := validator.Validate(); err != nil {
			t.Errorf("filter %q should be valid: %v", expr, err)
		}
	}
}

// TestValidator_ValidationAndEvaluationAgree asserts that validation and evaluation resolve attributes through the
// same code path: a filter that fails validation never silently fails to match, and valid filters keep matching.
func TestValidator_ValidationAndEvaluationAgree(t *testing.T) {
	resource := map[string]interface{}{
		"userName": "john",
		"active":   true,
		"name": map[string]interface{}{
			"familyName": "doe",
		},
		"emails": []interface{}{
			map[string]interface{}{
				"value":   "john@example.com",
				"type":    "work",
				"primary": true,
			},
		},
		enterpriseURI + ":organization": "Elimity",
		enterpriseURI + ":manager": map[string]interface{}{
			"displayName": "di-wu",
		},
	}

	t.Run("invalid filters are rejected and never match", func(t *testing.T) {
		for _, expr := range []string{
			`emails[type eq "work" and bogus co "x"]`,
			`bogus[attr eq "x"]`,
			`emails[primary gt true]`,
			enterpriseURI + `:userName eq "john"`,
			`name[familyName eq "doe"]`,
		} {
			validator := boundaryValidator(t, expr)
			if err := validator.Validate(); err == nil {
				t.Errorf("filter %q should fail validation", expr)
				continue
			}
			if err := validator.PassesFilter(resource); err == nil {
				t.Errorf("filter %q should not evaluate against the resource", expr)
			}
		}
	})

	t.Run("valid filters keep matching", func(t *testing.T) {
		for _, expr := range []string{
			`userName eq "john"`,
			`name.familyName co "o"`,
			`emails[type eq "work"]`,
			`emails[type eq "work" and value co "@example.com"]`,
			`active eq true`,
			enterpriseURI + `:organization eq "Elimity"`,
			// Extension attributes must stay resolvable without an explicit uri prefix.
			`organization eq "Elimity"`,
			`manager.displayName eq "di-wu"`,
		} {
			validator := boundaryValidator(t, expr)
			if err := validator.Validate(); err != nil {
				t.Fatalf("filter %q should be valid: %v", expr, err)
			}
			if err := validator.PassesFilter(resource); err != nil {
				t.Errorf("filter %q should match the resource: %v", expr, err)
			}
		}
	})

	t.Run("valid non-matching filters still evaluate to a mismatch", func(t *testing.T) {
		for _, expr := range []string{
			`userName eq "jane"`,
			`emails[type eq "home"]`,
			enterpriseURI + `:organization eq "Other"`,
		} {
			validator := boundaryValidator(t, expr)
			if err := validator.Validate(); err != nil {
				t.Fatalf("filter %q should be valid: %v", expr, err)
			}
			if err := validator.PassesFilter(resource); err == nil {
				t.Errorf("filter %q should not match the resource", expr)
			}
		}
	})

	t.Run("sub-attribute of multi-valued complex attribute", func(t *testing.T) {
		validator := boundaryValidator(t, `emails.value co "@example.com"`)
		matching := map[string]interface{}{
			"emails": []interface{}{
				map[string]interface{}{"value": "a@example.com", "type": "work"},
			},
		}
		if err := validator.PassesFilter(matching); err != nil {
			t.Errorf("expected a match: %v", err)
		}

		nonMatching := map[string]interface{}{
			"emails": []interface{}{
				map[string]interface{}{"value": "a@other.org", "type": "work"},
			},
		}
		if err := validator.PassesFilter(nonMatching); err == nil {
			t.Error("expected no match")
		}

		present := boundaryValidator(t, `emails.value pr`)
		if err := present.PassesFilter(matching); err != nil {
			t.Errorf("expected pr to match: %v", err)
		}
	})
}
