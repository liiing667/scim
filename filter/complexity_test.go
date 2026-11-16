package filter_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/elimity-com/scim/filter"
	"github.com/elimity-com/scim/schema"
	scimfilter "github.com/scim2/filter-parser/v2"
)

func parseExpression(t *testing.T, raw string) scimfilter.Expression {
	t.Helper()
	exp, err := scimfilter.ParseFilter([]byte(raw))
	if err != nil {
		t.Fatalf("failed to parse %q: %v", raw, err)
	}
	return exp
}

const (
	testMaxDepth = 100
	testMaxNodes = 10_000
)

// nestedNotFilter returns a filter with n nested "not" groups, e.g. n=3 -> not(not(not(userName eq "a"))).
func nestedNotFilter(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("not(")
	}
	b.WriteString(`userName eq "a"`)
	for i := 0; i < n; i++ {
		b.WriteByte(')')
	}
	return b.String()
}

// chainedFilter returns n attribute expressions joined by the given logical operator.
func chainedFilter(n int, operator string) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = `userName eq "a"`
	}
	return strings.Join(parts, " "+operator+" ")
}

func TestNewValidator_FilterComplexityDepth(t *testing.T) {
	for _, n := range []int{testMaxDepth, testMaxDepth + 1, 1000, 50_000} {
		_, err := filter.NewValidator(nestedNotFilter(n), schema.CoreUserSchema())
		if n <= testMaxDepth {
			if err != nil {
				t.Fatalf("depth %d should be accepted, got: %v", n, err)
			}
			continue
		}
		var complexityErr *filter.FilterComplexityError
		if !errors.As(err, &complexityErr) {
			t.Fatalf("depth %d: expected FilterComplexityError, got: %v", n, err)
		}
		if complexityErr.Kind != "depth" {
			t.Errorf("depth %d: expected kind %q, got %q", n, "depth", complexityErr.Kind)
		}
		if complexityErr.Limit != testMaxDepth || complexityErr.Actual <= testMaxDepth {
			t.Errorf("depth %d: unexpected limits: %+v", n, complexityErr)
		}
	}
}

func TestNewValidator_FilterComplexityNodes(t *testing.T) {
	// A flat "and" chain stays at nesting depth 1, so the node budget is hit without
	// triggering the depth budget. (n+1) leaves joined by n "and" operators plus one
	// wrapping "not" give testMaxNodes+1 structural nodes.
	n := testMaxNodes
	leaves := make([]string, n+1)
	for i := range leaves {
		leaves[i] = `userName eq "a"`
	}
	raw := "not(" + strings.Join(leaves, " and ") + ")"
	_, err := filter.NewValidator(raw, schema.CoreUserSchema())
	var complexityErr *filter.FilterComplexityError
	if !errors.As(err, &complexityErr) {
		t.Fatalf("expected FilterComplexityError, got: %v", err)
	}
	if complexityErr.Kind != "nodes" {
		t.Errorf("expected kind %q, got %q", "nodes", complexityErr.Kind)
	}
	if complexityErr.Limit != testMaxNodes || complexityErr.Actual <= testMaxNodes {
		t.Errorf("unexpected limits: %+v", complexityErr)
	}
}

func TestNewValidator_NodeBudgetExactLimitAccepted(t *testing.T) {
	// testMaxNodes leaves joined by testMaxNodes-1 "and" operators yield exactly
	// testMaxNodes structural nodes at nesting depth 1: the limit is inclusive.
	leaves := make([]string, testMaxNodes)
	for i := range leaves {
		leaves[i] = `userName eq "a"`
	}
	if _, err := filter.NewValidator(strings.Join(leaves, " and "), schema.CoreUserSchema()); err != nil {
		t.Fatalf("a filter at exactly the node limit should be accepted, got: %v", err)
	}
}

func TestNewValidator_NodeBudgetWithinLimit(t *testing.T) {
	// 2n-1 nodes, well below the budget: the parser and validator must accept it.
	n := 100
	validator, err := filter.NewValidator(chainedFilter(n, "or"), schema.CoreUserSchema())
	if err != nil {
		t.Fatalf("filter within budget should be accepted, got: %v", err)
	}
	if err := validator.Validate(); err != nil {
		t.Errorf("Validate should pass: %v", err)
	}
}

func TestPassesFilter_ComplexityEnforcedBeforeEvaluation(t *testing.T) {
	// A deeply nested filter must never reach the recursive evaluation logic.
	_, err := filter.NewValidator(nestedNotFilter(testMaxDepth+1), schema.CoreUserSchema())
	if err == nil {
		t.Fatal("expected the oversized filter to be rejected at construction")
	}
	var complexityErr *filter.FilterComplexityError
	if !errors.As(err, &complexityErr) {
		t.Fatalf("expected FilterComplexityError, got: %v", err)
	}

	// A validator built directly from an expression is checked again at evaluation time,
	// and the complexity error stays distinguishable from a non-matching resource.
	validator := filter.NewFilterValidator(
		parseExpression(t, nestedNotFilter(testMaxDepth+1)),
		schema.CoreUserSchema(),
	)
	err = validator.PassesFilter(map[string]interface{}{"userName": "a"})
	if !errors.As(err, &complexityErr) {
		t.Fatalf("PassesFilter should return FilterComplexityError before evaluation, got: %v", err)
	}
	err = validator.Validate()
	if !errors.As(err, &complexityErr) {
		t.Fatalf("Validate should return FilterComplexityError, got: %v", err)
	}
}

func TestCheckRawFilterBudget_IgnoresStringLiterals(t *testing.T) {
	// Brackets and keywords inside compare values must not be counted.
	raw := []byte(`userName eq "not(and(or([" and displayName co ")"`)
	if err := filter.CheckRawFilterBudget(raw); err != nil {
		t.Fatalf("string contents must be ignored, got: %v", err)
	}
}

func TestNewPathValidator_FilterComplexity(t *testing.T) {
	deep := "emails" + strings.Repeat("[not(", testMaxDepth+1) +
		`value eq "work"` + strings.Repeat(")]", testMaxDepth+1)
	_, err := filter.NewPathValidator(deep, schema.CoreUserSchema())
	var complexityErr *filter.FilterComplexityError
	if !errors.As(err, &complexityErr) {
		t.Fatalf("expected FilterComplexityError for deep path, got: %v", err)
	}

	// A value filter on a multi-valued attribute stays within the normal limits.
	validator, err := filter.NewPathValidator(`emails[type eq "work"]`, schema.CoreUserSchema())
	if err != nil {
		t.Fatalf("valid path should be accepted, got: %v", err)
	}
	if err := validator.Validate(); err != nil {
		t.Errorf("Validate should pass: %v", err)
	}
}

func TestComplexityError_DoesNotChangeMatchingSemantics(t *testing.T) {
	// The budget enforcement must not alter the result of ordinary, in-budget filters.
	validator, err := filter.NewValidator(
		`not(emails[type eq "work"]) and (userName eq "john" or userName eq "jane")`,
		schema.CoreUserSchema(),
	)
	if err != nil {
		t.Fatal(err)
	}
	resource := map[string]interface{}{"userName": "john"}
	if err := validator.PassesFilter(resource); err != nil {
		t.Errorf("matching resource should pass: %v", err)
	}
	if err := validator.PassesFilter(map[string]interface{}{"userName": "bob"}); err == nil {
		t.Error("non-matching resource should not pass")
	}
}
