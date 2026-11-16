package filter

import (
	"fmt"

	scimfilter "github.com/scim2/filter-parser/v2"
)

const (
	// maxFilterDepth is the maximum allowed nesting depth of a filter expression.
	// Every parenthesised group, "not" expression and value path counts as one level.
	maxFilterDepth = 100
	// maxFilterNodes is the maximum number of structural nodes a filter expression may contain.
	// Logical operators, "not" expressions and value paths each count as one node; leaf
	// attribute expressions are bounded implicitly because every structural node references
	// at least one of them.
	maxFilterNodes = 10_000
)

// FilterComplexityError indicates that a filter expression exceeds the nesting depth or node
// budget enforced by this package. It is returned before the expression is evaluated, so callers
// can distinguish it from a resource that merely does not match and map it to a 400 SCIM error.
type FilterComplexityError struct {
	// Kind is "depth" when the nesting depth budget was exceeded, "nodes" otherwise.
	Kind string
	// Limit is the configured budget that was exceeded.
	Limit int
	// Actual is the measured value that exceeded the limit.
	Actual int
}

func (e *FilterComplexityError) Error() string {
	return fmt.Sprintf(
		"filter %s %d exceeds the maximum allowed %s of %d",
		e.Kind, e.Actual, e.Kind, e.Limit,
	)
}

// CheckRawFilterBudget enforces the complexity limits on a raw filter or attribute path before
// the recursive parser is invoked. The external parser cannot recover from excessive nesting
// (it overflows the goroutine stack), so the budget has to be checked up front.
//
// For syntactically valid expressions the counted values match the AST metrics used in
// checkExpressionBudget. Malformed expressions may yield approximate counts, but they will
// either be rejected here or fail with a regular parse error afterwards.
func CheckRawFilterBudget(raw []byte) error {
	var (
		depth    int
		maxDepth int
		nodes    int
	)
	for i := 0; i < len(raw); {
		switch b := raw[i]; {
		case b == '"':
			// Skip string literals, including escaped characters, so brackets and
			// keywords inside a compare value are not counted.
			i++
			for i < len(raw) {
				if raw[i] == '\\' {
					i += 2
					continue
				}
				if raw[i] == '"' {
					i++
					break
				}
				i++
			}
		case b == '(' || b == '[':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
			if b == '[' {
				// A value path contributes a node in addition to the nesting level.
				nodes++
			}
			i++
		case b == ')' || b == ']':
			if depth > 0 {
				depth--
			}
			i++
		case isWordStart(b):
			start := i
			i++
			for i < len(raw) && isWordChar(raw[i]) {
				i++
			}
			if isLogicalKeyword(raw[start:i]) {
				nodes++
			}
		default:
			i++
		}
	}
	if maxDepth > maxFilterDepth {
		return &FilterComplexityError{Kind: "depth", Limit: maxFilterDepth, Actual: maxDepth}
	}
	if nodes > maxFilterNodes {
		return &FilterComplexityError{Kind: "nodes", Limit: maxFilterNodes, Actual: nodes}
	}
	return nil
}

func isWordStart(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b == '_'
}

func isWordChar(b byte) bool {
	return isWordStart(b) || b >= '0' && b <= '9' || b == '-'
}

func isLogicalKeyword(word []byte) bool {
	if len(word) != 3 {
		return false
	}
	w := toLower(word)
	return string(w) == "and" || string(w) == "or" || string(w) == "not"
}

func toLower(word []byte) []byte {
	lower := make([]byte, len(word))
	for i, b := range word {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		lower[i] = b
	}
	return lower
}

// checkExpressionBudget enforces the complexity limits on a parsed expression. It backs up the
// raw pre-scan for expressions constructed directly via NewFilterValidator and guarantees that
// every expression accepted by this package stays within the same budget.
func checkExpressionBudget(exp scimfilter.Expression) error {
	actualDepth, actualNodes, err := expressionSize(exp)
	if err != nil {
		return err
	}
	if actualDepth > maxFilterDepth {
		return &FilterComplexityError{Kind: "depth", Limit: maxFilterDepth, Actual: actualDepth}
	}
	if actualNodes > maxFilterNodes {
		return &FilterComplexityError{Kind: "nodes", Limit: maxFilterNodes, Actual: actualNodes}
	}
	return nil
}

// expressionSize returns the nesting depth and the number of nodes of the expression,
// traversing it iteratively so that the budget check itself cannot overflow the stack.
//
// The depth follows the same metric as CheckRawFilterBudget: the number of nested groups,
// i.e. parentheses (including those introduced by "not") and value path brackets. Parentheses
// that only group an expression do not create an AST node, so the measured AST depth can be
// lower than the raw bracket depth for such inputs - the raw pre-scan is always the stricter
// upper bound. "not" expressions and value paths do create nodes.
func expressionSize(root scimfilter.Expression) (int, int, error) {
	type frame struct {
		exp        scimfilter.Expression
		groupDepth int
	}
	var (
		stack    = []frame{{root, 0}}
		maxDepth int
		nodes    int
	)
	for len(stack) > 0 {
		last := len(stack) - 1
		current := stack[last]
		stack = stack[:last]

		switch current.exp.(type) {
		case *scimfilter.AttributeExpression:
			// Leaf attribute expressions are not counted. The budgets target the structural
			// nodes that drive parser and evaluator recursion.
		default:
			nodes++
		}
		if nodes > maxFilterNodes {
			return 0, nodes, &FilterComplexityError{
				Kind: "nodes", Limit: maxFilterNodes, Actual: nodes,
			}
		}
		depth := current.groupDepth
		switch current.exp.(type) {
		case *scimfilter.NotExpression, *scimfilter.ValuePath:
			depth++
		}
		if depth > maxDepth {
			maxDepth = depth
		}
		if depth > maxFilterDepth {
			return maxDepth, nodes, &FilterComplexityError{
				Kind: "depth", Limit: maxFilterDepth, Actual: depth,
			}
		}

		switch e := current.exp.(type) {
		case *scimfilter.ValuePath:
			stack = append(stack, frame{e.ValueFilter, depth})
		case *scimfilter.AttributeExpression:
			// Leaf node.
		case *scimfilter.LogicalExpression:
			stack = append(stack,
				frame{e.Left, current.groupDepth},
				frame{e.Right, current.groupDepth},
			)
		case *scimfilter.NotExpression:
			stack = append(stack, frame{e.Expression, depth})
		default:
			return 0, 0, fmt.Errorf("unknown expression type: %T", current.exp)
		}
	}
	return maxDepth, nodes, nil
}
