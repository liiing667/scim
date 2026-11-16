package filter

import (
	"fmt"

	"github.com/elimity-com/scim/schema"
	"github.com/scim2/filter-parser/v2"
)

// knownOperators contains all compare operators defined by RFC 7644 Section 3.4.2.2.
var knownOperators = map[filter.CompareOperator]struct{}{
	filter.EQ: {},
	filter.NE: {},
	filter.CO: {},
	filter.SW: {},
	filter.EW: {},
	filter.GT: {},
	filter.LT: {},
	filter.GE: {},
	filter.LE: {},
	filter.PR: {},
}

// validateExpression checks whether the given expression is a valid expression within the given reference schemas.
// Attribute path resolution is shared with PassesFilter through resolveAttributePath, so validation and evaluation
// always agree on which attribute an expression targets.
func validateExpression(refs []schema.Schema, e filter.Expression) error {
	switch e := e.(type) {
	case *filter.ValuePath:
		resolved, err := resolveAttributePath(refs, e.AttributePath)
		if err != nil {
			return err
		}
		// A value path filter targets the elements of a multi-valued attribute.
		if !resolved.attr.MultiValued() {
			return fmt.Errorf(
				"value path filters can only be applied to multi-valued attributes, but %q is single-valued",
				resolved.attr.Name(),
			)
		}
		if err := validateExpression(resolved.nestedRefs(), e.ValueFilter); err != nil {
			return err
		}
		return nil
	case *filter.AttributeExpression:
		resolved, err := resolveAttributePath(refs, e.AttributePath)
		if err != nil {
			return err
		}
		if err := validateOperator(resolved.compareAttribute(), e.Operator); err != nil {
			return err
		}
		return nil
	case *filter.LogicalExpression:
		if err := validateExpression(refs, e.Left); err != nil {
			return err
		}
		if err := validateExpression(refs, e.Right); err != nil {
			return err
		}
		return nil
	case *filter.NotExpression:
		if err := validateExpression(refs, e.Expression); err != nil {
			return err
		}
		return nil
	default:
		panic(fmt.Sprintf("unknown expression type: %s", e))
	}
}

// validateOperator checks whether the given operator is compatible with the attribute type.
// Per RFC 7644 Section 3.4.2.2, boolean and binary attributes do not support gt, lt, ge, or le. Unknown operators
// are rejected as well instead of being left to panic during evaluation.
func validateOperator(attr schema.CoreAttribute, op filter.CompareOperator) error {
	if _, ok := knownOperators[op]; !ok {
		return fmt.Errorf("unknown filter operator: %s", op)
	}
	switch attr.AttributeType() {
	case "boolean", "binary":
		switch op {
		case filter.GT, filter.LT, filter.GE, filter.LE:
			return fmt.Errorf("operator %q is not supported for %s attributes", op, attr.AttributeType())
		}
	}
	return nil
}

// Validator represents a filter validator.
type Validator struct {
	filter     filter.Expression
	schema     schema.Schema
	extensions []schema.Schema
}

// references returns the core schema followed by its extension schemas.
func (v Validator) references() []schema.Schema {
	return append([]schema.Schema{v.schema}, v.extensions...)
}

// NewFilterValidator constructs a new filter validator.
func NewFilterValidator(exp filter.Expression, s schema.Schema, exts ...schema.Schema) Validator {
	return Validator{
		filter:     exp,
		schema:     s,
		extensions: exts,
	}
}

// NewValidator constructs a new filter validator.
func NewValidator(exp string, s schema.Schema, exts ...schema.Schema) (Validator, error) {
	e, err := filter.ParseFilter([]byte(exp))
	if err != nil {
		return Validator{}, err
	}
	return Validator{
		filter:     e,
		schema:     s,
		extensions: exts,
	}, nil
}

// GetFilter returns the filter contained within the validator.
func (v Validator) GetFilter() filter.Expression {
	return v.filter
}

// PassesFilter checks whether given resources passes the filter.
func (v Validator) PassesFilter(resource map[string]interface{}) error {
	switch e := v.filter.(type) {
	case *filter.ValuePath:
		resolved, err := resolveAttributePath(v.references(), e.AttributePath)
		if err != nil {
			return err
		}
		attr := resolved.attr
		if !attr.MultiValued() {
			return fmt.Errorf("value path filters can only be applied to multi-valued attributes")
		}

		value, err := attributeValue(resource, resolved)
		if err != nil {
			return err
		}
		valueFilter := Validator{
			filter: e.ValueFilter,
			schema: resolved.nestedRefs()[0],
		}
		switch value := value.(type) {
		case []interface{}:
			for _, a := range value {
				attr, ok := a.(map[string]interface{})
				if !ok {
					return fmt.Errorf("the target is not a complex attribute")
				}
				if err := valueFilter.PassesFilter(attr); err == nil {
					// Found an attribute that passed the value filter.
					return nil
				}
			}
		default:
			panic(fmt.Sprintf("given value is not a []interface{}: %v", value))
		}
		return fmt.Errorf("the resource does not pass the filter")
	case *filter.AttributeExpression:
		resolved, err := resolveAttributePath(v.references(), e.AttributePath)
		if err != nil {
			return err
		}
		attr := resolved.attr

		value, err := attributeValue(resource, resolved)
		if err != nil {
			return err
		}

		// cmpAttr is the attribute the filter expression gets compared against.
		cmpAttr := resolved.compareAttribute()

		if !attr.MultiValued() {
			if resolved.hasSub {
				complexValue, ok := value.(map[string]interface{})
				if !ok {
					return fmt.Errorf("the target is not a complex attribute")
				}
				value, ok = complexValue[cmpAttr.Name()]
				if !ok {
					return fmt.Errorf("the resource does contain the attribute specified in the filter")
				}
			}

			// If the attribute has a non-empty or non-null value or if it contains a non-empty node for complex
			// attributes, there is a match.
			if e.Operator == filter.PR {
				// We already found a value.
				return nil
			}

			cmp, err := createCompareFunction(e, cmpAttr)
			if err != nil {
				return err
			}
			if err := cmp(value); err != nil {
				return fmt.Errorf("the resource does not pass the filter: %s", err)
			}
			return nil
		}

		if resolved.hasSub {
			complexValues, ok := value.([]interface{})
			if !ok {
				panic(fmt.Sprintf("given value is not a []interface{}: %v", value))
			}
			values := make([]interface{}, 0, len(complexValues))
			for _, complexValue := range complexValues {
				entry, ok := complexValue.(map[string]interface{})
				if !ok {
					return fmt.Errorf("the target is not a complex attribute")
				}
				subValue, ok := entry[cmpAttr.Name()]
				if !ok {
					return fmt.Errorf("the resource does contain the attribute specified in the filter")
				}
				values = append(values, subValue)
			}
			value = values
		}

		// If the attribute has a non-empty or non-null value or if it contains a non-empty node for complex
		// attributes, there is a match.
		if e.Operator == filter.PR {
			// We already found a value.
			return nil
		}

		cmp, err := createCompareFunction(e, cmpAttr)
		if err != nil {
			return err
		}

		switch value := value.(type) {
		case []interface{}:
			var err error
			for _, v := range value {
				if err = cmp(v); err == nil {
					return nil
				}
			}
			return fmt.Errorf("the resource does not pass the filter: %s", err)
		default:
			panic(fmt.Sprintf("given value is not a []interface{}: %v", value))
		}
	case *filter.LogicalExpression:
		switch e.Operator {
		case filter.AND:
			leftValidator := Validator{
				e.Left,
				v.schema,
				v.extensions,
			}
			if err := leftValidator.PassesFilter(resource); err != nil {
				return err
			}
			rightValidator := Validator{
				e.Right,
				v.schema,
				v.extensions,
			}
			return rightValidator.PassesFilter(resource)
		case filter.OR:
			leftValidator := Validator{
				e.Left,
				v.schema,
				v.extensions,
			}
			if err := leftValidator.PassesFilter(resource); err == nil {
				return nil
			}
			rightValidator := Validator{
				e.Right,
				v.schema,
				v.extensions,
			}
			return rightValidator.PassesFilter(resource)
		}
		return fmt.Errorf("the resource does not pass the filter")
	case *filter.NotExpression:
		validator := Validator{
			e.Expression,
			v.schema,
			v.extensions,
		}
		if err := validator.PassesFilter(resource); err != nil {
			return nil
		}
		return fmt.Errorf("the resource does not pass the filter")
	default:
		panic(fmt.Sprintf("unknown expression type: %s", e))
	}
}

// attributeValue looks up the value of the resolved top-level attribute in the resource. Extension attributes may be
// stored with their schema uri as prefix, so that key is tried as a fallback.
func attributeValue(resource map[string]interface{}, resolved resolvedPath) (interface{}, error) {
	if value, ok := resource[resolved.attr.Name()]; ok {
		return value, nil
	}
	if value, ok := resource[fmt.Sprintf("%s:%s", resolved.ref.ID, resolved.attr.Name())]; ok {
		return value, nil
	}
	return nil, fmt.Errorf("the resource does contain the attribute specified in the filter")
}

// Validate checks whether the expression is a valid path within the given reference schemas.
func (v Validator) Validate() error {
	return validateExpression(v.references(), v.filter)
}
