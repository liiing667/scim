package filter

import (
	"fmt"

	"github.com/elimity-com/scim/schema"
	"github.com/scim2/filter-parser/v2"
)

// resolvedPath is the result of resolving an attribute path against a set of reference schemas. It is the single
// source of truth shared by filter validation (Validate) and filter evaluation (PassesFilter), so that an expression
// can never be accepted during validation but fail to be resolved during evaluation (or vice versa).
type resolvedPath struct {
	// ref is the schema (core or extension) the attribute path belongs to.
	ref schema.Schema
	// attr is the resolved top-level attribute.
	attr schema.CoreAttribute
	// sub is the resolved sub-attribute. It is the zero value when no sub-attribute was specified.
	sub schema.CoreAttribute
	// hasSub reports whether the attribute path specified a sub-attribute.
	hasSub bool
}

// resolveAttributePath resolves the given attribute path against the given reference schemas. It fails closed on any
// unknown attribute, illegal sub-path or URI that does not match a known schema.
func resolveAttributePath(refs []schema.Schema, attrPath filter.AttributePath) (resolvedPath, error) {
	uri := attrPath.URI()

	var (
		attr schema.CoreAttribute
		ref  schema.Schema
		ok   bool
	)
	for _, candidate := range refs {
		// A given URI prefix must match the schema id exactly. An attribute path without a URI prefix may be
		// resolved against any of the reference schemas.
		if uri != "" && candidate.ID != uri {
			continue
		}
		attr, ok = candidate.Attributes.ContainsAttribute(attrPath.AttributeName)
		if ok {
			ref = candidate
			break
		}
	}
	if !ok {
		if uri != "" {
			return resolvedPath{}, fmt.Errorf(
				"the reference schemas do not have an attribute %q with the uri prefix: %s",
				attrPath.AttributeName,
				uri,
			)
		}
		return resolvedPath{}, fmt.Errorf(
			"the reference schemas do not have an attribute with the name: %s",
			attrPath.AttributeName,
		)
	}

	resolved := resolvedPath{ref: ref, attr: attr}

	// e.g. name.givenName
	//           ^________
	if subAttrName := attrPath.SubAttributeName(); subAttrName != "" {
		sub, err := resolveSubAttribute(attr, subAttrName)
		if err != nil {
			return resolvedPath{}, err
		}
		resolved.sub = sub
		resolved.hasSub = true
	}
	return resolved, nil
}

// compareAttribute returns the attribute the filter expression should be compared against: the sub-attribute when
// the path specifies one, otherwise the top-level attribute.
func (r resolvedPath) compareAttribute() schema.CoreAttribute {
	if r.hasSub {
		return r.sub
	}
	return r.attr
}

// resolveSubAttribute resolves a sub-attribute (e.g. the trailing displayName in members[value eq "0"].displayName)
// against the given attribute. It fails closed when the attribute has no sub-attributes or no matching sub-attribute.
func resolveSubAttribute(attr schema.CoreAttribute, subAttrName string) (schema.CoreAttribute, error) {
	if !attr.HasSubAttributes() {
		return schema.CoreAttribute{}, fmt.Errorf(
			"the attribute %q has no sub-attributes, but got sub-attribute: %s",
			attr.Name(),
			subAttrName,
		)
	}
	sub, ok := attr.SubAttributes().ContainsAttribute(subAttrName)
	if !ok {
		return schema.CoreAttribute{}, fmt.Errorf(
			"the attribute %q has no sub-attribute named: %s",
			attr.Name(),
			subAttrName,
		)
	}
	return sub, nil
}

// filterableAttributes returns the attributes against which a value filter on the resolved (multi-valued) attribute
// has to be resolved and validated.
func (r resolvedPath) filterableAttributes() schema.Attributes {
	return MultiValuedFilterAttributes(r.attr)
}

// nestedRefs returns the reference schemas to use when resolving or evaluating the value filter nested inside a
// value path on the resolved attribute.
func (r resolvedPath) nestedRefs() []schema.Schema {
	return []schema.Schema{{
		ID:         r.ref.ID,
		Attributes: r.filterableAttributes(),
	}}
}
