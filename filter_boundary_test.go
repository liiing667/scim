package scim_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/elimity-com/scim/errors"
)

// Test_User_Filter_RejectsInvalidFilters makes sure the server fails closed (400 invalidFilter) on unknown
// attributes, illegal sub-paths and incompatible operators instead of accepting the filter and silently matching
// nothing during evaluation.
func Test_User_Filter_RejectsInvalidFilters(t *testing.T) {
	s := newTestServerForFilter(t)

	for _, filter := range []string{
		// Unknown attribute inside a value path value filter.
		`emails[type eq "work" and bogus co "x"]`,
		// Unknown top-level attribute of a value path.
		`bogus[attr eq "x"]`,
		// Illegal sub-path on a simple attribute.
		`userName.bogus eq "x"`,
		// Ordering operator on a boolean attribute.
		`active gt true`,
		// Value path on a single-valued complex attribute.
		`name[familyName eq "doe"]`,
	} {
		t.Run(filter, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/Users?filter="+url.QueryEscape(filter), nil)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)

			if w.Result().StatusCode != http.StatusBadRequest {
				body, _ := io.ReadAll(w.Result().Body)
				t.Fatalf("expected status %d for %q, got %d: %s",
					http.StatusBadRequest, filter, w.Result().StatusCode, string(body))
			}

			var scimErr errors.ScimError
			if err := json.NewDecoder(w.Body).Decode(&scimErr); err != nil {
				t.Fatal(err)
			}
			if scimErr.ScimType != errors.ScimTypeInvalidFilter {
				t.Fatalf("expected scimType %q, got %q", errors.ScimTypeInvalidFilter, scimErr.ScimType)
			}
		})
	}
}

// Test_User_Filter_ExtensionSchema keeps a valid extension-schema filter working end to end. The test server only
// registers the core User schema, so this uses an explicit core uri prefix.
func Test_User_Filter_ExtensionSchema(t *testing.T) {
	s := newTestServerForFilter(t)

	for _, filter := range []string{
		`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "testUser"`,
		`emails[type eq "work"] or userName eq "testUser"`,
	} {
		t.Run(filter, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/Users?filter="+url.QueryEscape(filter), nil)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)

			if w.Result().StatusCode != http.StatusOK {
				body, _ := io.ReadAll(w.Result().Body)
				t.Fatalf("expected status 200 for %q, got %d: %s",
					filter, w.Result().StatusCode, string(body))
			}
		})
	}
}

// Test_User_Filter_RejectsUnknownURIPrefix verifies that an unknown schema uri prefix fails closed with 400 instead
// of being accepted and silently failing to match.
func Test_User_Filter_RejectsUnknownURIPrefix(t *testing.T) {
	s := newTestServerForFilter(t)

	filter := `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:userName eq "testUser"`
	r := httptest.NewRequest(http.MethodGet, "/Users?filter="+url.QueryEscape(filter), nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	if w.Result().StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(w.Result().Body)
		t.Fatalf("expected status 400 for cross-schema prefix, got %d: %s",
			w.Result().StatusCode, string(body))
	}
}
