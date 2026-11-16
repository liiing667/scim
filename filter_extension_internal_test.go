package scim

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestServerResourcesGetHandlerExtensionFilter covers extension schema uri prefixes end to end: a valid extension
// attribute filter is accepted, while an extension prefix on a core attribute fails closed.
func TestServerResourcesGetHandlerExtensionFilter(t *testing.T) {
	tests := []struct {
		name           string
		filter         string
		expectedStatus int
	}{
		{
			name:           "valid extension attribute",
			filter:         `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber eq "x"`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "extension prefix on core attribute",
			filter:         `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:userName eq "x"`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "unknown extension uri",
			filter:         `urn:ietf:params:scim:schemas:extension:bogus:2.0:User:employeeNumber eq "x"`,
			expectedStatus: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet,
				"/EnterpriseUsers?filter="+url.QueryEscape(tt.filter), nil)
			rr := httptest.NewRecorder()
			newTestServer(t).ServeHTTP(rr, req)

			assertEqualStatusCode(t, tt.expectedStatus, rr.Code)
		})
	}
}
