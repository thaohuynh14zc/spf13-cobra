package validation

import (
	"testing"
)

func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name           string
		uri            string
		allowedDomains []string
		expectError    bool
	}{
		{
			name:           "valid relative path",
			uri:            "/valid/path",
			allowedDomains: []string{},
			expectError:    false,
		},
		{
			name:           "valid absolute URL with allowed domain",
			uri:            "https://example.com/path",
			allowedDomains: []string{"example.com"},
			expectError:    false,
		},
		{
			name:           "valid absolute URL with subdomain",
			uri:            "https://sub.example.com/path",
			allowedDomains: []string{"example.com"},
			expectError:    false,
		},
		{
			name:           "absolute URL with disallowed domain",
			uri:            "https://evil.com/path",
			allowedDomains: []string{"example.com"},
			expectError:    true,
		},
		{
			name:           "empty URI",
			uri:            "",
			allowedDomains: []string{},
			expectError:    true,
		},
		{
			name:           "invalid URI",
			uri:            "://invalid",
			allowedDomains: []string{},
			expectError:    true,
		},
		{
			name:           "absolute URL without allowed domains configured",
			uri:            "https://example.com/path",
			allowedDomains: []string{},
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRedirectURI(tt.uri, tt.allowedDomains)
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
