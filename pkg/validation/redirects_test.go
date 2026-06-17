package validation

import (
	"testing"
)

func TestValidateRedirectURI_EmptyReturnsDefault(t *testing.T) {
	a := DefaultAllowedRedirect()
	got := a.ValidateRedirectURI("")
	if got != "/" {
		t.Errorf("expected /, got %q", got)
	}
}

func TestValidateRedirectURI_RelativePathAllowed(t *testing.T) {
	a := DefaultAllowedRedirect()
	cases := []struct {
		input    string
		expected string
	}{
		{"/", "/"},
		{"/dashboard", "/dashboard"},
		{"/deep/path/to/resource", "/deep/path/to/resource"},
		{"/settings/profile", "/settings/profile"},
	}
	for _, tc := range cases {
		got := a.ValidateRedirectURI(tc.input)
		if got != tc.expected {
			t.Errorf("ValidateRedirectURI(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestValidateRedirectURI_DangerousURIsBlocked(t *testing.T) {
	a := DefaultAllowedRedirect()
	dangerous := []string{
		"javascript:alert(1)",
		"data:text/html,<script>",
		"vbscript:msgbox",
		"file:///etc/passwd",
	}
	for _, uri := range dangerous {
		got := a.ValidateRedirectURI(uri)
		if got != "/" {
			t.Errorf("ValidateRedirectURI(%q) = %q, want / (blocked)", uri, got)
		}
	}
}

func TestValidateRedirectURI_ResponseSplitBlocked(t *testing.T) {
	a := DefaultAllowedRedirect()
	// Carriage return / line feed characters indicate response splitting attempts
	attacks := []string{
		"/good\r\nLocation: http://evil.com",
		"/good\nLocation: http://evil.com",
	}
	for _, uri := range attacks {
		got := a.ValidateRedirectURI(uri)
		if got != "/" {
			t.Errorf("ValidateRedirectURI(%q) = %q, want / (CR/LF blocked)", uri, got)
		}
	}
}

func TestValidateRedirectURI_AbsoluteURIAllowedWhenDomainMatches(t *testing.T) {
	a := DefaultAllowedRedirect()
	a.Domains = []string{"*.example.com", "example.org"}

	cases := []struct {
		input    string
		expected string
	}{
		{"https://app.example.com/dashboard", "https://app.example.com/dashboard"},
		{"https://example.org/settings", "https://example.org/settings"},
		{"https://evil.com/phishing", "/"}, // blocked
	}
	for _, tc := range cases {
		got := a.ValidateRedirectURI(tc.input)
		if got != tc.expected {
			t.Errorf("ValidateRedirectURI(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestValidateRedirectURI_EmptyAllowedDefault(t *testing.T) {
	a := &AllowedRedirect{
		Domains:        []string{},
		PathPrefixes:   []string{"/"},
		DefaultRedirect: "/fallback",
	}
	got := a.ValidateRedirectURI("https://evil.com")
	if got != "/fallback" {
		t.Errorf("expected /fallback, got %q", got)
	}
}

func TestValidateRedirectURI_WildcardDomain(t *testing.T) {
	a := DefaultAllowedRedirect()
	a.Domains = []string{"*"} // allow any domain

	got := a.ValidateRedirectURI("https://any-domain.com/path")
	if got != "https://any-domain.com/path" {
		t.Errorf("expected the URI to be allowed with * domain, got %q", got)
	}
}
