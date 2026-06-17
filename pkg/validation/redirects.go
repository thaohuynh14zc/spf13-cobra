package validation

import (
	"net/url"
	"strings"
)

// IsValidRedirect validates the redirect URI to prevent open-redirect vulnerabilities.
// It checks if the URI is a relative path or belongs to an allowed domain.
func IsValidRedirect(redirect string, allowedDomains []string) bool {
	if redirect == "" {
		return false
	}

	// Prevent protocol-relative URLs (e.g., //evil.com)
	if strings.HasPrefix(redirect, "//") {
		return false
	}

	u, err := url.Parse(redirect)
	if err != nil {
		return false
	}

	// Allow relative paths starting with /
	if u.Host == "" {
		return strings.HasPrefix(redirect, "/")
	}

	// For absolute URLs, validate scheme and host
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	for _, domain := range allowedDomains {
		// Exact match or subdomain match
		if u.Host == domain || strings.HasSuffix(u.Host, "."+domain) {
			return true
		}
	}

	return false
}
