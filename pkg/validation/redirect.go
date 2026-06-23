package validation

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateRedirectURI validates a redirect URI against allowed domains.
// Returns an error if the URI is invalid or not allowed.
func ValidateRedirectURI(uri string, allowedDomains []string) error {
	if uri == "" {
		return fmt.Errorf("redirect URI is empty")
	}

	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid redirect URI: %v", err)
	}

	// Allow relative paths
	if strings.HasPrefix(uri, "/") && parsed.Host == "" {
		return nil
	}

	// For absolute URIs, check against allowed domains
	if len(allowedDomains) == 0 {
		return fmt.Errorf("absolute redirect URI not allowed: no allowed domains configured")
	}

	host := parsed.Host
	for _, domain := range allowedDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return nil
		}
	}

	return fmt.Errorf("redirect URI host %q is not in allowed domains", host)
}
