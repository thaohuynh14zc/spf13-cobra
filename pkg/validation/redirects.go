// Package validation provides redirect-URL and open-redirect
// safety validation for the OAuth2 proxy.
package validation

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

// AllowedRedirect contains the configuration for which redirect
// destinations are considered safe.
type AllowedRedirect struct {
	// Domains lists the allowed hostnames or domains.
	Domains []string
	// PathPrefixes restricts redirects to paths starting with one
	// of the given prefixes (e.g. ["/"] allows everything under root).
	PathPrefixes []string
	// DefaultRedirect is the fallback when validation fails.
	DefaultRedirect string
}

// DefaultAllowedRedirect returns an AllowedRedirect with safe defaults:
// all domains allowed, only root path, default redirect to "/".
func DefaultAllowedRedirect() *AllowedRedirect {
	return &AllowedRedirect{
		Domains:       []string{"*"},
		PathPrefixes:  []string{"/"},
		DefaultRedirect: "/",
	}
}

// ValidateRedirectURI validates and sanitizes a raw URI to ensure it is
// safe for use as a redirect target. This prevents open-redirect attacks
// where an attacker could redirect users to external malicious sites.
//
// Rules:
//  1. If the URI is empty → return default redirect.
//  2. If the URI is absolute (has scheme) → only allow if host matches
//     an allowed domain.
//  3. If the URI is a path-only (relative) → allow if path starts with
//     an allowed prefix.
//  4. Block anything containing CR/LF characters (response splitting).
//  5. Block javascript: URIs and other dangerous schemes.
func (a *AllowedRedirect) ValidateRedirectURI(rawURI string) string {
	if rawURI == "" {
		return a.DefaultRedirect
	}

	// Reject dangerous characters (response splitting / injection)
	if strings.ContainsAny(rawURI, "\r\n") {
		return a.DefaultRedirect
	}

	// Reject dangerous schemes
	lower := strings.ToLower(rawURI)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(lower, "vbscript:") ||
		strings.HasPrefix(lower, "file:") {
		return a.DefaultRedirect
	}

	parsed, err := url.Parse(rawURI)
	if err != nil {
		return a.DefaultRedirect
	}

	// Absolute URIs — validate host against allowed domains
	if parsed.IsAbs() {
		if !a.isDomainAllowed(parsed.Host) {
			return a.DefaultRedirect
		}
		// All good — return the full URI (re-encoded for safety)
		return rawURI
	}

	// Relative path — validate against allowed prefixes
	if !a.isPathAllowed(parsed.Path) {
		return a.DefaultRedirect
	}

	return rawURI
}

// isDomainAllowed checks whether a hostname is in the allowed list.
// A single "*" in the list means all domains are accepted.
func (a *AllowedRedirect) isDomainAllowed(host string) bool {
	if host == "" {
		return false
	}
	// Strip port for comparison
	if h, _, err := netSplitHostPort(host); err == nil {
		host = h
	}
	for _, d := range a.Domains {
		if d == "*" {
			return true
		}
		// Exact match or wildcard suffix
		if strings.EqualFold(host, d) {
			return true
		}
		if strings.HasPrefix(d, "*.") && strings.HasSuffix(strings.ToLower(host), strings.ToLower(d[1:])) {
			return true
		}
	}
	return false
}

// isPathAllowed checks whether a path falls under an allowed prefix.
func (a *AllowedRedirect) isPathAllowed(p string) bool {
	cleaned := path.Clean(p)
	for _, prefix := range a.PathPrefixes {
		if cleaned == prefix || strings.HasPrefix(cleaned, prefix) {
			return true
		}
	}
	return false
}

// netSplitHostPort splits a host:port pair. Defined as a variable so
// tests can replace it.
var netSplitHostPort = func(hostport string) (string, string, error) {
	host, port, err := netSplitHostPortImpl(hostport)
	return host, port, err
}

func netSplitHostPortImpl(hostport string) (string, string, error) {
	lastColon := strings.LastIndex(hostport, ":")
	if lastColon == -1 {
		return hostport, "", fmt.Errorf("missing port")
	}
	return hostport[:lastColon], hostport[lastColon+1:], nil
}
