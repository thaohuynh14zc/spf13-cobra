package sessions

import (
	"net/http"
	"net/url"
	"strings"
)

const (
	XForwardedURIHeader = "X-Forwarded-Uri"
	XAuthRequestRedirectHeader = "X-Auth-Request-Redirect"
)

// getRedirectURI extracts and validates the redirect URI from the request headers.
// It checks X-Forwarded-Uri first, then falls back to X-Auth-Request-Redirect.
// If neither is present or valid, it returns the default redirect path.
func getRedirectURI(r *http.Request, defaultRedirect string) string {
	// Check X-Forwarded-Uri header
	if uri := r.Header.Get(XForwardedURIHeader); uri != "" {
		if sanitizedURI := sanitizeAndValidateURI(uri); sanitizedURI != "" {
			return sanitizedURI
		}
	}

	// Fallback to X-Auth-Request-Redirect header
	if uri := r.Header.Get(XAuthRequestRedirectHeader); uri != "" {
		if sanitizedURI := sanitizeAndValidateURI(uri); sanitizedURI != "" {
			return sanitizedURI
		}
	}

	// Default fallback
	return defaultRedirect
}

// sanitizeAndValidateURI sanitizes and validates a URI to prevent open-redirect attacks.
// It ensures the URI is a relative path (starts with '/') and does not contain scheme or host.
func sanitizeAndValidateURI(uri string) string {
	// Trim whitespace
	uri = strings.TrimSpace(uri)

	// Must start with '/'
	if !strings.HasPrefix(uri, "/") {
		return ""
	}

	// Parse the URI to check for scheme or host
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return ""
	}

	// Reject if it has a scheme or host (absolute URL)
	if parsedURL.IsAbs() || parsedURL.Host != "" {
		return ""
	}

	// Reject if it contains '..' path traversal
	if strings.Contains(uri, "..") {
		return ""
	}

	// Return the sanitized path (query string allowed)
	return parsedURL.RequestURI()
}

// RedirectWithPreservedPath redirects the user to the preserved path from headers or default.
func RedirectWithPreservedPath(w http.ResponseWriter, r *http.Request, defaultRedirect string) {
	redirectURI := getRedirectURI(r, defaultRedirect)
	http.Redirect(w, r, redirectURI, http.StatusFound)
}
