package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// SessionRefreshMiddleware handles session refresh and preserves the original request path
// via X-Forwarded-Uri or X-Auth-Request-Redirect headers when behind a reverse proxy.
type SessionRefreshMiddleware struct {
	redirectURL   string
	allowedDomains []string
	enabled        bool
}

// NewSessionRefreshMiddleware creates a new SessionRefreshMiddleware.
func NewSessionRefreshMiddleware(redirectURL string, allowedDomains []string, enabled bool) *SessionRefreshMiddleware {
	return &SessionRefreshMiddleware{
		redirectURL:    redirectURL,
		allowedDomains: allowedDomains,
		enabled:        enabled,
	}
}

// Handler returns an http.Handler that wraps the next handler.
func (m *SessionRefreshMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if !m.enabled {
			next.ServeHTTP(rw, req)
			return
		}

		// Extract the original request path from headers
		originalURI := m.extractOriginalURI(req)
		if originalURI == "" {
			// Fallback to default redirect URL
			originalURI = m.redirectURL
		}

		// Validate the URI to prevent open redirect vulnerabilities
		if !m.isValidRedirect(originalURI) {
			logger.Errorf("Invalid redirect URI: %s, falling back to default", originalURI)
			originalURI = m.redirectURL
		}

		// Store the original URI in the request context for later use
		ctx := req.Context()
		ctx = context.WithValue(ctx, "original_uri", originalURI)
		req = req.WithContext(ctx)

		next.ServeHTTP(rw, req)
	})
}

// extractOriginalURI extracts the original request URI from headers.
// It checks X-Forwarded-Uri first, then X-Auth-Request-Redirect.
func (m *SessionRefreshMiddleware) extractOriginalURI(req *http.Request) string {
	// Check X-Forwarded-Uri header
	if uri := req.Header.Get("X-Forwarded-Uri"); uri != "" {
		return uri
	}

	// Check X-Auth-Request-Redirect header
	if uri := req.Header.Get("X-Auth-Request-Redirect"); uri != "" {
		return uri
	}

	return ""
}

// isValidRedirect validates the redirect URI to prevent open redirect vulnerabilities.
// It checks that the URI is either a relative path or matches an allowed domain.
func (m *SessionRefreshMiddleware) isValidRedirect(uri string) bool {
	// Allow relative paths (starting with /)
	if strings.HasPrefix(uri, "/") {
		// Ensure it's a valid path (no protocol or host)
		parsed, err := url.Parse(uri)
		if err != nil {
			return false
		}
		// If it has a host, it's absolute and must be validated against allowed domains
		if parsed.Host != "" {
			return m.isAllowedDomain(parsed.Host)
		}
		return true
	}

	// For absolute URIs, validate against allowed domains
	parsed, err := url.Parse(uri)
	if err != nil {
		return false
	}
	return m.isAllowedDomain(parsed.Host)
}

// isAllowedDomain checks if the given host is in the list of allowed domains.
func (m *SessionRefreshMiddleware) isAllowedDomain(host string) bool {
	for _, domain := range m.allowedDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// GetOriginalURI retrieves the original URI from the request context.
func GetOriginalURI(req *http.Request) string {
	if uri, ok := req.Context().Value("original_uri").(string); ok {
		return uri
	}
	return ""
}
