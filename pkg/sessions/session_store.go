package sessions

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// SessionStore handles session persistence and refresh
type SessionStore struct {
	store   SessionStoreProvider
	options *options.SessionOptions
}

// NewSessionStore creates a new session store
func NewSessionStore(provider SessionStoreProvider, opts *options.SessionOptions) *SessionStore {
	return &SessionStore{
		store:   provider,
		options: opts,
	}
}

// RefreshSessionIfNeeded checks if session needs refresh and performs it
func (s *SessionStore) RefreshSessionIfNeeded(rw http.ResponseWriter, req *http.Request) (bool, error) {
	session, err := s.store.Load(req)
	if err != nil || session == nil {
		return false, err
	}

	if !session.IsExpired() {
		return false, nil
	}

	// Perform session refresh
	newSession, err := s.store.Refresh(session)
	if err != nil {
		return false, err
	}

	// Save the refreshed session
	if err := s.store.Save(rw, req, newSession); err != nil {
		return false, err
	}

	// Determine redirect URL after refresh
	redirectURL := s.getRedirectURL(req)
	if redirectURL != "" {
		http.Redirect(rw, req, redirectURL, http.StatusFound)
		return true, nil
	}

	return true, nil
}

// getRedirectURL extracts and validates the redirect URL from request headers
func (s *SessionStore) getRedirectURL(req *http.Request) string {
	// Check for X-Forwarded-Uri header first
	forwardedURI := req.Header.Get("X-Forwarded-Uri")
	if forwardedURI != "" {
		// Sanitize and validate the URI
		sanitizedURI := sanitizeURI(forwardedURI)
		if sanitizedURI != "" {
			return sanitizedURI
		}
	}

	// Fallback to X-Auth-Request-Redirect header
	redirectHeader := req.Header.Get("X-Auth-Request-Redirect")
	if redirectHeader != "" {
		sanitizedURI := sanitizeURI(redirectHeader)
		if sanitizedURI != "" {
			return sanitizedURI
		}
	}

	// Fallback to default redirect URL
	return s.options.DefaultRedirectURL
}

// sanitizeURI validates and sanitizes a URI to prevent open redirect vulnerabilities
func sanitizeURI(uri string) string {
	if uri == "" {
		return ""
	}

	// Parse the URI
	parsedURL, err := url.Parse(uri)
	if err != nil {
		logger.Errorf("Failed to parse redirect URI: %v", err)
		return ""
	}

	// Ensure the URI is a path-only (no host) to prevent open redirect
	if parsedURL.Host != "" {
		logger.Warnf("Rejected redirect URI with host: %s", uri)
		return ""
	}

	// Ensure the path starts with "/"
	if !strings.HasPrefix(parsedURL.Path, "/") {
		logger.Warnf("Rejected redirect URI without leading slash: %s", uri)
		return ""
	}

	// Reject paths that could be used for open redirect (e.g., //evil.com)
	if strings.HasPrefix(parsedURL.Path, "//") {
		logger.Warnf("Rejected redirect URI with double slash: %s", uri)
		return ""
	}

	// Reject paths containing certain dangerous patterns
	dangerousPatterns := []string{"..", "%0d", "%0a", "%00"}
	for _, pattern := range dangerousPatterns {
		if strings.Contains(parsedURL.Path, pattern) {
			logger.Warnf("Rejected redirect URI with dangerous pattern: %s", uri)
			return ""
		}
	}

	// Return the sanitized path
	return parsedURL.Path
}
