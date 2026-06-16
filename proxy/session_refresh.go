package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	// XForwardedUri is the header used by reverse proxies (Nginx, Traefik, Envoy)
	// to carry the original request URI to upstream services.
	XForwardedUri = "X-Forwarded-Uri"

	// XAuthRequestRedirect is an alternative header used for tracking the
	// original request destination during authentication flows.
	XAuthRequestRedirect = "X-Auth-Request-Redirect"

	// DefaultRedirectPath is the fallback redirect destination when no valid
	// original path can be determined.
	DefaultRedirectPath = "/"

	// redirectQueryParam is the query parameter used to carry the redirect URI
	// through the authentication/session refresh flow.
	redirectQueryParam = "rd"
)

// OriginalRequestPath extracts and validates the original request path from
// incoming headers set by a reverse proxy. It checks, in order:
//  1. X-Auth-Request-Redirect header
//  2. X-Forwarded-Uri header
//  3. The "rd" query parameter on the request URL
//
// If none are present or the value fails sanitization, DefaultRedirectPath ("/") is returned.
func OriginalRequestPath(r *http.Request) string {
	candidates := []string{
		r.Header.Get(XAuthRequestRedirect),
		r.Header.Get(XForwardedUri),
		r.URL.Query().Get(redirectQueryParam),
	}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		sanitized, err := sanitizeRedirectURI(candidate)
		if err != nil {
			continue
		}
		return sanitized
	}

	return DefaultRedirectPath
}

// sanitizeRedirectURI validates that the given URI is safe to use as a redirect
// target. It must be a relative URI (no scheme, no host) to prevent open-redirect
// attacks. Returns the sanitized URI or an error if the URI is invalid or unsafe.
func sanitizeRedirectURI(rawURI string) (string, error) {
	if rawURI == "" {
		return "", fmt.Errorf("empty URI")
	}

	// Reject anything that looks like a protocol-relative URL (//example.com/path)
	// or an absolute URL with a scheme.
	if strings.HasPrefix(rawURI, "//") {
		return "", fmt.Errorf("URI %q is protocol-relative and unsafe", rawURI)
	}

	parsed, err := url.Parse(rawURI)
	if err != nil {
		return "", fmt.Errorf("URI %q could not be parsed: %w", rawURI, err)
	}

	// Reject absolute URIs (those with a scheme or host component).
	if parsed.IsAbs() || parsed.Host != "" {
		return "", fmt.Errorf("URI %q is absolute and unsafe for redirect", rawURI)
	}

	// Ensure the path starts with "/" to make it an absolute path reference.
	path := parsed.RequestURI()
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return path, nil
}

// PreserveOriginalPathMiddleware is an HTTP middleware that extracts the original
// request path from reverse-proxy headers and attaches it to the request context
// (via a query parameter on any redirect) so that downstream handlers — including
// session-refresh handlers — can restore it after authentication completes.
//
// Usage:
//
//	mux.Handle("/oauth2/", PreserveOriginalPathMiddleware(oauthHandler))
func PreserveOriginalPathMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originalPath := OriginalRequestPath(r)

		// Attach the extracted original path to the request so downstream
		// handlers can use it without re-parsing headers.
		r = r.WithContext(withOriginalPath(r.Context(), originalPath))

		next.ServeHTTP(w, r)
	})
}

// RedirectToOriginalPath writes a redirect response to the client, sending them
// to the original request path that was preserved during the session refresh
// cycle. If no original path is available, it falls back to DefaultRedirectPath.
func RedirectToOriginalPath(w http.ResponseWriter, r *http.Request, statusCode int) {
	dest := OriginalPathFromContext(r.Context())
	if dest == "" {
		dest = DefaultRedirectPath
	}
	http.Redirect(w, r, dest, statusCode)
}

// BuildRefreshRedirectURL constructs the URL to redirect a user to the
// authentication/refresh endpoint, embedding the original destination so it can
// be restored after the session is refreshed.
//
// Example: given signInURL="/oauth2/sign_in" and originalPath="/dashboard/reports",
// the returned URL will be "/oauth2/sign_in?rd=%2Fdashboard%2Freports".
func BuildRefreshRedirectURL(signInURL, originalPath string) (string, error) {
	if originalPath == "" {
		originalPath = DefaultRedirectPath
	}

	sanitized, err := sanitizeRedirectURI(originalPath)
	if err != nil {
		// Fall back to default if the path is unsafe.
		sanitized = DefaultRedirectPath
	}

	base, err := url.Parse(signInURL)
	if err != nil {
		return "", fmt.Errorf("invalid sign-in URL %q: %w", signInURL, err)
	}

	q := base.Query()
	q.Set(redirectQueryParam, sanitized)
	base.RawQuery = q.Encode()

	return base.String(), nil
}

// SessionRefreshHandler wraps an existing http.Handler and ensures that the
// original request path (sourced from X-Forwarded-Uri or X-Auth-Request-Redirect)
// is preserved across a session-refresh redirect cycle.
//
// When a session refresh is required:
//  1. The original path is extracted from the incoming request headers.
//  2. The user is redirected to signInURL with the original path as a query parameter.
//  3. After successful authentication, RedirectToOriginalPath restores the destination.
//
// Parameters:
//   - next:       the upstream handler to invoke when the session is valid.
//   - signInURL:  the URL of the sign-in / session-refresh endpoint.
//   - needsRefresh: a function that returns true when a session refresh is required.
func SessionRefreshHandler(
	next http.Handler,
	signInURL string,
	needsRefresh func(r *http.Request) bool,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !needsRefresh(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract and validate the original path before triggering the refresh.
		originalPath := OriginalRequestPath(r)

		refreshURL, err := BuildRefreshRedirectURL(signInURL, originalPath)
		if err != nil {
			// If we cannot build the URL, redirect to the sign-in page without
			// the original path rather than returning a 500.
			http.Redirect(w, r, signInURL, http.StatusFound)
			return
		}

		http.Redirect(w, r, refreshURL, http.StatusFound)
	})
}
