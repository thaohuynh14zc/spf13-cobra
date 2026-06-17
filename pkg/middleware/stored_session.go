// Package middleware provides HTTP middleware components for the
// OAuth2 proxy, including session validation, refresh, and the
// critical X-Forwarded-Uri preservation during refresh cycles.
package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sniegul-szam/spf13-cobra/pkg/requests"
	"github.com/sniegul-szam/spf13-cobra/pkg/validation"
)

// SessionState holds the OAuth2 token data for an authenticated user.
type SessionState struct {
	// AccessToken is the current OAuth2 access token.
	AccessToken string `json:"access_token"`
	// RefreshToken is the OAuth2 refresh token (if available).
	RefreshToken string `json:"refresh_token,omitempty"`
	// ExpiresAt indicates when the access token will expire.
	ExpiresAt time.Time `json:"expires_at"`
	// Email is the authenticated user's email address.
	Email string `json:"email"`
	// Subject is the unique identifier (sub claim).
	Subject string `json:"subject"`
	// CreatedAt is when the session was first created.
	CreatedAt time.Time `json:"created_at"`
}

// IsExpired returns true when the access token has expired or will
// expire within a 30-second grace window.
func (s *SessionState) IsExpired() bool {
	return time.Now().After(s.ExpiresAt.Add(-30 * time.Second))
}

// CanRefresh returns true when a refresh token is available and the
// session as a whole hasn't passed its total lifetime.
func (s *SessionState) CanRefresh() bool {
	return s.RefreshToken != "" &&
		time.Now().Before(s.CreatedAt.Add(24*time.Hour))
}

// SessionStore is a simple in-memory session store keyed by cookie
// or session ID. In production this would be a Redis/DB backend.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionState
}

// NewSessionStore creates and returns an initialized SessionStore.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*SessionState),
	}
}

// Get retrieves a session by ID. Returns nil if not found.
func (s *SessionStore) Get(id string) *SessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[id]
}

// Set stores a session by ID.
func (s *SessionStore) Set(id string, state *SessionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = state
}

// Delete removes a session by ID.
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// SessionRefreshMiddleware is an HTTP middleware that:
//  1. Checks whether the incoming request has a valid (non-expired) session.
//  2. If the session is expired but a refresh token exists, it attempts a
//     token refresh.
//  3. During the refresh cycle, it preserves the X-Forwarded-Uri header
//     (or X-Auth-Request-Redirect) so that after a successful refresh
//     the user is redirected back to their original deep-linked destination
//     instead of the default redirect root.
//  4. If the header is missing, invalid, or the domain is not allowed,
//     it safely falls back to the configured default redirect URL.
//
// This is the core fix for the reported issue.
type SessionRefreshMiddleware struct {
	// Store is the session storage backend.
	Store *SessionStore
	// AllowedRedirects defines safe redirect targets.
	AllowedRedirects *validation.AllowedRedirect
	// ReverseProxy indicates whether we should trust reverse-proxy headers.
	ReverseProxy bool
	// TrustedCIDRs lists the IP ranges we trust for header provenance.
	TrustedCIDRs []string
	// CookieName is the name of the session cookie.
	CookieName string
	// TokenRefreshFunc is the pluggable OAuth2 token refresh callback.
	// It receives the current (expired) session and returns an updated
	// session with a fresh access token.
	TokenRefreshFunc func(session *SessionState) (*SessionState, error)
	// OnSessionRefresh is an optional callback invoked after a successful
	// token refresh (for logging/metrics).
	OnSessionRefresh func(sessionID string, state *SessionState)
}

// NewSessionRefreshMiddleware creates a SessionRefreshMiddleware with
// sensible defaults.
func NewSessionRefreshMiddleware(store *SessionStore, reverseProxy bool, trustedCIDRs []string) *SessionRefreshMiddleware {
	return &SessionRefreshMiddleware{
		Store:            store,
		AllowedRedirects: validation.DefaultAllowedRedirect(),
		ReverseProxy:     reverseProxy,
		TrustedCIDRs:     trustedCIDRs,
		CookieName:       "_oauth2_proxy",
		TokenRefreshFunc: defaultTokenRefresh,
	}
}

// Wrap returns an http.Handler that wraps the next handler with
// session validation and optional refresh logic.
func (m *SessionRefreshMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Extract session ID from cookie
		sessionID, err := m.extractSessionID(r)
		if err != nil || sessionID == "" {
			next.ServeHTTP(w, r)
			return
		}

		// 2. Load the session
		session := m.Store.Get(sessionID)
		if session == nil {
			next.ServeHTTP(w, r)
			return
		}

		// 3. Check if session is expired
		if !session.IsExpired() {
			// Session is still valid — pass through
			next.ServeHTTP(w, r)
			return
		}

		// 4. Session is expired — attempt refresh
		if !session.CanRefresh() {
			// No refresh token available or session TTL exceeded
			log.Printf("[session] session %s expired and cannot be refreshed", sessionID)
			m.Store.Delete(sessionID)
			m.redirectToDestination(w, r, sessionID)
			return
		}

		// 5. Perform the token refresh
		newSession, err := m.TokenRefreshFunc(session)
		if err != nil {
			log.Printf("[session] token refresh failed for session %s: %v", sessionID, err)
			m.Store.Delete(sessionID)
			m.redirectToDestination(w, r, sessionID)
			return
		}

		// 6. Update the stored session
		m.Store.Set(sessionID, newSession)
		if m.OnSessionRefresh != nil {
			m.OnSessionRefresh(sessionID, newSession)
		}

		log.Printf("[session] session %s refreshed successfully", sessionID)

		// 7. Extract and validate the original redirect target
		m.redirectToDestination(w, r, sessionID)
	})
}

// redirectToDestination determines the correct redirect target after a
// session refresh. It prefers the X-Forwarded-Uri header (when reverse
// proxy mode is enabled and the client is trusted), then falls back to
// the default redirect URL.
//
// This is the function that implements the X-Forwarded-Uri preservation
// behavior described in the issue.
func (m *SessionRefreshMiddleware) redirectToDestination(w http.ResponseWriter, r *http.Request, sessionID string) {
	var redirectTarget string

	if m.ReverseProxy {
		// Build request context to determine if headers are trustworthy
		ctx := requests.NewRequestContext(r, m.ReverseProxy, m.TrustedCIDRs)

		if ctx.IsTrustedIP && ctx.ForwardedURI != "" {
			// Validate the forwarded URI to prevent open redirects
			redirectTarget = m.AllowedRedirects.ValidateRedirectURI(ctx.ForwardedURI)
			log.Printf("[session] using X-Forwarded-Uri: %s → validated: %s", ctx.ForwardedURI, redirectTarget)
		}
	}

	if redirectTarget == "" {
		// Try fallback: rd query parameter or Referer header
		rd := r.URL.Query().Get("rd")
		if rd != "" {
			redirectTarget = m.AllowedRedirects.ValidateRedirectURI(rd)
		}
		if redirectTarget == "" {
			redirectTarget = m.AllowedRedirects.DefaultRedirect
		}
	}

	http.Redirect(w, r, redirectTarget, http.StatusFound)
}

// extractSessionID reads the session ID from the configured cookie.
// Returns an error if the cookie is missing or malformed.
func (m *SessionRefreshMiddleware) extractSessionID(r *http.Request) (string, error) {
	cookie, err := r.Cookie(m.CookieName)
	if err != nil {
		return "", err
	}
	// Basic sanity check — session IDs should be non-empty
	if strings.TrimSpace(cookie.Value) == "" {
		return "", nil
	}
	return cookie.Value, nil
}

// defaultTokenRefresh is a no-op token refresh that simply returns the
// same session. In a real deployment this would call the OAuth2
// provider's token endpoint with the refresh token.
func defaultTokenRefresh(session *SessionState) (*SessionState, error) {
	// Extend expiry by 1 hour as a simulated refresh
	newSession := *session
	newSession.ExpiresAt = time.Now().Add(1 * time.Hour)
	return &newSession, nil
}

// SessionMiddleware is the older session-validation middleware that
// checks the session cookie but does NOT perform refresh. It is
// retained for comparison and testing.
//
// Deprecated: Prefer SessionRefreshMiddleware which handles refresh
// and preserves X-Forwarded-Uri.
type SessionMiddleware struct {
	Store      *SessionStore
	CookieName string
	OnDeny     func(w http.ResponseWriter, r *http.Request)
}

// NewSessionMiddleware creates a basic session validator.
func NewSessionMiddleware(store *SessionStore) *SessionMiddleware {
	return &SessionMiddleware{
		Store:      store,
		CookieName: "_oauth2_proxy",
	}
}

// Wrap returns an http.Handler that validates the session.
func (sm *SessionMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sm.CookieName)
		if err != nil || cookie.Value == "" {
			sm.deny(w, r)
			return
		}
		session := sm.Store.Get(cookie.Value)
		if session == nil {
			sm.deny(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (sm *SessionMiddleware) deny(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/oauth2/sign_in", http.StatusFound)
}

// SessionFromJSON decodes a session from its JSON representation.
func SessionFromJSON(data []byte) (*SessionState, error) {
	var s SessionState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// SessionToJSON encodes a session to its JSON representation.
func SessionToJSON(s *SessionState) ([]byte, error) {
	return json.Marshal(s)
}

// ValidateRedirectURI is a convenience wrapper on AllowedRedirect.
func (m *SessionRefreshMiddleware) ValidateRedirectURI(rawURI string) string {
	return m.AllowedRedirects.ValidateRedirectURI(rawURI)
}

// SetAllowedDomains configures which domains are allowed as redirect
// targets. Pass "*" to allow all domains.
func (m *SessionRefreshMiddleware) SetAllowedDomains(domains []string) {
	m.AllowedRedirects.Domains = domains
}

// SetDefaultRedirect configures the fallback redirect URL.
func (m *SessionRefreshMiddleware) SetDefaultRedirect(url string) {
	m.AllowedRedirects.DefaultRedirect = url
}

// GetLoginURL builds the OAuth2 authorization URL with the original
// request path encoded as the "rd" (redirect) parameter so the user
// is sent back to their intended destination after authenticating.
func GetLoginURL(authURL string, originalURI string) string {
	u, err := url.Parse(authURL)
	if err != nil {
		return authURL
	}
	q := u.Query()
	q.Set("rd", originalURI)
	u.RawQuery = q.Encode()
	return u.String()
}
