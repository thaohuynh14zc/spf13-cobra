// Package server provides the HTTP server setup and request routing
// for the OAuth2 proxy, integrating the session middleware that
// preserves X-Forwarded-Uri during refresh cycles.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/sniegul-szam/spf13-cobra/pkg/middleware"
	"github.com/sniegul-szam/spf13-cobra/pkg/validation"
)

// Config holds all server-level configuration for the OAuth2 proxy.
type Config struct {
	// ListenAddr is the address the proxy listens on (e.g. ":4180").
	ListenAddr string

	// Upstream is the URL of the backend service being protected.
	Upstream string

	// RedirectURL is the OAuth2 callback URL.
	RedirectURL string

	// OAuthProviderURL is the OAuth2 provider's base URL.
	OAuthProviderURL string

	// ClientID is the OAuth2 client identifier.
	ClientID string

	// ClientSecret is the OAuth2 client secret.
	ClientSecret string

	// ReverseProxy enables trusting X-Forwarded-* headers.
	ReverseProxy bool

	// TrustedCIDRs lists IP ranges trusted to send proxy headers.
	TrustedCIDRs []string

	// CookieSecret is used to encrypt session cookies.
	CookieSecret string

	// CookieRefresh defines how often the session should be refreshed.
	CookieRefresh time.Duration

	// DefaultRedirect is the fallback URL when no redirect is specified.
	DefaultRedirect string
}

// Validate performs basic validation of the required config fields.
func (c *Config) Validate() error {
	if c.Upstream == "" {
		return fmt.Errorf("upstream is required")
	}
	if c.ClientID == "" {
		return fmt.Errorf("client-id is required")
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("client-secret is required")
	}
	if c.CookieSecret == "" {
		return fmt.Errorf("cookie-secret is required")
	}
	return nil
}

// Server wraps the HTTP server and its dependencies.
type Server struct {
	Config         *Config
	SessionStore   *middleware.SessionStore
	RefreshMW      *middleware.SessionRefreshMiddleware
	AllowedRedirect *validation.AllowedRedirect
	mux            *http.ServeMux
}

// New creates a new Server from the provided configuration.
func New(cfg *Config) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	store := middleware.NewSessionStore()

	allowed := validation.DefaultAllowedRedirect()
	if cfg.DefaultRedirect != "" {
		allowed.DefaultRedirect = cfg.DefaultRedirect
	}

	refreshMW := middleware.NewSessionRefreshMiddleware(
		store,
		cfg.ReverseProxy,
		cfg.TrustedCIDRs,
	)

	s := &Server{
		Config:         cfg,
		SessionStore:   store,
		RefreshMW:      refreshMW,
		AllowedRedirect: allowed,
		mux:            http.NewServeMux(),
	}

	s.registerRoutes()
	return s, nil
}

// registerRoutes sets up the HTTP handler routes.
func (s *Server) registerRoutes() {
	// OAuth2 endpoints
	s.mux.HandleFunc("/oauth2/sign_in", s.handleSignIn)
	s.mux.HandleFunc("/oauth2/callback", s.handleCallback)
	s.mux.HandleFunc("/oauth2/sign_out", s.handleSignOut)

	// Health / ping
	s.mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("pong"))
	})

	// The root handler applies session refresh middleware and then
	// reverse-proxies to the upstream.
	upstreamHandler := s.newUpstreamProxy()
	wrappedHandler := s.RefreshMW.Wrap(upstreamHandler)
	s.mux.Handle("/", wrappedHandler)
}

// newUpstreamProxy creates a reverse proxy that forwards requests to
// the configured upstream. It preserves the original X-Forwarded-Uri
// header for downstream services that need it.
func (s *Server) newUpstreamProxy() http.Handler {
	upstreamURL, err := url.Parse(s.Config.Upstream)
	if err != nil {
		log.Fatalf("invalid upstream URL %q: %v", s.Config.Upstream, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)

	// Custom Director to preserve and forward headers
	originalDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		originalDirector(r)

		// If X-Forwarded-Uri was present in the original request,
		// ensure it is forwarded to the upstream
		if s.Config.ReverseProxy {
			if fwdURI := r.Header.Get("X-Forwarded-Uri"); fwdURI != "" {
				r.Header.Set("X-Forwarded-Uri", fwdURI)
			}
		}

		// Set standard proxy headers
		r.Header.Set("X-Forwarded-Host", r.Host)
		r.Header.Set("X-Forwarded-Proto", s.getProto(r))
	}

	return proxy
}

// getProto determines the protocol (http/https) based on headers.
func (s *Server) getProto(r *http.Request) string {
	if s.Config.ReverseProxy {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			return proto
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// handleSignIn initiates the OAuth2 login flow.
func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	// Generate a random state for CSRF protection
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state := hex.EncodeToString(stateBytes)

	// Build the authorization URL with the redirect target
	authURL := fmt.Sprintf("%s/oauth2/authorize?client_id=%s&redirect_uri=%s&response_type=code&state=%s",
		strings.TrimRight(s.Config.OAuthProviderURL, "/"),
		s.Config.ClientID,
		url.QueryEscape(s.Config.RedirectURL),
		state,
	)

	// If the user asked for a specific redirect, propagate it
	rd := r.URL.Query().Get("rd")
	if rd != "" {
		validated := s.AllowedRedirect.ValidateRedirectURI(rd)
		authURL += "&rd=" + url.QueryEscape(validated)
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback processes the OAuth2 callback, exchanges the code for
// tokens, creates a session, and redirects the user back.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	// In production, this would exchange the code for tokens via the
	// OAuth2 provider's token endpoint.
	session := &middleware.SessionState{
		AccessToken:  "simulated-access-token-" + code,
		RefreshToken: "simulated-refresh-token-" + code,
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Email:        "user@example.com",
		Subject:      code,
		CreatedAt:    time.Now(),
	}

	sessionID := generateSessionID()
	s.SessionStore.Set(sessionID, session)

	// Set the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "_oauth2_proxy",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		MaxAge:   86400, // 24 hours
	})

	// Determine where to redirect after login
	rd := r.URL.Query().Get("rd")
	if rd == "" {
		rd = s.AllowedRedirect.DefaultRedirect
	} else {
		rd = s.AllowedRedirect.ValidateRedirectURI(rd)
	}

	http.Redirect(w, r, rd, http.StatusFound)
}

// handleSignOut clears the session and cookie.
func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("_oauth2_proxy"); err == nil {
		s.SessionStore.Delete(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "_oauth2_proxy",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, s.AllowedRedirect.DefaultRedirect, http.StatusFound)
}

// SignInPage renders a simple sign-in page when the user is not
// authenticated. This is used when the proxy is running in
// "display sign-in page" mode.
var signInTemplate = template.Must(template.New("sign_in").Parse(`<!DOCTYPE html>
<html>
<head><title>Sign In</title></head>
<body>
<h1>OAuth2 Proxy</h1>
<p>You must sign in to access this resource.</p>
<a href="/oauth2/sign_in">Sign in with OAuth2</a>
</body>
</html>`))

// generateSessionID creates a random session identifier.
func generateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("sess-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// Start begins listening for HTTP requests and returns the underlying
// http.Server so the caller can control its lifecycle.
func (s *Server) Start() *http.Server {
	httpServer := &http.Server{
		Addr:    s.Config.ListenAddr,
		Handler: s.mux,
	}

	go func() {
		log.Printf("[server] listening on %s, proxying to %s", s.Config.ListenAddr, s.Config.Upstream)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[server] listen error: %v", err)
		}
	}()

	return httpServer
}

// Shutdown gracefully stops the HTTP server within the given timeout.
func (s *Server) Shutdown(httpServer *http.Server, timeout time.Duration) error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}
