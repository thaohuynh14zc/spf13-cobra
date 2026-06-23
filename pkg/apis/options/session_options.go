package options

// SessionOptions holds configuration for session handling
type SessionOptions struct {
	// DefaultRedirectURL is the fallback URL when no redirect header is present
	DefaultRedirectURL string

	// ReverseProxy indicates whether the app is behind a reverse proxy
	ReverseProxy bool

	// TrustedIPs are IPs that are trusted to set X-Forwarded-* headers
	TrustedIPs []string
}

// NewSessionOptions creates default session options
func NewSessionOptions() *SessionOptions {
	return &SessionOptions{
		DefaultRedirectURL: "/",
		ReverseProxy:       false,
		TrustedIPs:         []string{},
	}
}
