package options

// MiddlewareOptions holds configuration for middleware components.
type MiddlewareOptions struct {
	// SessionRefreshEnabled enables the session refresh middleware.
	SessionRefreshEnabled bool `yaml:"session_refresh_enabled" json:"session_refresh_enabled"`

	// DefaultRedirectURL is the fallback redirect URL when no original URI is found.
	DefaultRedirectURL string `yaml:"default_redirect_url" json:"default_redirect_url"`

	// AllowedRedirectDomains is a list of domains allowed for redirects.
	AllowedRedirectDomains []string `yaml:"allowed_redirect_domains" json:"allowed_redirect_domains"`
}
