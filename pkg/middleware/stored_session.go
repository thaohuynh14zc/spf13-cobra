package middleware

import (
	"net/http"

	"github.com/thaohuynh14zc/spf13-cobra/pkg/requests"
	"github.com/thaohuynh14zc/spf13-cobra/pkg/validation"
)

// SessionHandler handles the session validation and refresh cycle.
type SessionHandler struct {
	ReverseProxy   bool
	AllowedDomains []string
}

// RefreshMiddleware intercepts requests to handle session refresh redirects.
// It ensures the original request path is preserved via X-Forwarded-Uri when in reverse proxy mode.
func (h *SessionHandler) RefreshMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// In oauth2-proxy, this logic is triggered when a session is expired but can be refreshed.
		// For the purpose of this fix, we simulate the redirection after a successful refresh.
		if r.URL.Path == "/oauth2/refresh" {
			// Extract, validate, and propagate the redirect URI
			redirectURI := requests.GetRedirectURI(r, h.ReverseProxy)
			
			if !validation.IsValidRedirect(redirectURI, h.AllowedDomains) {
				redirectURI = "/"
			}

			http.Redirect(w, r, redirectURI, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}
