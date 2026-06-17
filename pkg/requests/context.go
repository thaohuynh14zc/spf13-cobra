package requests

import (
	"net/http"
)

// GetRedirectURI extracts the original request path from headers or query parameters.
// When reverseProxy is enabled, it prioritizes X-Forwarded-Uri and X-Auth-Request-Redirect.
func GetRedirectURI(req *http.Request, reverseProxy bool) string {
	if reverseProxy {
		// Priority 1: X-Forwarded-Uri (Common in Nginx/Traefik)
		if uri := req.Header.Get("X-Forwarded-Uri"); uri != "" {
			return uri
		}
		// Priority 2: X-Auth-Request-Redirect (Common in Traefik/Envoy)
		if uri := req.Header.Get("X-Auth-Request-Redirect"); uri != "" {
			return uri
		}
	}

	// Fallback 1: 'rd' query parameter
	if rd := req.URL.Query().Get("rd"); rd != "" {
		return rd
	}

	// Fallback 2: Referer header
	if referer := req.Header.Get("Referer"); referer != "" {
		return referer
	}

	// Default fallback
	return "/"
}
