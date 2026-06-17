// Package requests provides helpers for extracting request context
// and headers used during OAuth2 proxy authentication flows.
package requests

import (
	"net"
	"net/http"
	"strings"
)

const (
	// HeaderXForwardedURI is the de facto standard header set by
	// reverse proxies (nginx, Traefik, Envoy) to convey the original
	// request URI before any path rewriting.
	HeaderXForwardedURI = "X-Forwarded-Uri"

	// HeaderXAuthRequestRedirect is an alternative header used by
	// oauth2-proxy to carry the original destination URL.
	HeaderXAuthRequestRedirect = "X-Auth-Request-Redirect"
)

// RequestContext holds parsed information from an incoming HTTP
// request that is relevant to the OAuth2 proxy decision flow.
type RequestContext struct {
	// Method is the original HTTP method.
	Method string
	// URL is the full request URL as received by the proxy.
	URL string
	// RemoteAddr is the client IP address.
	RemoteAddr string
	// ForwardedURI is the original request URI extracted from
	// X-Forwarded-Uri or X-Auth-Request-Redirect headers.
	ForwardedURI string
	// IsTrustedIP indicates whether the request originated from
	// a trusted IP range (reverse proxy, load balancer).
	IsTrustedIP bool
}

// ExtractForwardedURI extracts the original request URI from incoming
// headers. It checks X-Forwarded-Uri first (de facto standard), then
// falls back to X-Auth-Request-Redirect (oauth2-proxy convention).
// Returns an empty string when neither header is present.
//
// The caller must validate the returned URI before using it as a
// redirect target to prevent open-redirect vulnerabilities.
func ExtractForwardedURI(header http.Header) string {
	if uri := header.Get(HeaderXForwardedURI); uri != "" {
		return uri
	}
	return header.Get(HeaderXAuthRequestRedirect)
}

// IsTrustedIP checks whether the provided IP address belongs to a
// trusted CIDR range. This is used to determine whether we should
// trust headers set by a reverse proxy.
func IsTrustedIP(ipStr string, trustedCIDRs []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range trustedCIDRs {
		_, cidrNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if cidrNet.Contains(ip) {
			return true
		}
	}
	return false
}

// ExtractClientIP extracts the real client IP from the request,
// respecting X-Forwarded-For when the connection comes from a trusted
// proxy. Falls back to RemoteAddr.
func ExtractClientIP(r *http.Request, trustedCIDRs []string) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		clientIP := strings.TrimSpace(parts[0])
		// Only trust XFF when the immediate peer is trusted
		peerIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil && IsTrustedIP(peerIP, trustedCIDRs) {
			return clientIP
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// NewRequestContext builds a RequestContext from an incoming request.
// It trusts X-Forwarded-* headers only when reverseProxy is enabled
// (checked via trusted CIDR ranges).
func NewRequestContext(r *http.Request, reverseProxy bool, trustedCIDRs []string) *RequestContext {
	ctx := &RequestContext{
		Method:      r.Method,
		URL:         r.URL.String(),
		RemoteAddr:  r.RemoteAddr,
		ForwardedURI: "",
		IsTrustedIP: false,
	}

	if reverseProxy {
		clientIP := ExtractClientIP(r, trustedCIDRs)
		ctx.IsTrustedIP = IsTrustedIP(clientIP, trustedCIDRs)
		if ctx.IsTrustedIP {
			ctx.ForwardedURI = ExtractForwardedURI(r.Header)
		}
	}

	return ctx
}
