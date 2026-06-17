package requests

import (
	"net/http"
	"testing"
)

func TestExtractForwardedURI_Present(t *testing.T) {
	header := http.Header{}
	header.Set("X-Forwarded-Uri", "/deep/path/resource")

	uri := ExtractForwardedURI(header)
	if uri != "/deep/path/resource" {
		t.Errorf("expected /deep/path/resource, got %q", uri)
	}
}

func TestExtractForwardedURI_FallbackToXAuthRequestRedirect(t *testing.T) {
	header := http.Header{}
	header.Set("X-Auth-Request-Redirect", "/alternate/path")

	uri := ExtractForwardedURI(header)
	if uri != "/alternate/path" {
		t.Errorf("expected /alternate/path, got %q", uri)
	}
}

func TestExtractForwardedURI_XForwardedUriTakesPriority(t *testing.T) {
	header := http.Header{}
	header.Set("X-Forwarded-Uri", "/forwarded-uri")
	header.Set("X-Auth-Request-Redirect", "/auth-request-redirect")

	uri := ExtractForwardedURI(header)
	if uri != "/forwarded-uri" {
		t.Errorf("expected X-Forwarded-Uri to take priority, got %q", uri)
	}
}

func TestExtractForwardedURI_NotPresent(t *testing.T) {
	header := http.Header{}
	header.Set("Content-Type", "application/json")

	uri := ExtractForwardedURI(header)
	if uri != "" {
		t.Errorf("expected empty string, got %q", uri)
	}
}

func TestIsTrustedIP(t *testing.T) {
	tests := []struct {
		ip      string
		cidrs   []string
		trusted bool
	}{
		{"127.0.0.1", []string{"127.0.0.1/32"}, true},
		{"10.0.0.5", []string{"10.0.0.0/8"}, true},
		{"192.168.1.1", []string{"10.0.0.0/8"}, false},
		{"10.0.0.5", []string{}, false},
		{"invalid", []string{"10.0.0.0/8"}, false},
	}
	for _, tc := range tests {
		got := IsTrustedIP(tc.ip, tc.cidrs)
		if got != tc.trusted {
			t.Errorf("IsTrustedIP(%q, %v) = %v, want %v", tc.ip, tc.cidrs, got, tc.trusted)
		}
	}
}

func TestExtractClientIP(t *testing.T) {
	// Trusted proxy scenario: X-Forwarded-For is trusted because
	// the immediate peer is in the trusted CIDR range.
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
	req.RemoteAddr = "10.0.0.1:54321"

	ip := ExtractClientIP(req, []string{"10.0.0.0/8"})
	if ip != "203.0.113.5" {
		t.Errorf("expected 203.0.113.5 (from XFF), got %q", ip)
	}

	// Untrusted proxy scenario: X-Forwarded-For is NOT trusted
	req2, _ := http.NewRequest("GET", "/", nil)
	req2.Header.Set("X-Forwarded-For", "203.0.113.5")
	req2.RemoteAddr = "100.64.0.1:54321"

	ip2 := ExtractClientIP(req2, []string{"10.0.0.0/8"})
	if ip2 == "203.0.113.5" {
		t.Errorf("expected fallback to RemoteAddr when proxy not trusted")
	}
}

func TestNewRequestContext_ReverseProxyDisabled(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-Uri", "/secret")
	req.RemoteAddr = "10.0.0.5:12345"

	ctx := NewRequestContext(req, false, []string{"10.0.0.0/8"})
	if ctx.ForwardedURI != "" {
		t.Errorf("expected empty ForwardedURI when reverse-proxy is disabled, got %q", ctx.ForwardedURI)
	}
}

func TestNewRequestContext_ReverseProxyEnabledAndTrusted(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-Uri", "/api/data")
	req.RemoteAddr = "10.0.0.5:12345"

	ctx := NewRequestContext(req, true, []string{"10.0.0.0/8"})
	if ctx.ForwardedURI != "/api/data" {
		t.Errorf("expected /api/data, got %q", ctx.ForwardedURI)
	}
	if !ctx.IsTrustedIP {
		t.Error("expected IsTrustedIP to be true")
	}
}

func TestNewRequestContext_ReverseProxyEnabledButUntrusted(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-Uri", "/api/data")
	req.RemoteAddr = "203.0.113.5:12345"

	ctx := NewRequestContext(req, true, []string{"10.0.0.0/8"})
	if ctx.ForwardedURI != "" {
		t.Errorf("expected empty ForwardedURI when client is not trusted, got %q", ctx.ForwardedURI)
	}
	if ctx.IsTrustedIP {
		t.Error("expected IsTrustedIP to be false")
	}
}
