package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSessionRefreshMiddleware_ExtractOriginalURI(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name: "X-Forwarded-Uri present",
			headers: map[string]string{
				"X-Forwarded-Uri": "/original/path",
			},
			expected: "/original/path",
		},
		{
			name: "X-Auth-Request-Redirect present",
			headers: map[string]string{
				"X-Auth-Request-Redirect": "/other/path",
			},
			expected: "/other/path",
		},
		{
			name: "Both headers present, X-Forwarded-Uri takes precedence",
			headers: map[string]string{
				"X-Forwarded-Uri":        "/primary",
				"X-Auth-Request-Redirect": "/secondary",
			},
			expected: "/primary",
		},
		{
			name:     "No headers present",
			headers:  map[string]string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			m := NewSessionRefreshMiddleware("/default", []string{}, true)
			result := m.extractOriginalURI(req)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestSessionRefreshMiddleware_IsValidRedirect(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		domains  []string
		expected bool
	}{
		{
			name:     "relative path",
			uri:      "/valid/path",
			domains:  []string{},
			expected: true,
		},
		{
			name:     "absolute URL with allowed domain",
			uri:      "https://example.com/path",
			domains:  []string{"example.com"},
			expected: true,
		},
		{
			name:     "absolute URL with subdomain of allowed domain",
			uri:      "https://sub.example.com/path",
			domains:  []string{"example.com"},
			expected: true,
		},
		{
			name:     "absolute URL with disallowed domain",
			uri:      "https://evil.com/path",
			domains:  []string{"example.com"},
			expected: false,
		},
		{
			name:     "invalid URI",
			uri:      "://invalid",
			domains:  []string{},
			expected: false,
		},
		{
			name:     "empty URI",
			uri:      "",
			domains:  []string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewSessionRefreshMiddleware("/default", tt.domains, true)
			result := m.isValidRedirect(tt.uri)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSessionRefreshMiddleware_Handler(t *testing.T) {
	tests := []struct {
		name           string
		enabled        bool
		headers        map[string]string
		expectedURI    string
		fallbackURI    string
		allowedDomains []string
	}{
		{
			name:    "middleware disabled, no change",
			enabled: false,
			headers: map[string]string{
				"X-Forwarded-Uri": "/original",
			},
			expectedURI:    "",
			fallbackURI:    "/default",
			allowedDomains: []string{},
		},
		{
			name:    "valid X-Forwarded-Uri",
			enabled: true,
			headers: map[string]string{
				"X-Forwarded-Uri": "/original/path",
			},
			expectedURI:    "/original/path",
			fallbackURI:    "/default",
			allowedDomains: []string{},
		},
		{
			name:    "missing header, fallback to default",
			enabled: true,
			headers: map[string]string{},
			expectedURI:    "/default",
			fallbackURI:    "/default",
			allowedDomains: []string{},
		},
		{
			name:    "invalid absolute URL, fallback to default",
			enabled: true,
			headers: map[string]string{
				"X-Forwarded-Uri": "https://evil.com/path",
			},
			expectedURI:    "/default",
			fallbackURI:    "/default",
			allowedDomains: []string{"example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			m := NewSessionRefreshMiddleware(tt.fallbackURI, tt.allowedDomains, tt.enabled)
			nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				uri := GetOriginalURI(r)
				if uri != tt.expectedURI {
					t.Errorf("expected URI %q, got %q", tt.expectedURI, uri)
				}
			})

			m.Handler(nextHandler).ServeHTTP(httptest.NewRecorder(), req)
		})
	}
}
