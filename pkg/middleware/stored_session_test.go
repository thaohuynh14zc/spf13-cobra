package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRefreshMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		headers        map[string]string
		reverseProxy   bool
		allowedDomains []string
		expectedStatus int
		expectedLoc    string
	}{
		{
			name:           "Preserve original path via X-Forwarded-Uri",
			headers:        map[string]string{"X-Forwarded-Uri": "/deep/link"},
			reverseProxy:   true,
			expectedStatus: http.StatusFound,
			expectedLoc:    "/deep/link",
		},
		{
			name:           "Preserve original path via X-Auth-Request-Redirect",
			headers:        map[string]string{"X-Auth-Request-Redirect": "/another/path"},
			reverseProxy:   true,
			expectedStatus: http.StatusFound,
			expectedLoc:    "/another/path",
		},
		{
			name:           "Fallback to root when reverse-proxy is disabled",
			headers:        map[string]string{"X-Forwarded-Uri": "/deep/link"},
			reverseProxy:   false,
			expectedStatus: http.StatusFound,
			expectedLoc:    "/",
		},
		{
			name:           "Open redirect protection - invalid domain",
			headers:        map[string]string{"X-Forwarded-Uri": "http://malicious.com"},
			reverseProxy:   true,
			allowedDomains: []string{"example.com"},
			expectedStatus: http.StatusFound,
			expectedLoc:    "/",
		},
		{
			name:           "Allow valid absolute redirect",
			headers:        map[string]string{"X-Forwarded-Uri": "https://example.com/dashboard"},
			reverseProxy:   true,
			allowedDomains: []string{"example.com"},
			expectedStatus: http.StatusFound,
			expectedLoc:    "https://example.com/dashboard",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &SessionHandler{
				ReverseProxy:   tt.reverseProxy,
				AllowedDomains: tt.allowedDomains,
			}

			req := httptest.NewRequest("GET", "/oauth2/refresh", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			rr := httptest.NewRecorder()
			middleware := handler.RefreshMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			
			middleware.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %v, got %v", tt.expectedStatus, rr.Code)
			}

			loc := rr.Header().Get("Location")
			if loc != tt.expectedLoc {
				t.Errorf("expected location %v, got %v", tt.expectedLoc, loc)
			}
		})
	}
}
