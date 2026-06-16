package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// ---------------------------------------------------------------------------
// sanitizeRedirectURI
// ---------------------------------------------------------------------------

func TestSanitizeRedirectURI_ValidRelativePaths(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"/", "/"},
		{"/dashboard", "/dashboard"},
		{"/dashboard/reports?from=2024-01-01", "/dashboard/reports?from=2024-01-01"},
		{"/deep/nested/path", "/deep/nested/path"},
		{"relative", "/relative"},
	}

	for _, tc := range cases {
		got, err := sanitizeRedirectURI(tc.input)
		if err != nil {
			t.Errorf("sanitizeRedirectURI(%q) unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("sanitizeRedirectURI(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSanitizeRedirectURI_UnsafeInputs(t *testing.T) {
	cases := []string{
		"https://evil.com/steal",
		"http://evil.com/",
		"//evil.com/steal",
		"",
	}

	for _, tc := range cases {
		got, err := sanitizeRedirectURI(tc)
		if err == nil {
			t.Errorf("sanitizeRedirectURI(%q) expected error, got %q", tc, got)
		}
	}
}

// ---------------------------------------------------------------------------
// OriginalRequestPath
// ---------------------------------------------------------------------------

func makeRequest(xForwardedUri, xAuthRequestRedirect, rdParam string) *http.Request {
	u := &url.URL{Path: "/oauth2/sign_in"}
	if rdParam != "" {
		q := u.Query()
		q.Set("rd", rdParam)
		u.RawQuery = q.Encode()
	}
	r := &http.Request{
		Method: http.MethodGet,
		URL:    u,
		Header: make(http.Header),
	}
	if xForwardedUri != "" {
		r.Header.Set(XForwardedUri, xForwardedUri)
	}
	if xAuthRequestRedirect != "" {
		r.Header.Set(XAuthRequestRedirect, xAuthRequestRedirect)
	}
	return r
}

func TestOriginalRequestPath_XForwardedUri(t *testing.T) {
	r := makeRequest("/dashboard/reports", "", "")
	got := OriginalRequestPath(r)
	if got != "/dashboard/reports" {
		t.Errorf("expected /dashboard/reports, got %q", got)
	}
}

func TestOriginalRequestPath_XAuthRequestRedirect_TakesPrecedence(t *testing.T) {
	// X-Auth-Request-Redirect should win over X-Forwarded-Uri.
	r := makeRequest("/via-forwarded-uri", "/via-auth-request", "")
	got := OriginalRequestPath(r)
	if got != "/via-auth-request" {
		t.Errorf("expected /via-auth-request, got %q", got)
	}
}

func TestOriginalRequestPath_RdQueryParam(t *testing.T) {
	r := makeRequest("", "", "/from-query-param")
	got := OriginalRequestPath(r)
	if got != "/from-query-param" {
		t.Errorf("expected /from-query-param, got %q", got)
	}
}

func TestOriginalRequestPath_FallbackToDefault(t *testing.T) {
	r := makeRequest("", "", "")
	got := OriginalRequestPath(r)
	if got != DefaultRedirectPath {
		t.Errorf("expected %q, got %q", DefaultRedirectPath, got)
	}
}

func TestOriginalRequestPath_IgnoresUnsafeHeaders(t *testing.T) {
	// Absolute/unsafe URI in X-Forwarded-Uri should be ignored, falling back to default.
	r := makeRequest("https://evil.com/steal", "", "")
	got := OriginalRequestPath(r)
	if got != DefaultRedirectPath {
		t.Errorf("expected %q for unsafe header, got %q", DefaultRedirectPath, got)
	}
}

// ---------------------------------------------------------------------------
// BuildRefreshRedirectURL
// ---------------------------------------------------------------------------

func TestBuildRefreshRedirectURL(t *testing.T) {
	got, err := BuildRefreshRedirectURL("/oauth2/sign_in", "/dashboard/reports")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("result is not a valid URL: %v", err)
	}

	if parsed.Path != "/oauth2/sign_in" {
		t.Errorf("expected path /oauth2/sign_in, got %q", parsed.Path)
	}

	rd := parsed.Query().Get("rd")
	if rd != "/dashboard/reports" {
		t.Errorf("expected rd=/dashboard/reports, got %q", rd)
	}
}

func TestBuildRefreshRedirectURL_UnsafeOriginalPath_FallsBackToDefault(t *testing.T) {
	got, err := BuildRefreshRedirectURL("/oauth2/sign_in", "https://evil.com/steal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, _ := url.Parse(got)
	rd := parsed.Query().Get("rd")
	if rd != DefaultRedirectPath {
		t.Errorf("expected rd to fall back to %q for unsafe path, got %q", DefaultRedirectPath, rd)
	}
}

// ---------------------------------------------------------------------------
// PreserveOriginalPathMiddleware
// ---------------------------------------------------------------------------

func TestPreserveOriginalPathMiddleware(t *testing.T) {
	var capturedPath string

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = OriginalPathFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := PreserveOriginalPathMiddleware(inner)

	r := makeRequest("/my/deep/link", "", "")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if capturedPath != "/my/deep/link" {
		t.Errorf("expected context to contain /my/deep/link, got %q", capturedPath)
	}
}

// ---------------------------------------------------------------------------
// SessionRefreshHandler
// ---------------------------------------------------------------------------

func TestSessionRefreshHandler_NoRefreshNeeded(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := SessionRefreshHandler(inner, "/oauth2/sign_in", func(r *http.Request) bool {
		return false // session is valid
	})

	r := makeRequest("/protected/resource", "", "")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if !called {
		t.Error("expected inner handler to be called when no refresh is needed")
	}
}

func TestSessionRefreshHandler_RefreshNeeded_PreservesOriginalPath(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SessionRefreshHandler(inner, "/oauth2/sign_in", func(r *http.Request) bool {
		return true // session needs refresh
	})

	r := makeRequest("/dashboard/analytics", "", "")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("redirect Location is not a valid URL: %v", err)
	}

	rd := parsed.Query().Get("rd")
	if rd != "/dashboard/analytics" {
		t.Errorf("expected original path /dashboard/analytics to be preserved in rd param, got %q", rd)
	}
}

func TestSessionRefreshHandler_RefreshNeeded_FallsBackToDefaultWhenNoHeader(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SessionRefreshHandler(inner, "/oauth2/sign_in", func(r *http.Request) bool {
		return true
	})

	r := makeRequest("", "", "") // no X-Forwarded-Uri, no rd param
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	parsed, _ := url.Parse(location)
	rd := parsed.Query().Get("rd")
	if rd != DefaultRedirectPath {
		t.Errorf("expected rd to fall back to %q, got %q", DefaultRedirectPath, rd)
	}
}

// ---------------------------------------------------------------------------
// RedirectToOriginalPath
// ---------------------------------------------------------------------------

func TestRedirectToOriginalPath_UsesContextPath(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(withOriginalPath(r.Context(), "/my/original/destination"))
	w := httptest.NewRecorder()

	RedirectToOriginalPath(w, r, http.StatusFound)

	if w.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/my/original/destination" {
		t.Errorf("expected redirect to /my/original/destination, got %q", loc)
	}
}

func TestRedirectToOriginalPath_FallsBackToDefaultWhenContextEmpty(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	// No original path in context.
	w := httptest.NewRecorder()

	RedirectToOriginalPath(w, r, http.StatusFound)

	if loc := w.Header().Get("Location"); loc != DefaultRedirectPath {
		t.Errorf("expected redirect to %q, got %q", DefaultRedirectPath, loc)
	}
}
