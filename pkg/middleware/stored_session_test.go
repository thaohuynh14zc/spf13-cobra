package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestSession returns a session that expires soon, suitable for
// testing the refresh flow.
func newTestSession() *SessionState {
	return &SessionState{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		ExpiresAt:    time.Now().Add(5 * time.Second), // expires soon
		Email:        "test@example.com",
		Subject:      "test-subject",
		CreatedAt:    time.Now().Add(-30 * time.Minute),
	}
}

// newExpiredSession returns an already-expired session.
func newExpiredSession() *SessionState {
	return &SessionState{
		AccessToken:  "expired-access-token",
		RefreshToken: "test-refresh-token",
		ExpiresAt:    time.Now().Add(-10 * time.Minute),
		Email:        "test@example.com",
		Subject:      "test-subject",
		CreatedAt:    time.Now().Add(-30 * time.Minute),
	}
}

func TestSessionState_IsExpired(t *testing.T) {
	t.Run("fresh session is not expired", func(t *testing.T) {
		s := &SessionState{
			AccessToken: "tok",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		}
		if s.IsExpired() {
			t.Error("expected session to NOT be expired")
		}
	})

	t.Run("expired session returns true", func(t *testing.T) {
		s := &SessionState{
			AccessToken: "tok",
			ExpiresAt:   time.Now().Add(-1 * time.Hour),
		}
		if !s.IsExpired() {
			t.Error("expected session to be expired")
		}
	})
}

func TestSessionState_CanRefresh(t *testing.T) {
	t.Run("has refresh token and within TTL", func(t *testing.T) {
		s := &SessionState{
			RefreshToken: "rtok",
			CreatedAt:    time.Now().Add(-1 * time.Hour),
		}
		if !s.CanRefresh() {
			t.Error("expected CanRefresh to be true")
		}
	})

	t.Run("no refresh token returns false", func(t *testing.T) {
		s := &SessionState{
			RefreshToken: "",
			CreatedAt:    time.Now().Add(-1 * time.Hour),
		}
		if s.CanRefresh() {
			t.Error("expected CanRefresh to be false without refresh token")
		}
	})

	t.Run("expired TTL returns false", func(t *testing.T) {
		s := &SessionState{
			RefreshToken: "rtok",
			CreatedAt:    time.Now().Add(-48 * time.Hour),
		}
		if s.CanRefresh() {
			t.Error("expected CanRefresh to be false after TTL expiry")
		}
	})
}

func TestSessionStore(t *testing.T) {
	store := NewSessionStore()
	session := newTestSession()

	store.Set("sess-1", session)
	if got := store.Get("sess-1"); got == nil {
		t.Fatal("expected to get session")
	}

	store.Delete("sess-1")
	if got := store.Get("sess-1"); got != nil {
		t.Error("expected nil after delete")
	}
}

func TestSessionRefreshMiddleware_XForwardedUriPreserved(t *testing.T) {
	store := NewSessionStore()
	session := newExpiredSession()
	store.Set("sess-refresh", session)

	mw := NewSessionRefreshMiddleware(store, true, []string{"127.0.0.1/32", "10.0.0.0/8"})
	mw.CookieName = "_oauth2_proxy_test"

	// Record refresh events
	refreshCalled := false
	mw.TokenRefreshFunc = func(s *SessionState) (*SessionState, error) {
		refreshCalled = true
		newS := *s
		newS.ExpiresAt = time.Now().Add(1 * time.Hour)
		return &newS, nil
	}

	// Set up a request with X-Forwarded-Uri header and expired session cookie
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Uri", "/deep/path/to/resource")
	req.AddCookie(&http.Cookie{Name: "_oauth2_proxy_test", Value: "sess-refresh"})
	// Simulate trusted proxy (remote addr on trusted CIDR)
	req.RemoteAddr = "10.0.0.5:34567"

	w := httptest.NewRecorder()
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw.Wrap(nextHandler).ServeHTTP(w, req)

	if !refreshCalled {
		t.Error("expected TokenRefreshFunc to be called")
	}

	resp := w.Result()
	// Should be a redirect (302) back to the X-Forwarded-Uri
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected 302 Found, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	expectedLocation := "/deep/path/to/resource"
	if location != expectedLocation {
		t.Errorf("expected Location header %q, got %q", expectedLocation, location)
	}
}

func TestSessionRefreshMiddleware_MissingHeaderFallsBackToDefault(t *testing.T) {
	store := NewSessionStore()
	session := newExpiredSession()
	store.Set("sess-fallback", session)

	mw := NewSessionRefreshMiddleware(store, true, []string{"127.0.0.1/32"})
	mw.CookieName = "_oauth2_proxy_test"
	mw.SetDefaultRedirect("/default-landing")

	mw.TokenRefreshFunc = func(s *SessionState) (*SessionState, error) {
		newS := *s
		newS.ExpiresAt = time.Now().Add(1 * time.Hour)
		return &newS, nil
	}

	// Request without X-Forwarded-Uri header
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "_oauth2_proxy_test", Value: "sess-fallback"})

	w := httptest.NewRecorder()
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw.Wrap(nextHandler).ServeHTTP(w, req)

	resp := w.Result()
	location := resp.Header.Get("Location")
	if location != "/default-landing" {
		t.Errorf("expected Location %q, got %q", "/default-landing", location)
	}
}

func TestSessionRefreshMiddleware_TokenRefreshFailure(t *testing.T) {
	store := NewSessionStore()
	session := newExpiredSession()
	store.Set("sess-fail", session)

	mw := NewSessionRefreshMiddleware(store, false, nil)
	mw.CookieName = "_oauth2_proxy_test"

	mw.TokenRefreshFunc = func(s *SessionState) (*SessionState, error) {
		return nil, http.ErrAbortHandler
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "_oauth2_proxy_test", Value: "sess-fail"})

	w := httptest.NewRecorder()
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw.Wrap(nextHandler).ServeHTTP(w, req)

	resp := w.Result()
	location := resp.Header.Get("Location")
	if location != "/" {
		t.Errorf("expected fallback redirect to /, got %q", location)
	}

	// Session should be deleted after failed refresh
	if store.Get("sess-fail") != nil {
		t.Error("expected session to be deleted after failed refresh")
	}
}

func TestSessionRefreshMiddleware_ValidSessionNoRefresh(t *testing.T) {
	store := NewSessionStore()
	session := newTestSession()
	session.ExpiresAt = time.Now().Add(1 * time.Hour) // still valid
	store.Set("sess-valid", session)

	mw := NewSessionRefreshMiddleware(store, false, nil)
	mw.CookieName = "_oauth2_proxy_test"

	refreshCalled := false
	mw.TokenRefreshFunc = func(s *SessionState) (*SessionState, error) {
		refreshCalled = true
		return s, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/protected/resource", nil)
	req.AddCookie(&http.Cookie{Name: "_oauth2_proxy_test", Value: "sess-valid"})

	w := httptest.NewRecorder()
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("protected content"))
	})

	mw.Wrap(nextHandler).ServeHTTP(w, req)

	if refreshCalled {
		t.Error("did NOT expect refresh to be called for a valid session")
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSessionRefreshMiddleware_InvalidRedirectBlocked(t *testing.T) {
	store := NewSessionStore()
	session := newExpiredSession()
	store.Set("sess-blocked", session)

	mw := NewSessionRefreshMiddleware(store, true, []string{"127.0.0.1/32"})
	mw.CookieName = "_oauth2_proxy_test"
	// Restrict allowed domains so evil.com is blocked
	mw.SetAllowedDomains([]string{"example.com", "*.example.org"})

	mw.TokenRefreshFunc = func(s *SessionState) (*SessionState, error) {
		newS := *s
		newS.ExpiresAt = time.Now().Add(1 * time.Hour)
		return &newS, nil
	}

	// Malicious external redirect
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Uri", "http://evil.com/phishing")
	req.AddCookie(&http.Cookie{Name: "_oauth2_proxy_test", Value: "sess-blocked"})
	req.RemoteAddr = "127.0.0.1:56789"

	w := httptest.NewRecorder()
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw.Wrap(nextHandler).ServeHTTP(w, req)

	resp := w.Result()
	location := resp.Header.Get("Location")
	if location != "/" {
		t.Errorf("expected redirect to safe default (/), got %q (open redirect vulnerability!)", location)
	}
}

func TestSessionFromJSON(t *testing.T) {
	data := []byte(`{"access_token":"at","refresh_token":"rt","email":"a@b.com","subject":"sub"}`)
	s, err := SessionFromJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.AccessToken != "at" {
		t.Errorf("expected access_token 'at', got %q", s.AccessToken)
	}
	if s.Email != "a@b.com" {
		t.Errorf("expected email 'a@b.com', got %q", s.Email)
	}
}

func TestSessionToJSON(t *testing.T) {
	s := &SessionState{
		AccessToken:  "tok",
		RefreshToken: "rtok",
		Email:        "x@y.com",
		Subject:      "sub",
	}
	data, err := SessionToJSON(s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s2, err := SessionFromJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s2.Email != s.Email {
		t.Errorf("round-trip failed: %q != %q", s2.Email, s.Email)
	}
}
