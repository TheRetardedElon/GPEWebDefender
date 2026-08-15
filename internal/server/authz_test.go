package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"gpewebdefender/internal/store"
)

func testServer(t *testing.T, token string) (*Server, http.Handler) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{Store: st, Token: token}
	return s, s.Handler()
}

func postJSON(h http.Handler, path, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestSetupLoginAndIngestSplit(t *testing.T) {
	_, h := testServer(t, "ingest-secret")

	if rec := httptest.NewRecorder(); true {
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))
		if rec.Code != 200 {
			t.Fatalf("health: %d", rec.Code)
		}
	}

	// Token required for API before any users exist.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
	if rec.Code != 401 {
		t.Fatalf("settings no token: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	req.Header.Set("Authorization", "Bearer ingest-secret")
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("settings bearer: %d %s", rec.Code, rec.Body.String())
	}

	// Ingest without token is 401 even before users exist.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(nil)))
	if rec.Code != 401 {
		t.Fatalf("ingest open: %d", rec.Code)
	}

	rec = postJSON(h, "/api/setup", `{"username":"ops","password":"first-admin-pass"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body.String())
	}
	var cookies []*http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			cookies = append(cookies, c)
		}
	}
	if len(cookies) == 0 {
		t.Fatal("no session cookie")
	}

	// After users exist, ingest token no longer unlocks the UI API.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	req.Header.Set("Authorization", "Bearer ingest-secret")
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("bearer still opens UI: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	req.AddCookie(cookies[0])
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("session settings: %d %s", rec.Code, rec.Body.String())
	}

	// Ingest still requires the ingest token, not a session.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(nil))
	req.AddCookie(cookies[0])
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("session ingest: %d", rec.Code)
	}
}

func TestLoginRejectsNonJSONAndBadPassword(t *testing.T) {
	s, h := testServer(t, "")
	if _, err := s.Store.CreateUser("ops", "first-admin-pass", "admin"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader("username=ops&password=first-admin-pass"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 415 {
		t.Fatalf("form login: %d", rec.Code)
	}
	rec = postJSON(h, "/api/login", `{"username":"ops","password":"nope-nope-nope"}`, nil)
	if rec.Code != 401 {
		t.Fatalf("bad pw: %d", rec.Code)
	}
	rec = postJSON(h, "/api/login", `{"username":"ops","password":"first-admin-pass"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("good login: %d %s", rec.Code, rec.Body.String())
	}
}

func TestViewerCannotCreateUsers(t *testing.T) {
	s, h := testServer(t, "")
	if _, err := s.Store.CreateUser("boss", "first-admin-pass", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.CreateUser("eye", "viewer-long-pw", "viewer"); err != nil {
		t.Fatal(err)
	}
	rec := postJSON(h, "/api/login", `{"username":"eye","password":"viewer-long-pw"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	var cookies []*http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			cookies = append(cookies, c)
		}
	}
	rec = postJSON(h, "/api/users", `{"username":"other","password":"another-long-pw","role":"admin"}`, cookies)
	if rec.Code != 403 {
		t.Fatalf("viewer create: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"site_name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookies[0])
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("viewer settings: %d", rec.Code)
	}
}

func TestLastAdminAndPasswordChange(t *testing.T) {
	s, h := testServer(t, "")
	admin, err := s.Store.CreateUser("boss", "first-admin-pass", "admin")
	if err != nil {
		t.Fatal(err)
	}
	rec := postJSON(h, "/api/login", `{"username":"boss","password":"first-admin-pass"}`, nil)
	var cookies []*http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			cookies = append(cookies, c)
		}
	}
	del := httptest.NewRequest(http.MethodDelete, "/api/users/"+itoa(admin.ID), nil)
	del.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, del)
	if rec.Code != 400 {
		t.Fatalf("delete last admin: %d %s", rec.Code, rec.Body.String())
	}
	rec = postJSON(h, "/api/me/password", `{"current":"wrong-password","next":"brand-new-pass"}`, cookies)
	if rec.Code != 403 {
		t.Fatalf("wrong current: %d", rec.Code)
	}
	rec = postJSON(h, "/api/me/password", `{"current":"first-admin-pass","next":"brand-new-pass"}`, cookies)
	if rec.Code != 200 {
		t.Fatalf("change pw: %d %s", rec.Code, rec.Body.String())
	}
	// old cookie revoked
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.AddCookie(cookies[0])
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("old session: %d", rec.Code)
	}
}

func TestLoginPageEmbedded(t *testing.T) {
	_, h := testServer(t, "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "operator") {
		t.Fatalf("login page: %d %s", rec.Code, rec.Body.String()[:min(80, rec.Body.Len())])
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
