package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPairRequiresAdminAndPhrase(t *testing.T) {
	s, h := testServer(t, "ingest-secret")
	if _, err := s.Store.CreateUser("boss", "first-admin-pass", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.CreateUser("eye", "viewer-long-pw", "viewer"); err != nil {
		t.Fatal(err)
	}
	view := loginCookies(t, h, "eye", "viewer-long-pw")
	admin := loginCookies(t, h, "boss", "first-admin-pass")

	rec := postJSON(h, "/api/pair-codes", `{}`, view)
	if rec.Code != 403 {
		t.Fatalf("viewer mint: %d", rec.Code)
	}
	rec = postJSON(h, "/api/pair-phrase", `{"phrase":"correct-horse-phrase"}`, view)
	if rec.Code != 403 {
		t.Fatalf("viewer phrase: %d", rec.Code)
	}
	rec = postJSON(h, "/api/pair-codes", `{}`, admin)
	if rec.Code != 400 {
		t.Fatalf("mint before phrase: %d %s", rec.Code, rec.Body.String())
	}
	rec = postJSON(h, "/api/pair-phrase", `{"phrase":"correct-horse-phrase"}`, admin)
	if rec.Code != 200 {
		t.Fatalf("set phrase: %d %s", rec.Code, rec.Body.String())
	}
	rec = postJSON(h, "/api/pair-codes", `{}`, admin)
	if rec.Code != 200 {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body.String())
	}
	var minted struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil || minted.Code == "" {
		t.Fatal(rec.Body.String())
	}

	rec = postJSON(h, "/api/agent/pair", `{
		"name":"web-1","code":"`+minted.Code+`","phrase":"wrong-phrase-xx","os":"linux"
	}`, nil)
	if rec.Code != 403 {
		t.Fatalf("bad phrase: %d %s", rec.Code, rec.Body.String())
	}
	rec = postJSON(h, "/api/agent/pair", `{
		"name":"web-1","code":"`+minted.Code+`","phrase":"correct-horse-phrase","os":"linux"
	}`, nil)
	if rec.Code != 200 {
		t.Fatalf("pair: %d %s", rec.Code, rec.Body.String())
	}
	var paired struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
		Status string `json:"status"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &paired)
	if paired.Secret == "" || paired.Status != "pending" {
		t.Fatal(rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/commands", nil)
	req.Header.Set("Authorization", "Bearer "+paired.Secret)
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("commands while pending: %d", rec.Code)
	}

	rec = postJSON(h, "/api/agents/"+paired.ID+"/approve", `{}`, view)
	if rec.Code != 403 {
		t.Fatalf("viewer approve: %d", rec.Code)
	}
	rec = postJSON(h, "/api/agents/"+paired.ID+"/approve", `{}`, admin)
	if rec.Code != 200 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}

	rec = postJSON(h, "/api/agents/"+paired.ID+"/ban", `{"ip":"10.1.1.1","duration":"1h"}`, admin)
	if rec.Code != 400 {
		t.Fatalf("private ban: %d %s", rec.Code, rec.Body.String())
	}
	rec = postJSON(h, "/api/agents/"+paired.ID+"/ban", `{"ip":"198.51.100.20","duration":"1h"}`, view)
	if rec.Code != 403 {
		t.Fatalf("viewer ban: %d", rec.Code)
	}
	rec = postJSON(h, "/api/agents/"+paired.ID+"/ban", `{"ip":"198.51.100.20","duration":"1h"}`, admin)
	if rec.Code != 200 {
		t.Fatalf("ban: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/agent/commands", nil)
	req.Header.Set("Authorization", "Bearer "+paired.Secret)
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "198.51.100.20") {
		t.Fatalf("pickup: %d %s", rec.Code, rec.Body.String())
	}

	// ingest token still cannot mint
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/pair-codes", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer ingest-secret")
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("ingest mint: %d", rec.Code)
	}
}

func TestHostStatusCheckIsOnDemandAndAdmin(t *testing.T) {
	s, h := testServer(t, "ingest-secret")
	s.Version = "test"
	if _, err := s.Store.CreateUser("boss", "first-admin-pass", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.CreateUser("eye", "viewer-long-pw", "viewer"); err != nil {
		t.Fatal(err)
	}
	view := loginCookies(t, h, "eye", "viewer-long-pw")
	admin := loginCookies(t, h, "boss", "first-admin-pass")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	for _, c := range view {
		req.AddCookie(c)
	}
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"name":"manager"`) {
		t.Fatalf("viewer status: %d %s", rec.Code, rec.Body.String())
	}

	rec = postJSON(h, "/api/status/check", `{}`, view)
	if rec.Code != 403 {
		t.Fatalf("viewer check: %d", rec.Code)
	}
	rec = postJSON(h, "/api/agents/check-all", `{}`, view)
	if rec.Code != 403 {
		t.Fatalf("viewer check-all: %d", rec.Code)
	}

	rec = postJSON(h, "/api/status/check", `{}`, admin)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("admin check: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	for _, c := range admin {
		req.AddCookie(c)
	}
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"hostname"`) {
		t.Fatalf("after check: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/status/check", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer ingest-secret")
	h.ServeHTTP(rec, req)
	if rec.Code != 403 && rec.Code != 401 {
		t.Fatalf("ingest check: %d", rec.Code)
	}
}

func loginCookies(t *testing.T, h http.Handler, user, pass string) []*http.Cookie {
	t.Helper()
	rec := postJSON(h, "/api/login", `{"username":"`+user+`","password":"`+pass+`"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("login %s: %d %s", user, rec.Code, rec.Body.String())
	}
	var out []*http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		t.Fatal("no cookie")
	}
	return out
}
