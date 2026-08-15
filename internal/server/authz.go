package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gpewebdefender/internal/auth"
	"gpewebdefender/internal/store"
	"gpewebdefender/ui"
)

type ctxKey int

const userCtx ctxKey = 1

const sessionCookie = "siem_session"
const sessionTTL = 12 * time.Hour

func (s *Server) reqUser(r *http.Request) (store.User, bool) {
	u, ok := r.Context().Value(userCtx).(store.User)
	return u, ok && u.ID != 0
}

func clientIP(r *http.Request) string {
	if x := r.Header.Get("X-Real-IP"); x != "" {
		return strings.TrimSpace(strings.Split(x, ",")[0])
	}
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		return strings.TrimSpace(strings.Split(x, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, raw string) {
	c := &http.Cookie{
		Name:     sessionCookie,
		Value:    raw,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	}
	if r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil {
		c.Secure = true
	}
	http.SetCookie(w, c)
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func openPath(p string) bool {
	switch p {
	case "/api/health", "/api/login", "/api/setup", "/api/auth-status", "/login", "/login.html":
		return true
	case "/app.css", "/app.js", "/map-basemap.jpg":
		return true
	default:
		return false
	}
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")

		if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
			if u, err := s.Store.SessionUser(c.Value); err == nil {
				r = r.WithContext(context.WithValue(r.Context(), userCtx, u))
			}
		}

		if r.URL.Path == "/api/ingest" {
			if !s.bearerOK(r) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		if openPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		usersOn := s.Store.UserCount() > 0
		if !usersOn {
			// Legacy: ingest token still gates /api/* if set. UI stays reachable
			// so the first operator can open /login and create an admin.
			if s.Token != "" && strings.HasPrefix(r.URL.Path, "/api/") && !s.bearerOK(r) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		if _, ok := s.reqUser(r); !ok {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if r.URL.Path == "/" || r.URL.Path == "/index.html" || strings.HasPrefix(r.URL.Path, "/docs") {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) bearerOK(r *http.Request) bool {
	if s.Token == "" {
		return false
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got == "" {
		got = r.URL.Query().Get("token")
	}
	if got == "" {
		return false
	}
	return auth.TokensEqual(got, s.Token)
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	ct := r.Header.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	if strings.TrimSpace(ct) != "application/json" {
		http.Error(w, "json required", http.StatusUnsupportedMediaType)
		return false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(dst); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return false
	}
	return true
}

func (s *Server) serveLogin(w http.ResponseWriter, r *http.Request) {
	b, err := ui.FS.ReadFile("login.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

func (s *Server) authStatus(w http.ResponseWriter, _ *http.Request) {
	n := s.Store.UserCount()
	writeJSON(w, map[string]any{"users": n, "setup": n == 0})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	u, ok := s.reqUser(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	u.Hash = ""
	writeJSON(w, u)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ip := clientIP(r)
	user := strings.ToLower(strings.TrimSpace(in.Username))
	if s.Store.LockedOut(user, ip) {
		http.Error(w, "too many attempts — wait 15 minutes", http.StatusTooManyRequests)
		return
	}
	u, err := s.Store.UserByName(user)
	if err != nil || u.Disabled {
		_ = auth.CheckPassword(mustDummy(), in.Password)
		s.Store.RecordFail(user, ip)
		time.Sleep(200 * time.Millisecond)
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}
	if !auth.CheckPassword(u.Hash, in.Password) {
		s.Store.RecordFail(user, ip)
		time.Sleep(200 * time.Millisecond)
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}
	s.Store.ClearFails(user, ip)
	raw, err := s.Store.NewSession(u.ID, ip, sessionTTL)
	if err != nil {
		http.Error(w, "session", http.StatusInternalServerError)
		return
	}
	s.Store.TouchLogin(u.ID)
	s.setSessionCookie(w, r, raw)
	u.Hash = ""
	writeJSON(w, map[string]any{"ok": true, "user": u})
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if s.Store.UserCount() > 0 {
		http.Error(w, "already set up", http.StatusConflict)
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	u, err := s.Store.CreateUser(in.Username, in.Password, "admin")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	raw, err := s.Store.NewSession(u.ID, clientIP(r), sessionTTL)
	if err != nil {
		http.Error(w, "session", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, r, raw)
	writeJSON(w, map[string]any{"ok": true, "user": u})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.Store.RevokeSession(c.Value)
	}
	s.clearSessionCookie(w)
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	u, ok := s.reqUser(r)
	if !ok || u.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return u, false
	}
	return u, true
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	list, err := s.Store.ListUsers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, list)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	u, err := s.Store.CreateUser(in.Username, in.Password, in.Role)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, u)
}

func parseUserID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	id, ok := parseUserID(r)
	if !ok {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := s.Store.DeleteUser(id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) adminSetPassword(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	id, ok := parseUserID(r)
	if !ok {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	var in struct {
		Next string `json:"next"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if err := s.Store.SetPassword(id, in.Next); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.Store.RevokeUserSessions(id)
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) disableUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	id, ok := parseUserID(r)
	if !ok {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	var in struct {
		Disabled bool `json:"disabled"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if err := s.Store.SetUserDisabled(id, in.Disabled); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	u, ok := s.reqUser(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var in struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	full, err := s.Store.UserByID(u.ID)
	if err != nil || !auth.CheckPassword(full.Hash, in.Current) {
		http.Error(w, "current password is wrong", http.StatusForbidden)
		return
	}
	if err := s.Store.SetPassword(u.ID, in.Next); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.Store.RevokeUserSessions(u.ID)
	raw, err := s.Store.NewSession(u.ID, clientIP(r), sessionTTL)
	if err == nil {
		s.setSessionCookie(w, r, raw)
	}
	writeJSON(w, map[string]any{"ok": true})
}

var dummyOnce string

func mustDummy() string {
	if dummyOnce == "" {
		dummyOnce, _ = auth.HashPassword("not-used-for-compare")
	}
	return dummyOnce
}
