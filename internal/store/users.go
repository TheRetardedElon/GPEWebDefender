package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"gpewebdefender/internal/auth"
)

type User struct {
	ID          int64     `json:"id"`
	Username    string    `json:"username"`
	Role        string    `json:"role"`
	Disabled    bool      `json:"disabled"`
	Created     time.Time `json:"created"`
	LastLogin   time.Time `json:"last_login,omitempty"`
	Hash        string    `json:"-"`
}

func (s *Store) initUsers() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  hash TEXT NOT NULL,
  role TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_ms INTEGER NOT NULL,
  last_login_ms INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL,
  created_ms INTEGER NOT NULL,
  ip TEXT
);
CREATE TABLE IF NOT EXISTS login_fails (
  username TEXT NOT NULL,
  ip TEXT NOT NULL,
  ts_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS lf_lookup ON login_fails(username, ip, ts_ms);
`)
	return err
}

func (s *Store) UserCount() int {
	if n := s.userCount.Load(); n >= 0 {
		return int(n)
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	s.userCount.Store(int64(n))
	return n
}

func (s *Store) CreateUser(username, password, role string) (User, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if !auth.ValidUsername(username) {
		return User{}, fmt.Errorf("username must be 3–32 letters, numbers, . _ -")
	}
	if err := auth.ValidPassword(password, username); err != nil {
		return User{}, err
	}
	if role != "admin" && role != "viewer" {
		role = "viewer"
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return User{}, err
	}
	now := time.Now().UnixMilli()
	res, err := s.db.Exec(`INSERT INTO users(username, hash, role, disabled, created_ms) VALUES(?,?,?,0,?)`,
		username, hash, role, now)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return User{}, fmt.Errorf("username already exists")
		}
		return User{}, err
	}
	id, _ := res.LastInsertId()
	s.userCount.Add(1)
	return User{ID: id, Username: username, Role: role, Created: time.UnixMilli(now).UTC()}, nil
}

func (s *Store) UserByName(username string) (User, error) {
	return s.scanUser(`SELECT id, username, hash, role, disabled, created_ms, last_login_ms FROM users WHERE username = ?`,
		strings.ToLower(strings.TrimSpace(username)))
}

func (s *Store) UserByID(id int64) (User, error) {
	return s.scanUser(`SELECT id, username, hash, role, disabled, created_ms, last_login_ms FROM users WHERE id = ?`, id)
}

func (s *Store) scanUser(q string, arg any) (User, error) {
	var u User
	var dis int
	var created, last int64
	err := s.db.QueryRow(q, arg).Scan(&u.ID, &u.Username, &u.Hash, &u.Role, &dis, &created, &last)
	if err == sql.ErrNoRows {
		return User{}, fmt.Errorf("not found")
	}
	if err != nil {
		return User{}, err
	}
	u.Disabled = dis != 0
	u.Created = time.UnixMilli(created).UTC()
	if last > 0 {
		u.LastLogin = time.UnixMilli(last).UTC()
	}
	return u, nil
}

func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT id, username, hash, role, disabled, created_ms, last_login_ms FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var dis int
		var created, last int64
		if err := rows.Scan(&u.ID, &u.Username, &u.Hash, &u.Role, &dis, &created, &last); err != nil {
			return nil, err
		}
		u.Hash = ""
		u.Disabled = dis != 0
		u.Created = time.UnixMilli(created).UTC()
		if last > 0 {
			u.LastLogin = time.UnixMilli(last).UTC()
		}
		out = append(out, u)
	}
	if out == nil {
		out = []User{}
	}
	return out, rows.Err()
}

func (s *Store) SetPassword(id int64, password string) error {
	u, err := s.UserByID(id)
	if err != nil {
		return err
	}
	if err := auth.ValidPassword(password, u.Username); err != nil {
		return err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE users SET hash = ? WHERE id = ?`, hash, id)
	return err
}

func (s *Store) SetUserDisabled(id int64, disabled bool) error {
	u, err := s.UserByID(id)
	if err != nil {
		return err
	}
	if disabled && u.Role == "admin" {
		var n int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?`, id).Scan(&n)
		if n < 1 {
			return fmt.Errorf("cannot disable the last admin")
		}
	}
	v := 0
	if disabled {
		v = 1
	}
	if _, err := s.db.Exec(`UPDATE users SET disabled = ? WHERE id = ?`, v, id); err != nil {
		return err
	}
	if disabled {
		s.RevokeUserSessions(id)
	}
	return nil
}

func (s *Store) DeleteUser(id int64) error {
	var admins int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?`, id).Scan(&admins)
	u, err := s.UserByID(id)
	if err != nil {
		return err
	}
	if u.Role == "admin" && admins < 1 {
		return fmt.Errorf("cannot delete the last admin")
	}
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, id)
	_, err = s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err == nil {
		s.userCount.Add(-1)
	}
	return err
}

func (s *Store) TouchLogin(id int64) {
	_, _ = s.db.Exec(`UPDATE users SET last_login_ms = ? WHERE id = ?`, time.Now().UnixMilli(), id)
}

func (s *Store) LockedOut(username, ip string) bool {
	cut := time.Now().Add(-15 * time.Minute).UnixMilli()
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM login_fails WHERE username = ? AND ip = ? AND ts_ms >= ?`,
		strings.ToLower(username), ip, cut).Scan(&n)
	return n >= 8
}

func (s *Store) RecordFail(username, ip string) {
	_, _ = s.db.Exec(`INSERT INTO login_fails(username, ip, ts_ms) VALUES(?,?,?)`,
		strings.ToLower(username), ip, time.Now().UnixMilli())
	cut := time.Now().Add(-24 * time.Hour).UnixMilli()
	_, _ = s.db.Exec(`DELETE FROM login_fails WHERE ts_ms < ?`, cut)
}

func (s *Store) ClearFails(username, ip string) {
	_, _ = s.db.Exec(`DELETE FROM login_fails WHERE username = ? AND ip = ?`, strings.ToLower(username), ip)
}

func (s *Store) NewSession(userID int64, ip string, ttl time.Duration) (raw string, err error) {
	raw, err = auth.RandomToken(32)
	if err != nil {
		return "", err
	}
	now := time.Now()
	_, err = s.db.Exec(`INSERT INTO sessions(token_hash, user_id, expires_ms, created_ms, ip) VALUES(?,?,?,?,?)`,
		auth.TokenHash(raw), userID, now.Add(ttl).UnixMilli(), now.UnixMilli(), ip)
	return raw, err
}

func (s *Store) SessionUser(raw string) (User, error) {
	if raw == "" {
		return User{}, fmt.Errorf("no session")
	}
	var uid, exp int64
	err := s.db.QueryRow(`SELECT user_id, expires_ms FROM sessions WHERE token_hash = ?`, auth.TokenHash(raw)).Scan(&uid, &exp)
	if err != nil {
		return User{}, fmt.Errorf("no session")
	}
	if time.Now().UnixMilli() > exp {
		_, _ = s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, auth.TokenHash(raw))
		return User{}, fmt.Errorf("expired")
	}
	u, err := s.UserByID(uid)
	if err != nil || u.Disabled {
		return User{}, fmt.Errorf("no session")
	}
	return u, nil
}

func (s *Store) RevokeSession(raw string) {
	if raw == "" {
		return
	}
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, auth.TokenHash(raw))
}

func (s *Store) RevokeUserSessions(userID int64) {
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
}

func (s *Store) SweepSessions() {
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE expires_ms < ?`, time.Now().UnixMilli())
}
