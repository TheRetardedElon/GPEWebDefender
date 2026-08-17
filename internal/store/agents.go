package store

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"gpewebdefender/internal/auth"
	"gpewebdefender/internal/block"
)

const (
	AgentPending  = "pending"
	AgentActive   = "active"
	AgentRejected = "rejected"
	AgentRevoked  = "revoked"

	CmdQueued  = "queued"
	CmdSent    = "sent"
	CmdDone    = "done"
	CmdFailed  = "failed"
	CmdExpired = "expired"

	pairCodeTTL    = 15 * time.Minute
	commandPickup  = 2 * time.Minute
	maxActiveBans  = 200
	pairAlphabet   = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

type Agent struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	OS         string    `json:"os,omitempty"`
	Hostname   string    `json:"hostname,omitempty"`
	Version    string    `json:"version,omitempty"`
	SeenIP     string    `json:"seen_ip,omitempty"`
	Block      string    `json:"block,omitempty"`
	Jail       string    `json:"jail,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Created    time.Time `json:"created"`
	Approved   time.Time `json:"approved,omitempty"`
	ApprovedBy string    `json:"approved_by,omitempty"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
	SecretHash string    `json:"-"`
}

type PairCode struct {
	ID      int64     `json:"id"`
	Expires time.Time `json:"expires"`
	By      string    `json:"created_by,omitempty"`
}

type AgentCommand struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	Action    string    `json:"action"`
	IP        string    `json:"ip,omitempty"`
	Until     time.Time `json:"until,omitempty"`
	Duration  string    `json:"duration,omitempty"`
	Status    string    `json:"status"`
	Result    string    `json:"result,omitempty"`
	Created   time.Time `json:"created"`
	CreatedBy string    `json:"created_by,omitempty"`
	Expires   time.Time `json:"expires"`
}

type BanWhy struct {
	Title    string `json:"title,omitempty"`
	Category string `json:"category,omitempty"`
	AlertNum int64  `json:"alert_num,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

type AgentBan struct {
	IP        string    `json:"ip"`
	Host      string    `json:"host,omitempty"`
	AgentID   string    `json:"agent_id,omitempty"`
	Until     time.Time `json:"until,omitempty"`
	Duration  string    `json:"duration,omitempty"`
	Created   time.Time `json:"created"`
	CreatedBy string    `json:"created_by,omitempty"`
	Active    bool      `json:"active"`
	Title     string    `json:"title,omitempty"`
	Category  string    `json:"category,omitempty"`
	AlertNum  int64     `json:"alert_num,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	Applied   string    `json:"applied,omitempty"`
	HitsAfter int64     `json:"hits_after,omitempty"`
}

type BlockReport struct {
	Active  int        `json:"active"`
	IPs     int        `json:"ips"`
	Applied int        `json:"applied"`
	Failed  int        `json:"failed"`
	Queued  int        `json:"queued"`
	Rows    []AgentBan `json:"rows"`
}

func (s *Store) initAgents() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS pair_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code_hash TEXT NOT NULL,
  expires_ms INTEGER NOT NULL,
  used_ms INTEGER NOT NULL DEFAULT 0,
  created_ms INTEGER NOT NULL,
  created_by TEXT
);
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  secret_hash TEXT NOT NULL,
  fingerprint TEXT,
  os TEXT,
  hostname TEXT,
  version TEXT,
  seen_ip TEXT,
  block TEXT,
  jail TEXT,
  created_ms INTEGER NOT NULL,
  approved_ms INTEGER NOT NULL DEFAULT 0,
  approved_by TEXT,
  last_seen_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ag_name ON agents(name);
CREATE INDEX IF NOT EXISTS ag_secret ON agents(secret_hash);
CREATE TABLE IF NOT EXISTS agent_commands (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  action TEXT NOT NULL,
  ip TEXT,
  until_ms INTEGER NOT NULL DEFAULT 0,
  duration TEXT,
  status TEXT NOT NULL,
  result TEXT,
  created_ms INTEGER NOT NULL,
  created_by TEXT,
  expires_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ac_agent ON agent_commands(agent_id, status);
CREATE TABLE IF NOT EXISTS agent_bans (
  agent_id TEXT NOT NULL,
  ip TEXT NOT NULL,
  until_ms INTEGER NOT NULL DEFAULT 0,
  duration TEXT,
  created_ms INTEGER NOT NULL,
  created_by TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (agent_id, ip)
);
CREATE TABLE IF NOT EXISTS agent_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_ms INTEGER NOT NULL,
  actor TEXT,
  action TEXT NOT NULL,
  agent_id TEXT,
  ip TEXT,
  detail TEXT
);
`)
	if err != nil {
		return err
	}
	for _, col := range []string{
		"ALTER TABLE agent_bans ADD COLUMN title TEXT",
		"ALTER TABLE agent_bans ADD COLUMN category TEXT",
		"ALTER TABLE agent_bans ADD COLUMN alert_num INTEGER",
		"ALTER TABLE agent_bans ADD COLUMN scope TEXT",
		"ALTER TABLE agent_bans ADD COLUMN applied TEXT",
	} {
		_, _ = s.db.Exec(col)
	}
	return nil
}

func ValidAgentName(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 2 || len(s) > 40 {
		return false
	}
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func ValidPairPhrase(pw string) error {
	return auth.ValidPassword(pw, "")
}

func (s *Store) PairPhraseSet() bool {
	var v string
	if err := s.db.QueryRow(`SELECT v FROM settings WHERE k = 'pair_phrase'`).Scan(&v); err != nil {
		return false
	}
	return v != ""
}

func (s *Store) SetPairPhrase(phrase string) error {
	if err := ValidPairPhrase(phrase); err != nil {
		return err
	}
	hash, err := auth.HashPassword(phrase)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO settings(k,v) VALUES('pair_phrase', ?)
		ON CONFLICT(k) DO UPDATE SET v = excluded.v`, hash)
	return err
}

func (s *Store) CheckPairPhrase(phrase string) bool {
	var hash string
	if err := s.db.QueryRow(`SELECT v FROM settings WHERE k = 'pair_phrase'`).Scan(&hash); err != nil || hash == "" {
		_ = auth.CheckPassword(mustDummyHash(), phrase)
		return false
	}
	return auth.CheckPassword(hash, phrase)
}

func mustDummyHash() string {
	h, err := auth.HashPassword("not-the-real-phrase-at-all")
	if err != nil {
		return ""
	}
	return h
}

func normalizePairCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func FormatPairCode(raw string) string {
	raw = normalizePairCode(raw)
	if len(raw) == 8 {
		return raw[:4] + "-" + raw[4:]
	}
	return raw
}

func mintPairCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, 8)
	for i := range out {
		out[i] = pairAlphabet[int(b[i])%len(pairAlphabet)]
	}
	return string(out), nil
}

func (s *Store) MintPairCode(by string) (plain string, expires time.Time, err error) {
	if !s.PairPhraseSet() {
		return "", time.Time{}, fmt.Errorf("set an enrollment phrase first")
	}
	plain, err = mintPairCode()
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now()
	expires = now.Add(pairCodeTTL)
	_, err = s.db.Exec(`INSERT INTO pair_codes(code_hash, expires_ms, created_ms, created_by) VALUES(?,?,?,?)`,
		auth.TokenHash(normalizePairCode(plain)), expires.UnixMilli(), now.UnixMilli(), by)
	if err != nil {
		return "", time.Time{}, err
	}
	_, _ = s.db.Exec(`DELETE FROM pair_codes WHERE expires_ms < ? AND used_ms = 0`, now.UnixMilli())
	return FormatPairCode(plain), expires, nil
}

func (s *Store) consumePairCode(plain string) error {
	norm := normalizePairCode(plain)
	if len(norm) != 8 {
		return fmt.Errorf("bad pair code")
	}
	now := time.Now().UnixMilli()
	var id int64
	var exp, used int64
	err := s.db.QueryRow(`SELECT id, expires_ms, used_ms FROM pair_codes WHERE code_hash = ? ORDER BY id DESC LIMIT 1`,
		auth.TokenHash(norm)).Scan(&id, &exp, &used)
	if err == sql.ErrNoRows {
		return fmt.Errorf("unknown or expired pair code")
	}
	if err != nil {
		return err
	}
	if used != 0 || now > exp {
		return fmt.Errorf("unknown or expired pair code")
	}
	res, err := s.db.Exec(`UPDATE pair_codes SET used_ms = ? WHERE id = ? AND used_ms = 0 AND expires_ms >= ?`,
		now, id, now)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return fmt.Errorf("unknown or expired pair code")
	}
	return nil
}

func fingerprintOf(secretHash string) string {
	if len(secretHash) < 8 {
		return secretHash
	}
	return strings.ToUpper(secretHash[:4] + " " + secretHash[4:8])
}

func (s *Store) PairAgent(name, phrase, code, osName, hostname, version, seenIP string) (Agent, string, error) {
	name = strings.TrimSpace(name)
	if !ValidAgentName(name) {
		return Agent{}, "", fmt.Errorf("host name must be 2–40 letters, numbers, . _ -")
	}
	if !s.PairPhraseSet() {
		return Agent{}, "", fmt.Errorf("this monitor has no enrollment phrase yet")
	}
	if !s.CheckPairPhrase(phrase) {
		return Agent{}, "", fmt.Errorf("enrollment phrase does not match")
	}
	if err := s.consumePairCode(code); err != nil {
		return Agent{}, "", err
	}
	if existing, err := s.AgentByName(name); err == nil && existing.Status == AgentActive {
		return Agent{}, "", fmt.Errorf("host %s is already paired — revoke it first", name)
	}
	_, _ = s.db.Exec(`UPDATE agents SET status = ? WHERE name = ? AND status = ?`,
		AgentRevoked, name, AgentPending)

	secret, err := auth.RandomToken(32)
	if err != nil {
		return Agent{}, "", err
	}
	rid, err := auth.RandomToken(8)
	if err != nil {
		return Agent{}, "", err
	}
	id := "agt_" + rid
	hash := auth.TokenHash(secret)
	now := time.Now()
	a := Agent{
		ID:          id,
		Name:        name,
		Status:      AgentPending,
		OS:          strings.TrimSpace(osName),
		Hostname:    strings.TrimSpace(hostname),
		Version:     strings.TrimSpace(version),
		SeenIP:      strings.TrimSpace(seenIP),
		Fingerprint: fingerprintOf(hash),
		Created:     now,
		SecretHash:  hash,
	}
	_, err = s.db.Exec(`INSERT INTO agents(id, name, status, secret_hash, fingerprint, os, hostname, version, seen_ip, created_ms)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Name, a.Status, a.SecretHash, a.Fingerprint, a.OS, a.Hostname, a.Version, a.SeenIP, now.UnixMilli())
	if err != nil {
		return Agent{}, "", err
	}
	s.audit("", "pair", a.ID, seenIP, "pending "+a.Name)
	return a, secret, nil
}

func (s *Store) AgentByID(id string) (Agent, error) {
	return s.scanAgent(`SELECT id, name, status, secret_hash, IFNULL(fingerprint,''), IFNULL(os,''), IFNULL(hostname,''),
		IFNULL(version,''), IFNULL(seen_ip,''), IFNULL(block,''), IFNULL(jail,''), created_ms, approved_ms, IFNULL(approved_by,''), last_seen_ms
		FROM agents WHERE id = ?`, id)
}

func (s *Store) AgentByName(name string) (Agent, error) {
	return s.scanAgent(`SELECT id, name, status, secret_hash, IFNULL(fingerprint,''), IFNULL(os,''), IFNULL(hostname,''),
		IFNULL(version,''), IFNULL(seen_ip,''), IFNULL(block,''), IFNULL(jail,''), created_ms, approved_ms, IFNULL(approved_by,''), last_seen_ms
		FROM agents WHERE name = ? ORDER BY created_ms DESC LIMIT 1`, strings.TrimSpace(name))
}

func (s *Store) AgentBySecret(secret string) (Agent, error) {
	if secret == "" {
		return Agent{}, fmt.Errorf("no agent")
	}
	return s.scanAgent(`SELECT id, name, status, secret_hash, IFNULL(fingerprint,''), IFNULL(os,''), IFNULL(hostname,''),
		IFNULL(version,''), IFNULL(seen_ip,''), IFNULL(block,''), IFNULL(jail,''), created_ms, approved_ms, IFNULL(approved_by,''), last_seen_ms
		FROM agents WHERE secret_hash = ?`, auth.TokenHash(secret))
}

func (s *Store) scanAgent(q string, arg any) (Agent, error) {
	var a Agent
	var created, approved, last int64
	err := s.db.QueryRow(q, arg).Scan(&a.ID, &a.Name, &a.Status, &a.SecretHash, &a.Fingerprint, &a.OS, &a.Hostname,
		&a.Version, &a.SeenIP, &a.Block, &a.Jail, &created, &approved, &a.ApprovedBy, &last)
	if err == sql.ErrNoRows {
		return Agent{}, fmt.Errorf("not found")
	}
	if err != nil {
		return Agent{}, err
	}
	a.Created = time.UnixMilli(created).UTC()
	if approved > 0 {
		a.Approved = time.UnixMilli(approved).UTC()
	}
	if last > 0 {
		a.LastSeen = time.UnixMilli(last).UTC()
	}
	return a, nil
}

func (s *Store) ListAgents() ([]Agent, error) {
	rows, err := s.db.Query(`SELECT id, name, status, secret_hash, IFNULL(fingerprint,''), IFNULL(os,''), IFNULL(hostname,''),
		IFNULL(version,''), IFNULL(seen_ip,''), IFNULL(block,''), IFNULL(jail,''), created_ms, approved_ms, IFNULL(approved_by,''), last_seen_ms
		FROM agents ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 ELSE 2 END, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		var a Agent
		var created, approved, last int64
		if err := rows.Scan(&a.ID, &a.Name, &a.Status, &a.SecretHash, &a.Fingerprint, &a.OS, &a.Hostname,
			&a.Version, &a.SeenIP, &a.Block, &a.Jail, &created, &approved, &a.ApprovedBy, &last); err != nil {
			return nil, err
		}
		a.SecretHash = ""
		a.Created = time.UnixMilli(created).UTC()
		if approved > 0 {
			a.Approved = time.UnixMilli(approved).UTC()
		}
		if last > 0 {
			a.LastSeen = time.UnixMilli(last).UTC()
		}
		out = append(out, a)
	}
	if out == nil {
		out = []Agent{}
	}
	return out, rows.Err()
}

func (s *Store) ApproveAgent(id, by string) error {
	a, err := s.AgentByID(id)
	if err != nil {
		return err
	}
	if a.Status != AgentPending {
		return fmt.Errorf("agent is %s, not pending", a.Status)
	}
	now := time.Now().UnixMilli()
	_, err = s.db.Exec(`UPDATE agents SET status = ?, approved_ms = ?, approved_by = ? WHERE id = ?`,
		AgentActive, now, by, id)
	if err == nil {
		s.audit(by, "approve", id, "", a.Name)
	}
	return err
}

func (s *Store) RejectAgent(id, by string) error {
	a, err := s.AgentByID(id)
	if err != nil {
		return err
	}
	if a.Status != AgentPending {
		return fmt.Errorf("agent is %s, not pending", a.Status)
	}
	_, err = s.db.Exec(`UPDATE agents SET status = ?, secret_hash = ? WHERE id = ?`,
		AgentRejected, "revoked-"+a.ID, id)
	if err == nil {
		s.audit(by, "reject", id, "", a.Name)
	}
	return err
}

func (s *Store) RevokeAgent(id, by string) error {
	a, err := s.AgentByID(id)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE agents SET status = ?, secret_hash = ? WHERE id = ?`,
		AgentRevoked, "revoked-"+a.ID, id)
	if err == nil {
		s.audit(by, "revoke", id, "", a.Name)
	}
	return err
}

func (s *Store) TouchAgent(id, seenIP, osName, hostname, version, backend, jail string) {
	_, _ = s.db.Exec(`UPDATE agents SET last_seen_ms = ?, seen_ip = COALESCE(NULLIF(?,''), seen_ip),
		os = COALESCE(NULLIF(?,''), os), hostname = COALESCE(NULLIF(?,''), hostname),
		version = COALESCE(NULLIF(?,''), version), block = COALESCE(NULLIF(?,''), block),
		jail = COALESCE(NULLIF(?,''), jail) WHERE id = ?`,
		time.Now().UnixMilli(), seenIP, osName, hostname, version, backend, jail, id)
}

func (s *Store) EnqueueCommand(agentID, action, ip, duration, by string) (AgentCommand, error) {
	return s.EnqueueCommandWhy(agentID, action, ip, duration, by, BanWhy{})
}

func (s *Store) EnqueueCommandWhy(agentID, action, ip, duration, by string, why BanWhy) (AgentCommand, error) {
	a, err := s.AgentByID(agentID)
	if err != nil {
		return AgentCommand{}, err
	}
	if a.Status != AgentActive {
		return AgentCommand{}, fmt.Errorf("host is not approved")
	}
	action = strings.ToLower(strings.TrimSpace(action))
	switch action {
	case "ban", "unban", "list", "stats":
	default:
		return AgentCommand{}, fmt.Errorf("action must be ban, unban, list, or stats")
	}
	if action == "stats" {
		now := time.Now()
		cmd := AgentCommand{
			ID: "cmd_" + ID(), AgentID: agentID, Action: action,
			Status: CmdQueued, Created: now.UTC(), CreatedBy: by,
			Expires: now.Add(commandPickup).UTC(),
		}
		_, err = s.db.Exec(`INSERT INTO agent_commands(id, agent_id, action, ip, until_ms, duration, status, created_ms, created_by, expires_ms)
			VALUES(?,?,?,?,0,'',?,?,?,?)`,
			cmd.ID, cmd.AgentID, cmd.Action, "", cmd.Status, now.UnixMilli(), by, cmd.Expires.UnixMilli())
		if err != nil {
			return AgentCommand{}, err
		}
		s.audit(by, action, agentID, "", "check")
		return cmd, nil
	}
	var until time.Time
	if action == "ban" {
		clean, err := block.CheckBanIP(ip)
		if err != nil {
			return AgentCommand{}, err
		}
		ip = clean
		if a.SeenIP != "" && ip == a.SeenIP {
			return AgentCommand{}, fmt.Errorf("refusing to ban this host’s own address")
		}
		d, err := block.ParseDuration(duration)
		if err != nil {
			return AgentCommand{}, err
		}
		if d > 0 {
			until = time.Now().UTC().Add(d)
		}
		var n int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM agent_bans WHERE agent_id = ? AND active = 1`, agentID).Scan(&n)
		if n >= maxActiveBans {
			return AgentCommand{}, fmt.Errorf("too many active bans on this host")
		}
	}
	if action == "unban" {
		clean, err := block.CheckBanIP(ip)
		if err != nil {
			return AgentCommand{}, err
		}
		ip = clean
	}
	now := time.Now()
	cmd := AgentCommand{
		ID:        "cmd_" + ID(),
		AgentID:   agentID,
		Action:    action,
		IP:        ip,
		Until:     until,
		Duration:  duration,
		Status:    CmdQueued,
		Created:   now.UTC(),
		CreatedBy: by,
		Expires:   now.Add(commandPickup).UTC(),
	}
	var untilMS int64
	if !until.IsZero() {
		untilMS = until.UnixMilli()
	}
	_, err = s.db.Exec(`INSERT INTO agent_commands(id, agent_id, action, ip, until_ms, duration, status, created_ms, created_by, expires_ms)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		cmd.ID, cmd.AgentID, cmd.Action, cmd.IP, untilMS, cmd.Duration, cmd.Status, now.UnixMilli(), by, cmd.Expires.UnixMilli())
	if err != nil {
		return AgentCommand{}, err
	}
	if action == "ban" {
		scope := strings.TrimSpace(why.Scope)
		if scope == "" {
			scope = "this"
		}
		_, _ = s.db.Exec(`INSERT INTO agent_bans(agent_id, ip, until_ms, duration, created_ms, created_by, active, title, category, alert_num, scope, applied)
			VALUES(?,?,?,?,?,?,1,?,?,?,?, 'queued')
			ON CONFLICT(agent_id, ip) DO UPDATE SET until_ms = excluded.until_ms, duration = excluded.duration,
				created_ms = excluded.created_ms, created_by = excluded.created_by, active = 1,
				title = COALESCE(NULLIF(excluded.title,''), agent_bans.title),
				category = COALESCE(NULLIF(excluded.category,''), agent_bans.category),
				alert_num = CASE WHEN excluded.alert_num > 0 THEN excluded.alert_num ELSE agent_bans.alert_num END,
				scope = excluded.scope, applied = 'queued'`,
			agentID, ip, untilMS, duration, now.UnixMilli(), by, why.Title, why.Category, why.AlertNum, scope)
	}
	if action == "unban" {
		_, _ = s.db.Exec(`UPDATE agent_bans SET active = 0 WHERE agent_id = ? AND ip = ?`, agentID, ip)
	}
	s.audit(by, action, agentID, ip, duration)
	return cmd, nil
}

func (s *Store) EnqueueBanAll(ip, duration, by string) (int, error) {
	return s.EnqueueBanAllWhy(ip, duration, by, BanWhy{Scope: "all"})
}

func (s *Store) EnqueueBanAllWhy(ip, duration, by string, why BanWhy) (int, error) {
	if why.Scope == "" {
		why.Scope = "all"
	}
	list, err := s.ListAgents()
	if err != nil {
		return 0, err
	}
	n := 0
	var last error
	for _, a := range list {
		if a.Status != AgentActive {
			continue
		}
		if _, err := s.EnqueueCommandWhy(a.ID, "ban", ip, duration, by, why); err != nil {
			last = err
			continue
		}
		n++
	}
	if n == 0 && last != nil {
		return 0, last
	}
	return n, nil
}

func (s *Store) TakeCommands(agentID string) ([]AgentCommand, error) {
	now := time.Now().UnixMilli()
	_, _ = s.db.Exec(`UPDATE agent_commands SET status = ? WHERE agent_id = ? AND status = ? AND expires_ms < ?`,
		CmdExpired, agentID, CmdQueued, now)
	rows, err := s.db.Query(`SELECT id, agent_id, action, IFNULL(ip,''), until_ms, IFNULL(duration,''), status, IFNULL(result,''), created_ms, IFNULL(created_by,''), expires_ms
		FROM agent_commands WHERE agent_id = ? AND status = ? AND expires_ms >= ? ORDER BY created_ms`,
		agentID, CmdQueued, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentCommand
	var ids []string
	for rows.Next() {
		c, err := scanCmd(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		ids = append(ids, c.ID)
	}
	if len(ids) == 0 {
		return []AgentCommand{}, rows.Err()
	}
	for _, id := range ids {
		_, _ = s.db.Exec(`UPDATE agent_commands SET status = ? WHERE id = ? AND status = ?`, CmdSent, id, CmdQueued)
	}
	return out, nil
}

func scanCmd(rows *sql.Rows) (AgentCommand, error) {
	var c AgentCommand
	var until, created, exp int64
	err := rows.Scan(&c.ID, &c.AgentID, &c.Action, &c.IP, &until, &c.Duration, &c.Status, &c.Result, &created, &c.CreatedBy, &exp)
	if err != nil {
		return c, err
	}
	c.Created = time.UnixMilli(created).UTC()
	c.Expires = time.UnixMilli(exp).UTC()
	if until > 0 {
		c.Until = time.UnixMilli(until).UTC()
	}
	return c, nil
}

func (s *Store) CommandResult(id, agentID, status, result string) error {
	switch status {
	case CmdDone, CmdFailed:
	default:
		return fmt.Errorf("status must be done or failed")
	}
	res, err := s.db.Exec(`UPDATE agent_commands SET status = ?, result = ? WHERE id = ? AND agent_id = ? AND status IN (?,?)`,
		status, strings.TrimSpace(result), id, agentID, CmdSent, CmdQueued)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return fmt.Errorf("command not found")
	}
	var action, ip string
	_ = s.db.QueryRow(`SELECT action, IFNULL(ip,'') FROM agent_commands WHERE id = ?`, id).Scan(&action, &ip)
	if action == "ban" && ip != "" {
		mark := "applied"
		if status == CmdFailed {
			mark = "failed"
		}
		_, _ = s.db.Exec(`UPDATE agent_bans SET applied = ? WHERE agent_id = ? AND ip = ?`, mark, agentID, ip)
	}
	return nil
}

func (s *Store) AgentBans(agentID string) ([]AgentBan, error) {
	rows, err := s.db.Query(`SELECT ip, until_ms, IFNULL(duration,''), created_ms, IFNULL(created_by,''), active
		FROM agent_bans WHERE agent_id = ? ORDER BY created_ms DESC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentBan
	for rows.Next() {
		var b AgentBan
		var until, created int64
		var active int
		if err := rows.Scan(&b.IP, &until, &b.Duration, &created, &b.CreatedBy, &active); err != nil {
			return nil, err
		}
		b.Active = active != 0
		b.Created = time.UnixMilli(created).UTC()
		if until > 0 {
			b.Until = time.UnixMilli(until).UTC()
		}
		out = append(out, b)
	}
	if out == nil {
		out = []AgentBan{}
	}
	return out, rows.Err()
}

func (s *Store) expireBans() {
	now := time.Now().UnixMilli()
	_, _ = s.db.Exec(`UPDATE agent_bans SET active = 0 WHERE active = 1 AND until_ms > 0 AND until_ms < ?`, now)
}

func (s *Store) BlockList() (BlockReport, error) {
	s.expireBans()
	rep := BlockReport{Rows: []AgentBan{}}
	rows, err := s.db.Query(`SELECT b.agent_id, IFNULL(a.name,''), b.ip, b.until_ms, IFNULL(b.duration,''), b.created_ms,
		IFNULL(b.created_by,''), b.active, IFNULL(b.title,''), IFNULL(b.category,''), IFNULL(b.alert_num,0),
		IFNULL(b.scope,''), IFNULL(NULLIF(b.applied,''),'queued')
		FROM agent_bans b LEFT JOIN agents a ON a.id = b.agent_id
		ORDER BY b.active DESC, b.created_ms DESC`)
	if err != nil {
		return rep, err
	}
	ips := map[string]bool{}
	for rows.Next() {
		var b AgentBan
		var until, created int64
		var active int
		if err := rows.Scan(&b.AgentID, &b.Host, &b.IP, &until, &b.Duration, &created, &b.CreatedBy, &active,
			&b.Title, &b.Category, &b.AlertNum, &b.Scope, &b.Applied); err != nil {
			rows.Close()
			return rep, err
		}
		b.Active = active != 0
		b.Created = time.UnixMilli(created).UTC()
		if until > 0 {
			b.Until = time.UnixMilli(until).UTC()
		}
		if b.Active {
			rep.Active++
			ips[b.IP] = true
			switch b.Applied {
			case "applied":
				rep.Applied++
			case "failed":
				rep.Failed++
			default:
				rep.Queued++
			}
		}
		rep.Rows = append(rep.Rows, b)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return rep, err
	}
	// One SQLite connection: never QueryRow while this result set is open.
	for i := range rep.Rows {
		b := &rep.Rows[i]
		if !b.Active || b.Host == "" {
			continue
		}
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE src_ip = ? AND source = ? AND ts > ?`,
			b.IP, b.Host, b.Created.UnixMilli()).Scan(&b.HitsAfter)
	}
	rep.IPs = len(ips)
	return rep, nil
}

func (s *Store) audit(actor, action, agentID, ip, detail string) {
	_, _ = s.db.Exec(`INSERT INTO agent_audit(ts_ms, actor, action, agent_id, ip, detail) VALUES(?,?,?,?,?,?)`,
		time.Now().UnixMilli(), actor, action, agentID, ip, detail)
}

func (s *Store) AgentAudit(limit int) ([]map[string]any, error) {
	if limit <= 0 || limit > 200 {
		limit = 40
	}
	rows, err := s.db.Query(`SELECT ts_ms, IFNULL(actor,''), action, IFNULL(agent_id,''), IFNULL(ip,''), IFNULL(detail,'')
		FROM agent_audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var ts int64
		var actor, action, agentID, ip, detail string
		if err := rows.Scan(&ts, &actor, &action, &agentID, &ip, &detail); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"time": time.UnixMilli(ts).UTC(), "actor": actor, "action": action,
			"agent_id": agentID, "ip": ip, "detail": detail,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, rows.Err()
}
