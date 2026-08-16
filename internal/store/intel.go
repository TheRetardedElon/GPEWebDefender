package store

import (
	"net"
	"strings"
	"time"

	"gpewebdefender/internal/event"
)

func privateIP(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

func (s *Store) IPIntel(ip string, since time.Time) (event.IPIntel, error) {
	ip = strings.TrimSpace(ip)
	until := time.Now().UTC()
	out := event.IPIntel{
		SrcIP:      ip,
		Since:      since.UTC(),
		Until:      until,
		Private:    privateIP(ip),
		Hosts:      []string{},
		Categories: []string{},
		ByRule:     []event.RuleCount{},
		Users:      []event.NameCount{},
		Why:        []string{},
	}
	if ip == "" || net.ParseIP(ip) == nil {
		out.Verdict = "unknown"
		out.Intent = "not an IP"
		out.Why = []string{"that is not a parseable IP address"}
		return out, nil
	}
	if out.Private {
		out.Verdict = "local"
		out.Intent = "private or loopback — no public reputation"
		out.Why = []string{"this address is not on the public internet"}
	}

	where := "WHERE src_ip = ?"
	args := []any{ip}
	if !since.IsZero() {
		where += " AND ts >= ?"
		args = append(args, since.UnixMilli())
	}

	var first, last int64
	var hosts, cats, country, cname string
	err := s.db.QueryRow(`
SELECT COUNT(*),
       COALESCE(SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN category = 'canary' THEN 1 ELSE 0 END), 0),
       COALESCE(MIN(ts), 0), COALESCE(MAX(ts), 0),
       COALESCE(GROUP_CONCAT(DISTINCT source), ''),
       COALESCE(GROUP_CONCAT(DISTINCT category), ''),
       COALESCE(MAX(country), ''), COALESCE(MAX(country_name), '')
FROM alerts `+where, args...).Scan(
		&out.Alerts, &out.Critical, &out.High, &out.Canary, &first, &last, &hosts, &cats, &country, &cname)
	if err != nil {
		return out, err
	}
	if first > 0 {
		out.FirstSeen = time.UnixMilli(first).UTC()
	}
	if last > 0 {
		out.LastSeen = time.UnixMilli(last).UTC()
	}
	out.Country, out.CountryName = country, cname
	if hosts != "" {
		out.Hosts = splitCSV(hosts)
	}
	if cats != "" {
		out.Categories = splitCSV(cats)
	}

	rrows, err := s.db.Query(`SELECT COALESCE(rule_id,''), COALESCE(title,''), COALESCE(severity,''), COALESCE(category,''), COUNT(*)
		FROM alerts `+where+` GROUP BY rule_id ORDER BY COUNT(*) DESC LIMIT 8`, args...)
	if err != nil {
		return out, err
	}
	for rrows.Next() {
		var n event.RuleCount
		if rrows.Scan(&n.ID, &n.Title, &n.Severity, &n.Category, &n.Count) == nil && n.ID != "" {
			out.ByRule = append(out.ByRule, n)
		}
	}
	rrows.Close()

	urows, err := s.db.Query(`SELECT user, COUNT(*) FROM events `+where+` AND IFNULL(user,'') != ''
		GROUP BY user ORDER BY COUNT(*) DESC LIMIT 8`, args...)
	if err == nil {
		for urows.Next() {
			var n event.NameCount
			if urows.Scan(&n.Name, &n.Count) == nil {
				out.Users = append(out.Users, n)
			}
		}
		urows.Close()
	}

	scoreIntel(&out)
	s.attachIntelCache(&out)
	return out, nil
}

func (s *Store) initIntel() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS intel_cache (
  ip TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  score INTEGER NOT NULL,
  note TEXT,
  raw TEXT,
  cached_ms INTEGER NOT NULL,
  expire_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS intel_queue (
  ip TEXT PRIMARY KEY,
  prio INTEGER NOT NULL,
  reason TEXT,
  queued_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS intel_fetch (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT,
  provider TEXT,
  code INTEGER,
  ts_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS intel_q_prio ON intel_queue(prio, queued_ms);
`)
	return err
}

func (s *Store) attachIntelCache(in *event.IPIntel) {
	if in == nil || in.SrcIP == "" {
		return
	}
	var provider, note string
	var score, cached, exp int64
	err := s.db.QueryRow(`SELECT provider, score, note, cached_ms, expire_ms FROM intel_cache WHERE ip = ?`, in.SrcIP).
		Scan(&provider, &score, &note, &cached, &exp)
	if err == nil {
		in.ExtSource = provider
		in.ExtScore = int(score)
		in.ExtNote = note
		in.ExtCachedAt = time.UnixMilli(cached).UTC()
		if time.Now().UnixMilli() < exp {
			in.Research = "cached"
			fuseExternal(in, int(score), provider, note)
		} else {
			in.Research = "stale"
		}
	}
	var dummy string
	if s.db.QueryRow(`SELECT ip FROM intel_queue WHERE ip = ?`, in.SrcIP).Scan(&dummy) == nil {
		in.Queued = true
		if in.Research == "" || in.Research == "stale" {
			in.Research = "queued"
		}
	}
	if in.Research == "" {
		in.Research = "local"
	}
}

func fuseExternal(in *event.IPIntel, score int, provider, note string) {
	if in.Private || score <= 0 {
		return
	}
	if score >= 75 {
		in.Weight += 18
		in.Why = append(in.Why, provider+" confidence "+itoa(score)+" (cached, not live-scraped)")
	} else if score >= 25 {
		in.Weight += 8
		in.Why = append(in.Why, provider+" medium "+itoa(score)+" (cached)")
	} else {
		in.Why = append(in.Why, provider+" is quiet on this IP (cached)")
	}
	if in.Weight > 100 {
		in.Weight = 100
	}
	if in.Weight >= 70 {
		in.Verdict = "act"
	}
	if note != "" && in.ExtNote == "" {
		in.ExtNote = note
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// EnqueueIntel puts a public IP on the slow research queue. No-op for private / invalid / already cached.
func (s *Store) EnqueueIntel(ip string, prio int, reason string) {
	ip = strings.TrimSpace(ip)
	if ip == "" || net.ParseIP(ip) == nil || privateIP(ip) {
		return
	}
	if prio <= 0 {
		prio = 5
	}
	now := time.Now().UnixMilli()
	var exp int64
	if s.db.QueryRow(`SELECT expire_ms FROM intel_cache WHERE ip = ?`, ip).Scan(&exp) == nil && exp > now {
		return
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM intel_queue`).Scan(&n)
	if n >= 150 {
		_, _ = s.db.Exec(`DELETE FROM intel_queue WHERE ip IN (SELECT ip FROM intel_queue ORDER BY prio DESC, queued_ms ASC LIMIT 20)`)
	}
	_, _ = s.db.Exec(`INSERT INTO intel_queue(ip, prio, reason, queued_ms) VALUES(?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET prio = MIN(prio, excluded.prio), reason = excluded.reason`,
		ip, prio, reason, now)
}

func (s *Store) NextIntelJob() (ip string, ok bool) {
	row := s.db.QueryRow(`SELECT ip FROM intel_queue ORDER BY prio ASC, queued_ms ASC LIMIT 1`)
	if row.Scan(&ip) != nil || ip == "" {
		return "", false
	}
	_, _ = s.db.Exec(`DELETE FROM intel_queue WHERE ip = ?`, ip)
	return ip, true
}

func (s *Store) SaveIntelCache(ip, provider string, score int, note, raw string, ttl time.Duration) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	now := time.Now()
	_, _ = s.db.Exec(`INSERT INTO intel_cache(ip, provider, score, note, raw, cached_ms, expire_ms) VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET provider=excluded.provider, score=excluded.score, note=excluded.note, raw=excluded.raw, cached_ms=excluded.cached_ms, expire_ms=excluded.expire_ms`,
		ip, provider, score, note, raw, now.UnixMilli(), now.Add(ttl).UnixMilli())
}

func (s *Store) LogIntelFetch(ip, provider string, code int) {
	now := time.Now().UnixMilli()
	_, _ = s.db.Exec(`INSERT INTO intel_fetch(ip, provider, code, ts_ms) VALUES(?,?,?,?)`, ip, provider, code, now)
	_, _ = s.db.Exec(`DELETE FROM intel_fetch WHERE id NOT IN (SELECT id FROM intel_fetch ORDER BY id DESC LIMIT 200)`)
}

func (s *Store) IntelQueueDepth() int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM intel_queue`).Scan(&n)
	return n
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func scoreIntel(in *event.IPIntel) {
	if in.Private {
		return
	}
	why := []string{}
	w := 0
	if in.Alerts >= 200 {
		w += 30
		why = append(why, "very high volume against you")
	} else if in.Alerts >= 40 {
		w += 20
		why = append(why, "sustained volume against you")
	} else if in.Alerts >= 8 {
		w += 10
		why = append(why, "repeat hits on this estate")
	} else if in.Alerts > 0 {
		w += 4
		why = append(why, "at least one alert on this estate")
	}
	if in.Canary > 0 {
		w += 35
		why = append(why, "hit a canary / trap path")
	}
	if in.Critical > 0 {
		w += 20
		why = append(why, "at least one critical alert")
	} else if in.High > 0 {
		w += 10
		why = append(why, "at least one high alert")
	}
	if len(in.Hosts) >= 3 {
		w += 20
		why = append(why, "seen on 3+ of your hosts")
	} else if len(in.Hosts) == 2 {
		w += 12
		why = append(why, "seen on more than one host")
	}
	if len(in.Categories) >= 3 {
		w += 10
		why = append(why, "more than one attack type")
	}
	has := func(name string) bool {
		for _, c := range in.Categories {
			if c == name {
				return true
			}
		}
		return false
	}
	intent := "not enough of our data"
	switch {
	case in.Canary > 0:
		intent = "trap / they found something we planted"
	case has("brute") || has("hostauth"):
		if in.Alerts >= 20 {
			intent = "credential attack (spray / brute)"
		} else {
			intent = "auth probing"
		}
	case has("sqli") || has("rce") || has("xss") || has("traversal") || has("cmdi"):
		intent = "opportunistic web exploit attempt"
	case has("scanner") || has("recon") || has("snoop"):
		intent = "internet noise / scanner (often not personal)"
		if w > 45 && !has("canary") && in.Critical == 0 {
			w = 45
			why = append(why, "capped — looks like background scan noise")
		}
	case in.Alerts > 0:
		intent = "hitting you; check the rules below"
	}
	if w > 100 {
		w = 100
	}
	verdict := "watch"
	switch {
	case in.Alerts == 0:
		verdict = "unknown"
		intent = "no alerts for this IP in the window"
		why = []string{"we have not seen this address ourselves"}
	case w >= 70:
		verdict = "act"
	case w < 35:
		verdict = "noise"
	}
	in.Weight = w
	in.Verdict = verdict
	in.Intent = intent
	if len(why) == 0 {
		why = []string{"weight is only from our logs, not AbuseIPDB or Talos"}
	} else {
		why = append(why, "this is our estate only — open the lookups for third-party context")
	}
	in.Why = why
}
