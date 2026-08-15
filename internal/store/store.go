package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"gpewebdefender/internal/event"
)

type Store struct {
	db    *sql.DB
	mu    sync.Mutex
	start time.Time
}

func Open(path string) (*Store, error) {
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, start: time.Now()}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  ts INTEGER NOT NULL,
  src_ip TEXT,
  method TEXT,
  url TEXT,
  path TEXT,
  query TEXT,
  status INTEGER,
  bytes INTEGER,
  ua TEXT,
  referer TEXT,
  host TEXT,
  source TEXT,
  raw TEXT
);
CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ev_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS ev_source ON events(source);

CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  ts INTEGER NOT NULL,
  event_id TEXT,
  rule_id TEXT,
  title TEXT,
  severity TEXT,
  category TEXT,
  src_ip TEXT,
  method TEXT,
  url TEXT,
  status INTEGER,
  ua TEXT,
  evidence TEXT,
  mitre TEXT,
  count INTEGER,
  source TEXT
);
CREATE INDEX IF NOT EXISTS al_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS al_ip ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS al_sev ON alerts(severity);
CREATE INDEX IF NOT EXISTS al_rule ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS al_source ON alerts(source);
`)
	if err != nil {
		return err
	}
	for _, col := range []string{
		"ALTER TABLE alerts ADD COLUMN country TEXT",
		"ALTER TABLE alerts ADD COLUMN country_name TEXT",
		"ALTER TABLE alerts ADD COLUMN lat REAL",
		"ALTER TABLE alerts ADD COLUMN lon REAL",
		"ALTER TABLE alerts ADD COLUMN tags TEXT",
		"ALTER TABLE events ADD COLUMN user TEXT",
		"ALTER TABLE events ADD COLUMN kind TEXT",
		"ALTER TABLE events ADD COLUMN outcome TEXT",
		"CREATE INDEX IF NOT EXISTS ev_kind ON events(kind)",
		"CREATE INDEX IF NOT EXISTS ev_status ON events(status)",
		"CREATE INDEX IF NOT EXISTS ev_user ON events(user)",
		"CREATE INDEX IF NOT EXISTS al_cat ON alerts(category)",
		"ALTER TABLE alerts ADD COLUMN num INTEGER",
		"CREATE UNIQUE INDEX IF NOT EXISTS al_num ON alerts(num)",
		`CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)`,
	} {
		_, _ = s.db.Exec(col) // already-exists is fine
	}
	if err := s.backfillAlertNums(); err != nil {
		return err
	}
	_, _ = s.db.Exec(`UPDATE events SET kind = 'tenantlogin' WHERE lower(IFNULL(kind,'')) IN
		('ownerlogin','tenant','owner','siteowner','site-owner','site_owner')`)
	return s.initSearch()
}

func (s *Store) backfillAlertNums() error {
	_, err := s.db.Exec(`
UPDATE alerts SET num = (
  SELECT COUNT(*) FROM alerts a2
  WHERE a2.ts < alerts.ts OR (a2.ts = alerts.ts AND a2.id <= alerts.id)
) WHERE IFNULL(num,0) = 0`)
	if err != nil {
		return err
	}
	var max sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(num) FROM alerts`).Scan(&max); err != nil {
		return err
	}
	n := int64(0)
	if max.Valid {
		n = max.Int64
	}
	_, err = s.db.Exec(`INSERT INTO settings(k,v) VALUES('alert_num', ?)
		ON CONFLICT(k) DO UPDATE SET v = CASE WHEN CAST(v AS INTEGER) < ? THEN ? ELSE v END`,
		fmt.Sprintf("%d", n), n, fmt.Sprintf("%d", n))
	return err
}

func (s *Store) nextAlertNum() (int64, error) {
	if _, err := s.db.Exec(`INSERT INTO settings(k,v) VALUES('alert_num','0') ON CONFLICT(k) DO NOTHING`); err != nil {
		return 0, err
	}
	if _, err := s.db.Exec(`UPDATE settings SET v = CAST(CAST(v AS INTEGER) + 1 AS TEXT) WHERE k = 'alert_num'`); err != nil {
		return 0, err
	}
	var raw string
	if err := s.db.QueryRow(`SELECT v FROM settings WHERE k = 'alert_num'`).Scan(&raw); err != nil {
		return 0, err
	}
	return strconv.ParseInt(raw, 10, 64)
}

func (s *Store) InsertEvent(ev event.Event) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO events
		(id, ts, src_ip, method, url, path, query, status, bytes, ua, referer, host, source, raw, user, kind, outcome)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ev.ID, ev.Time.UnixMilli(), ev.SrcIP, ev.Method, ev.URL, ev.Path, ev.Query,
		ev.Status, ev.Bytes, ev.UA, ev.Referer, ev.Host, ev.Source, ev.Raw, ev.User, ev.Kind, ev.Outcome)
	if err != nil {
		return err
	}
	s.indexEvent(ev)
	return nil
}

func (s *Store) InsertAlert(al *event.Alert) error {
	if al.Num <= 0 {
		n, err := s.nextAlertNum()
		if err != nil {
			return err
		}
		al.Num = n
	}
	mitre, _ := json.Marshal(al.MITRE)
	tags, _ := json.Marshal(al.Tags)
	_, err := s.db.Exec(`INSERT OR REPLACE INTO alerts
		(id, ts, event_id, rule_id, title, severity, category, src_ip, method, url, status, ua, evidence, mitre, count, source, country, country_name, lat, lon, tags, num)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		al.ID, al.Time.UnixMilli(), al.EventID, al.RuleID, al.Title, al.Severity, al.Category,
		al.SrcIP, al.Method, al.URL, al.Status, al.UA, al.Evidence, string(mitre), al.Count, al.Source,
		al.Country, al.CountryName, al.Lat, al.Lon, string(tags), al.Num)
	if err != nil {
		return err
	}
	s.indexAlert(*al)
	return nil
}

type AlertQuery struct {
	Q, Severity, IP, Source string
	Since                   time.Time
	Limit                   int
	BeforeNum               int64
	AfterNum                int64
}

func (s *Store) Alerts(q AlertQuery) (event.AlertPage, error) {
	if q.Limit <= 0 || q.Limit > 200 {
		q.Limit = 40
	}
	var cond []string
	var args []any
	if !q.Since.IsZero() {
		cond = append(cond, "ts >= ?")
		args = append(args, q.Since.UnixMilli())
	}
	if q.Severity != "" && q.Severity != "all" {
		cond = append(cond, "severity = ?")
		args = append(args, q.Severity)
	}
	if q.IP != "" {
		cond = append(cond, "src_ip = ?")
		args = append(args, q.IP)
	}
	if q.Source != "" {
		cond = append(cond, "source = ?")
		args = append(args, q.Source)
	}
	if q.BeforeNum > 0 {
		cond = append(cond, "num < ?")
		args = append(args, q.BeforeNum)
	}
	if q.AfterNum > 0 {
		cond = append(cond, "num > ?")
		args = append(args, q.AfterNum)
	}
	if q.Q != "" {
		qtrim := strings.TrimSpace(q.Q)
		raw := strings.TrimPrefix(qtrim, "#")
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil && (qtrim == raw || strings.HasPrefix(qtrim, "#")) {
			cond = append(cond, "num = ?")
			args = append(args, n)
		} else {
			cond = append(cond, "(title LIKE ? OR url LIKE ? OR src_ip LIKE ? OR rule_id LIKE ? OR evidence LIKE ? OR source LIKE ? OR CAST(num AS TEXT) = ?)")
			like := "%" + q.Q + "%"
			args = append(args, like, like, like, like, like, like, q.Q)
		}
	}
	where := ""
	if len(cond) > 0 {
		where = "WHERE " + strings.Join(cond, " AND ")
	}
	fetch := q.Limit + 1
	args = append(args, fetch)
	order := "ORDER BY num DESC"
	if q.AfterNum > 0 {
		order = "ORDER BY num ASC"
	}
	rows, err := s.db.Query(`SELECT id, ts, event_id, rule_id, title, severity, category, src_ip, method, url, status, ua, evidence, mitre, count, source,
		COALESCE(country,''), COALESCE(country_name,''), COALESCE(lat,0), COALESCE(lon,0), COALESCE(tags,''), COALESCE(num,0)
		FROM alerts `+where+` `+order+` LIMIT ?`, args...)
	if err != nil {
		return event.AlertPage{}, err
	}
	defer rows.Close()
	var out []event.Alert
	for rows.Next() {
		var a event.Alert
		var ts int64
		var mitre, tags string
		if err := rows.Scan(&a.ID, &ts, &a.EventID, &a.RuleID, &a.Title, &a.Severity, &a.Category,
			&a.SrcIP, &a.Method, &a.URL, &a.Status, &a.UA, &a.Evidence, &mitre, &a.Count, &a.Source,
			&a.Country, &a.CountryName, &a.Lat, &a.Lon, &tags, &a.Num); err != nil {
			return event.AlertPage{}, err
		}
		a.Time = time.UnixMilli(ts).UTC()
		a.HasGeo = a.Country != "" && (a.Lat != 0 || a.Lon != 0)
		_ = json.Unmarshal([]byte(mitre), &a.MITRE)
		_ = json.Unmarshal([]byte(tags), &a.Tags)
		out = append(out, a)
	}
	if out == nil {
		out = []event.Alert{}
	}
	hasMore := len(out) > q.Limit
	if hasMore {
		out = out[:q.Limit]
	}
	if q.AfterNum > 0 {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	page := event.AlertPage{Alerts: out, HasMore: hasMore}
	if len(out) > 0 {
		page.NewestNum = out[0].Num
		page.OldestNum = out[len(out)-1].Num
	}
	return page, rows.Err()
}

func (s *Store) Events(q, ip, source string, limit int) ([]event.Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var cond []string
	var args []any
	if ip != "" {
		cond = append(cond, "src_ip = ?")
		args = append(args, ip)
	}
	if source != "" {
		cond = append(cond, "source = ?")
		args = append(args, source)
	}
	if q != "" {
		cond = append(cond, "(url LIKE ? OR ua LIKE ? OR src_ip LIKE ? OR source LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like, like, like)
	}
	where := ""
	if len(cond) > 0 {
		where = "WHERE " + strings.Join(cond, " AND ")
	}
	args = append(args, limit)
	rows, err := s.db.Query(`SELECT id, ts, src_ip, method, url, path, query, status, bytes, ua, referer, host, source,
		COALESCE(user,''), COALESCE(kind,''), COALESCE(outcome,'')
		FROM events `+where+` ORDER BY ts DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []event.Event
	for rows.Next() {
		var e event.Event
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.SrcIP, &e.Method, &e.URL, &e.Path, &e.Query, &e.Status, &e.Bytes, &e.UA, &e.Referer, &e.Host, &e.Source, &e.User, &e.Kind, &e.Outcome); err != nil {
			return nil, err
		}
		e.Time = time.UnixMilli(ts).UTC()
		out = append(out, e)
	}
	if out == nil {
		out = []event.Event{}
	}
	return out, rows.Err()
}

func (s *Store) Attackers(since time.Time, limit int, source string) ([]event.Attacker, error) {
	if limit <= 0 {
		limit = 15
	}
	where := "WHERE ts >= ?"
	args := []any{since.UnixMilli()}
	if source != "" {
		where += " AND source = ?"
		args = append(args, source)
	}
	args = append(args, limit)
	rows, err := s.db.Query(`
SELECT src_ip, COUNT(*), MAX(ts),
       (SELECT title FROM alerts a2 WHERE a2.src_ip = a.src_ip ORDER BY ts DESC LIMIT 1),
       GROUP_CONCAT(DISTINCT category),
       COALESCE((SELECT country_name FROM alerts a3 WHERE a3.src_ip = a.src_ip AND IFNULL(country_name,'') != '' ORDER BY ts DESC LIMIT 1), '')
FROM alerts a
`+where+`
GROUP BY src_ip
ORDER BY COUNT(*) DESC
LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []event.Attacker
	for rows.Next() {
		var a event.Attacker
		var ts int64
		var cats string
		if err := rows.Scan(&a.SrcIP, &a.Alerts, &ts, &a.LastTitle, &cats, &a.Country); err != nil {
			return nil, err
		}
		a.LastSeen = time.UnixMilli(ts).UTC()
		if cats != "" {
			a.Categories = strings.Split(cats, ",")
		}
		out = append(out, a)
	}
	if out == nil {
		out = []event.Attacker{}
	}
	return out, rows.Err()
}

func (s *Store) Stats(rules int, source string) (event.Stats, error) {
	hour := time.Now().Add(-time.Hour).UnixMilli()
	st := event.Stats{
		BySeverity:  map[string]int64{},
		ByCategory:  map[string]int64{},
		ByStatus:    map[string]int64{},
		UptimeSec:   int64(time.Since(s.start).Seconds()),
		RulesLoaded: rules,
	}
	srcWhere, srcArgs := "", []any{}
	if source != "" {
		srcWhere = " AND source = ?"
		srcArgs = []any{source}
	}
	scan1 := func(q string, dest *int64, args ...any) {
		_ = s.db.QueryRow(q, args...).Scan(dest)
	}
	scan1(`SELECT COUNT(*) FROM events WHERE 1=1`+srcWhere, &st.EventsTotal, srcArgs...)
	scan1(`SELECT COUNT(*) FROM events WHERE ts >= ?`+srcWhere, &st.Events1h, append([]any{hour}, srcArgs...)...)
	scan1(`SELECT COUNT(*) FROM alerts WHERE 1=1`+srcWhere, &st.AlertsTotal, srcArgs...)
	scan1(`SELECT COUNT(*) FROM alerts WHERE ts >= ?`+srcWhere, &st.Alerts1h, append([]any{hour}, srcArgs...)...)
	scan1(`SELECT COUNT(*) FROM alerts WHERE ts >= ? AND severity = 'critical'`+srcWhere, &st.Critical1h, append([]any{hour}, srcArgs...)...)
	scan1(`SELECT COUNT(DISTINCT src_ip) FROM alerts WHERE ts >= ?`+srcWhere, &st.UniqueIPs1h, append([]any{hour}, srcArgs...)...)

	rows, err := s.db.Query(`SELECT severity, COUNT(*) FROM alerts WHERE ts >= ?`+srcWhere+` GROUP BY severity`, append([]any{hour}, srcArgs...)...)
	if err == nil {
		for rows.Next() {
			var k string
			var n int64
			if rows.Scan(&k, &n) == nil {
				st.BySeverity[k] = n
			}
		}
		rows.Close()
	}
	rows, err = s.db.Query(`SELECT category, COUNT(*) FROM alerts WHERE ts >= ?`+srcWhere+` GROUP BY category`, append([]any{hour}, srcArgs...)...)
	if err == nil {
		for rows.Next() {
			var k string
			var n int64
			if rows.Scan(&k, &n) == nil {
				st.ByCategory[k] = n
			}
		}
		rows.Close()
	}
	srows, err := s.db.Query(`SELECT status, COUNT(*) FROM events WHERE ts >= ?`+srcWhere+` GROUP BY status`, append([]any{hour}, srcArgs...)...)
	if err == nil {
		for srows.Next() {
			var code int
			var n int64
			if srows.Scan(&code, &n) == nil {
				st.ByStatus[fmt.Sprintf("%d", code)] = n
			}
		}
		srows.Close()
	}
	return st, nil
}

func (s *Store) MapArcs(since time.Time, limit int, source string) ([]event.MapArc, []event.MapCountry, error) {
	if limit <= 0 || limit > 400 {
		limit = 120
	}
	where := "WHERE ts >= ?"
	args := []any{since.UnixMilli()}
	if source != "" {
		where += " AND source = ?"
		args = append(args, source)
	}
	limitArgs := append(append([]any{}, args...), limit)
	rows, err := s.db.Query(`SELECT id, ts, src_ip, title, severity, category,
		COALESCE(country,''), COALESCE(country_name,''), COALESCE(lat,0), COALESCE(lon,0), COALESCE(source,'')
		FROM alerts `+where+`
		ORDER BY ts DESC LIMIT ?`, limitArgs...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var arcs []event.MapArc
	for rows.Next() {
		var a event.MapArc
		var ts int64
		if err := rows.Scan(&a.ID, &ts, &a.SrcIP, &a.Title, &a.Severity, &a.Category, &a.Country, &a.Name, &a.Lat, &a.Lon, &a.Source); err != nil {
			return nil, nil, err
		}
		a.Time = time.UnixMilli(ts).UTC()
		arcs = append(arcs, a)
	}
	if arcs == nil {
		arcs = []event.MapArc{}
	}
	crows, err := s.db.Query(`SELECT COALESCE(country,''), COALESCE(country_name,''), COUNT(*)
		FROM alerts `+where+` AND IFNULL(country,'') != ''
		GROUP BY country ORDER BY COUNT(*) DESC LIMIT 12`, args...)
	if err != nil {
		return arcs, []event.MapCountry{}, err
	}
	defer crows.Close()
	var countries []event.MapCountry
	for crows.Next() {
		var c event.MapCountry
		if err := crows.Scan(&c.Country, &c.Name, &c.Count); err != nil {
			return arcs, nil, err
		}
		countries = append(countries, c)
	}
	if countries == nil {
		countries = []event.MapCountry{}
	}
	return arcs, countries, nil
}

func (s *Store) Sources() ([]event.SourceInfo, error) {
	hour := time.Now().Add(-time.Hour).UnixMilli()
	rows, err := s.db.Query(`
SELECT source,
       SUM(ev) AS events_total,
       SUM(ev1h) AS events_1h,
       SUM(al1h) AS alerts_1h,
       MAX(last_ts) AS last_seen
FROM (
  SELECT IFNULL(source,'') AS source,
         COUNT(*) AS ev,
         SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS ev1h,
         0 AS al1h,
         MAX(ts) AS last_ts
  FROM events GROUP BY IFNULL(source,'')
  UNION ALL
  SELECT IFNULL(source,'') AS source,
         0,
         0,
         SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END),
         MAX(ts)
  FROM alerts GROUP BY IFNULL(source,'')
)
WHERE source != ''
GROUP BY source
ORDER BY events_1h DESC, alerts_1h DESC, source`, hour, hour)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []event.SourceInfo
	for rows.Next() {
		var info event.SourceInfo
		var ts int64
		if err := rows.Scan(&info.Name, &info.EventsTotal, &info.Events1h, &info.Alerts1h, &ts); err != nil {
			return nil, err
		}
		if ts > 0 {
			info.LastSeen = time.UnixMilli(ts).UTC()
		}
		out = append(out, info)
	}
	if out == nil {
		out = []event.SourceInfo{}
	}
	return out, rows.Err()
}

func (s *Store) Prune(olderThan time.Duration) error {
	cut := time.Now().Add(-olderThan).UnixMilli()
	_, _ = s.db.Exec(`DELETE FROM search_idx WHERE bucket = 'event' AND ref IN (SELECT id FROM events WHERE ts < ?)`, cut)
	if _, err := s.db.Exec(`DELETE FROM events WHERE ts < ?`, cut); err != nil {
		return err
	}
	alertCut := time.Now().Add(-olderThan * 4).UnixMilli()
	_, _ = s.db.Exec(`DELETE FROM search_idx WHERE bucket = 'alert' AND ref IN (SELECT id FROM alerts WHERE ts < ?)`, alertCut)
	_, err := s.db.Exec(`DELETE FROM alerts WHERE ts < ?`, alertCut)
	return err
}

func (s *Store) Ping() error { return s.db.Ping() }

var seq atomic.Uint64

func ID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixMicro(), seq.Add(1))
}
