package store

import (
	"fmt"
	"strings"
	"time"

	"gpewebdefender/internal/event"
)

func (s *Store) VectorReport(since time.Time, source string) (event.VectorReport, error) {
	rep := event.VectorReport{
		Since:      since,
		Source:     source,
		ByCategory: []event.NameCount{},
		ByRule:     []event.RuleCount{},
		ByPath:     []event.NameCount{},
		ByCountry:  []event.NameCount{},
		ByHour:     []event.HourCount{},
		TopIPs:     []event.Attacker{},
	}
	where, args := reportWhere(since, source, "")
	scan1 := func(q string, dest *int64, extra ...any) {
		_ = s.db.QueryRow(q, extra...).Scan(dest)
	}
	scan1(`SELECT COUNT(*) FROM alerts `+where, &rep.Alerts, args...)
	scan1(`SELECT COUNT(DISTINCT src_ip) FROM alerts `+where, &rep.UniqueIPs, args...)
	scan1(`SELECT COUNT(*) FROM alerts `+where+` AND severity = 'critical'`, &rep.Critical, args...)

	rows, err := s.db.Query(`SELECT COALESCE(category,''), COUNT(*), COUNT(DISTINCT src_ip)
		FROM alerts `+where+` GROUP BY category ORDER BY COUNT(*) DESC LIMIT 20`, args...)
	if err != nil {
		return rep, err
	}
	for rows.Next() {
		var n event.NameCount
		if rows.Scan(&n.Name, &n.Count, &n.IPs) == nil {
			if n.Name == "" {
				n.Name = "web"
			}
			rep.ByCategory = append(rep.ByCategory, n)
		}
	}
	rows.Close()

	rrows, err := s.db.Query(`SELECT COALESCE(rule_id,''), COALESCE(title,''), COALESCE(severity,''), COALESCE(category,''), COUNT(*)
		FROM alerts `+where+` GROUP BY rule_id ORDER BY COUNT(*) DESC LIMIT 16`, args...)
	if err != nil {
		return rep, err
	}
	for rrows.Next() {
		var n event.RuleCount
		if rrows.Scan(&n.ID, &n.Title, &n.Severity, &n.Category, &n.Count) == nil {
			rep.ByRule = append(rep.ByRule, n)
		}
	}
	rrows.Close()

	prows, err := s.db.Query(`SELECT path, COUNT(*), COUNT(DISTINCT src_ip) FROM (
		SELECT CASE WHEN instr(url,'?')>0 THEN substr(url,1,instr(url,'?')-1) ELSE url END AS path, src_ip
		FROM alerts `+where+`
	) GROUP BY path ORDER BY COUNT(*) DESC LIMIT 16`, args...)
	if err != nil {
		return rep, err
	}
	for prows.Next() {
		var n event.NameCount
		if prows.Scan(&n.Name, &n.Count, &n.IPs) == nil && n.Name != "" {
			rep.ByPath = append(rep.ByPath, n)
		}
	}
	prows.Close()

	crows, err := s.db.Query(`SELECT COALESCE(country,''), COALESCE(country_name,''), COUNT(*)
		FROM alerts `+where+` AND IFNULL(country,'') != ''
		GROUP BY country ORDER BY COUNT(*) DESC LIMIT 12`, args...)
	if err != nil {
		return rep, err
	}
	for crows.Next() {
		var iso, name string
		var n int64
		if crows.Scan(&iso, &name, &n) == nil {
			if name == "" {
				name = iso
			}
			rep.ByCountry = append(rep.ByCountry, event.NameCount{Name: name, Count: n})
		}
	}
	crows.Close()

	hrows, err := s.db.Query(`SELECT (ts / 3600000) * 3600000, COUNT(*)
		FROM alerts `+where+` GROUP BY 1 ORDER BY 1`, args...)
	if err != nil {
		return rep, err
	}
	for hrows.Next() {
		var ms, n int64
		if hrows.Scan(&ms, &n) == nil {
			rep.ByHour = append(rep.ByHour, event.HourCount{Time: time.UnixMilli(ms).UTC(), Count: n})
		}
	}
	hrows.Close()

	ips, err := s.Attackers(since, 12, source)
	if err != nil {
		return rep, err
	}
	rep.TopIPs = ips
	return rep, nil
}

func (s *Store) AuthReport(channel string, since time.Time, source string) (event.AuthReport, error) {
	rep := event.AuthReport{
		Channel:  channel,
		Since:    since,
		Source:   source,
		ByStatus: map[string]int64{},
		ByPath:   []event.NameCount{},
		ByUser:   []event.NameCount{},
		BySource: []event.NameCount{},
		TopIPs:   []event.AuthIP{},
		Recent:   []event.Event{},
	}
	kindFilter, failSQL := authSQL(channel)
	where, args := reportWhere(since, source, kindFilter)
	hour := time.Now().Add(-time.Hour).UnixMilli()

	scan1 := func(q string, dest *int64, extra ...any) {
		_ = s.db.QueryRow(q, extra...).Scan(dest)
	}
	scan1(`SELECT COUNT(*) FROM events `+where+` AND (`+failSQL+`)`, &rep.Fails, args...)
	scan1(`SELECT COUNT(*) FROM events `+where+` AND (`+failSQL+`) AND ts >= ?`, &rep.Fails1h, append(append([]any{}, args...), hour)...)
	scan1(`SELECT COUNT(*) FROM events `+where+` AND (outcome = 'ok' OR status IN (200,201,204,302))`, &rep.Success, args...)
	scan1(`SELECT COUNT(DISTINCT src_ip) FROM events `+where+` AND IFNULL(src_ip,'') != '' AND (`+failSQL+`)`, &rep.UniqueIPs, args...)
	scan1(`SELECT COUNT(DISTINCT user) FROM events `+where+` AND IFNULL(user,'') != '' AND (`+failSQL+`)`, &rep.UniqueUsers, args...)

	srows, err := s.db.Query(`SELECT status, COUNT(*) FROM events `+where+` GROUP BY status`, args...)
	if err != nil {
		return rep, err
	}
	for srows.Next() {
		var code int
		var n int64
		if srows.Scan(&code, &n) == nil {
			rep.ByStatus[fmt.Sprintf("%d", code)] = n
		}
	}
	srows.Close()

	prows, err := s.db.Query(`SELECT path, COUNT(*) FROM (
		SELECT CASE WHEN IFNULL(path,'') != '' THEN path
		            WHEN instr(url,'?')>0 THEN substr(url,1,instr(url,'?')-1)
		            ELSE url END AS path
		FROM events `+where+` AND (`+failSQL+`)
	) GROUP BY path ORDER BY COUNT(*) DESC LIMIT 12`, args...)
	if err != nil {
		return rep, err
	}
	for prows.Next() {
		var n event.NameCount
		if prows.Scan(&n.Name, &n.Count) == nil && n.Name != "" {
			rep.ByPath = append(rep.ByPath, n)
		}
	}
	prows.Close()

	urows, err := s.db.Query(`SELECT user, COUNT(*) FROM events `+where+` AND (`+failSQL+`) AND IFNULL(user,'') != ''
		GROUP BY user ORDER BY COUNT(*) DESC LIMIT 12`, args...)
	if err != nil {
		return rep, err
	}
	for urows.Next() {
		var n event.NameCount
		if urows.Scan(&n.Name, &n.Count) == nil {
			rep.ByUser = append(rep.ByUser, n)
		}
	}
	urows.Close()

	srcRows, err := s.db.Query(`SELECT COALESCE(source,''), COUNT(*) FROM events `+where+` AND (`+failSQL+`)
		GROUP BY source ORDER BY COUNT(*) DESC LIMIT 12`, args...)
	if err != nil {
		return rep, err
	}
	for srcRows.Next() {
		var n event.NameCount
		if srcRows.Scan(&n.Name, &n.Count) == nil && n.Name != "" {
			rep.BySource = append(rep.BySource, n)
		}
	}
	srcRows.Close()

	ipRows, err := s.db.Query(`SELECT src_ip, COUNT(*), COUNT(DISTINCT user), MAX(ts),
		COALESCE((SELECT user FROM events e2 WHERE e2.src_ip = e.src_ip AND IFNULL(e2.user,'') != '' ORDER BY ts DESC LIMIT 1),'')
		FROM events e `+where+` AND (`+failSQL+`) AND IFNULL(src_ip,'') != ''
		GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 12`, args...)
	if err != nil {
		return rep, err
	}
	for ipRows.Next() {
		var a event.AuthIP
		var ts int64
		if ipRows.Scan(&a.SrcIP, &a.Count, &a.Users, &ts, &a.LastUser) == nil {
			a.LastSeen = time.UnixMilli(ts).UTC()
			rep.TopIPs = append(rep.TopIPs, a)
		}
	}
	ipRows.Close()

	recentArgs := append(append([]any{}, args...), 40)
	erows, err := s.db.Query(`SELECT id, ts, src_ip, method, url, path, query, status, bytes, ua, referer, host, source,
		COALESCE(user,''), COALESCE(kind,''), COALESCE(outcome,'')
		FROM events `+where+` AND (`+failSQL+`) ORDER BY ts DESC LIMIT ?`, recentArgs...)
	if err != nil {
		return rep, err
	}
	defer erows.Close()
	for erows.Next() {
		var e event.Event
		var ts int64
		if err := erows.Scan(&e.ID, &ts, &e.SrcIP, &e.Method, &e.URL, &e.Path, &e.Query, &e.Status, &e.Bytes, &e.UA, &e.Referer, &e.Host, &e.Source, &e.User, &e.Kind, &e.Outcome); err != nil {
			return rep, err
		}
		e.Time = time.UnixMilli(ts).UTC()
		rep.Recent = append(rep.Recent, e)
	}
	return rep, erows.Err()
}

func reportWhere(since time.Time, source, extra string) (string, []any) {
	var cond []string
	var args []any
	if !since.IsZero() {
		cond = append(cond, "ts >= ?")
		args = append(args, since.UnixMilli())
	}
	if source != "" {
		cond = append(cond, "source = ?")
		args = append(args, source)
	}
	if extra != "" {
		cond = append(cond, extra)
	}
	if len(cond) == 0 {
		return "", nil
	}
	return "WHERE " + strings.Join(cond, " AND "), args
}

func authSQL(channel string) (kindFilter, failSQL string) {
	switch strings.ToLower(channel) {
	case "linux", "hostauth", "ssh":
		return "kind = 'hostauth'", "(outcome = 'fail' OR status IN (401,403))"
	case "app", "applogin", "platform":
		return "kind = 'applogin'", "(outcome = 'fail' OR status IN (401,403))"
	case "tenant", "tenantlogin", "owner", "ownerlogin":
		return "kind = 'tenantlogin'", "(outcome = 'fail' OR status IN (401,403))"
	default:
		// Web: 401/403 or obvious login paths. Empty kind is legacy access-log rows.
		return "(IFNULL(kind,'') IN ('','web'))",
			`(status IN (401,403) OR lower(path) LIKE '%login%' OR lower(path) LIKE '%signin%'
			  OR lower(path) LIKE '%sign-in%' OR lower(path) LIKE '%/auth%'
			  OR lower(path) LIKE '%wp-login%' OR lower(path) LIKE '%session%')`
	}
}
