package store

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"gpewebdefender/internal/event"
)

func (s *Store) VectorReport(since time.Time, source string) (event.VectorReport, error) {
	until := time.Now().UTC()
	step, bucketName := reportStep(since, until)
	rep := event.VectorReport{
		Since:      since.UTC(),
		Until:      until,
		Bucket:     bucketName,
		Source:     source,
		ByCategory: []event.NameCount{},
		BySeverity: []event.NameCount{},
		BySource:   []event.NameCount{},
		ByMITRE:    []event.NameCount{},
		ByRule:     []event.RuleCount{},
		ByPath:     []event.NameCount{},
		ByCountry:  []event.NameCount{},
		ByHour:     []event.HourCount{},
		HourMix:    []event.HourCat{},
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

	sevRows, err := s.db.Query(`SELECT COALESCE(NULLIF(severity,''),'medium'), COUNT(*)
		FROM alerts `+where+` GROUP BY 1 ORDER BY COUNT(*) DESC`, args...)
	if err != nil {
		return rep, err
	}
	for sevRows.Next() {
		var n event.NameCount
		if sevRows.Scan(&n.Name, &n.Count) == nil {
			rep.BySeverity = append(rep.BySeverity, n)
		}
	}
	sevRows.Close()

	srcRows, err := s.db.Query(`SELECT COALESCE(NULLIF(source,''),'(none)'), COUNT(*), COUNT(DISTINCT src_ip)
		FROM alerts `+where+` GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 12`, args...)
	if err != nil {
		return rep, err
	}
	for srcRows.Next() {
		var n event.NameCount
		if srcRows.Scan(&n.Name, &n.Count, &n.IPs) == nil {
			rep.BySource = append(rep.BySource, n)
		}
	}
	srcRows.Close()

	if tags, err := s.mitreRollup(where, args); err == nil {
		rep.ByMITRE = tags
	}

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
			rep.ByCountry = append(rep.ByCountry, event.NameCount{Name: name, Key: iso, Count: n})
		}
	}
	crows.Close()

	hourArgs := append([]any{step, step}, args...)
	hrows, err := s.db.Query(`SELECT (ts / ?) * ?, COUNT(*)
		FROM alerts `+where+` GROUP BY 1 ORDER BY 1`, hourArgs...)
	if err != nil {
		return rep, err
	}
	var rawHours []event.HourCount
	for hrows.Next() {
		var ms, n int64
		if hrows.Scan(&ms, &n) == nil {
			rawHours = append(rawHours, event.HourCount{Time: time.UnixMilli(ms).UTC(), Count: n})
		}
	}
	hrows.Close()
	rep.ByHour = fillHours(since, until, step, rawHours)

	mixArgs := append([]any{step, step}, args...)
	mixRows, err := s.db.Query(`SELECT (ts / ?) * ?, COALESCE(NULLIF(category,''),'web'), COUNT(*)
		FROM alerts `+where+` GROUP BY 1, 2 ORDER BY 1`, mixArgs...)
	if err != nil {
		return rep, err
	}
	var rawMix []event.HourCat
	for mixRows.Next() {
		var ms int64
		var h event.HourCat
		if mixRows.Scan(&ms, &h.Category, &h.Count) == nil {
			h.Time = time.UnixMilli(ms).UTC()
			rawMix = append(rawMix, h)
		}
	}
	mixRows.Close()
	rep.HourMix = fillMix(since, until, step, rawMix)

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
		Since:    since.UTC(),
		Until:    time.Now().UTC(),
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

func reportStep(since, until time.Time) (int64, string) {
	d := until.Sub(since)
	switch {
	case d <= 2*time.Hour:
		return 5 * 60 * 1000, "5m"
	case d <= 36*time.Hour:
		return 60 * 60 * 1000, "1h"
	default:
		return 4 * 60 * 60 * 1000, "4h"
	}
}

func fillHours(since, until time.Time, step int64, have []event.HourCount) []event.HourCount {
	if step <= 0 {
		return have
	}
	by := map[int64]int64{}
	for _, h := range have {
		by[h.Time.UnixMilli()] = h.Count
	}
	start := (since.UTC().UnixMilli() / step) * step
	end := until.UTC().UnixMilli()
	out := []event.HourCount{}
	for t := start; t <= end; t += step {
		out = append(out, event.HourCount{Time: time.UnixMilli(t).UTC(), Count: by[t]})
	}
	return out
}

func fillMix(since, until time.Time, step int64, have []event.HourCat) []event.HourCat {
	if step <= 0 {
		return have
	}
	type key struct {
		t   int64
		cat string
	}
	by := map[key]int64{}
	cats := []string{}
	seen := map[string]bool{}
	for _, h := range have {
		by[key{h.Time.UnixMilli(), h.Category}] = h.Count
		if h.Category != "" && !seen[h.Category] {
			seen[h.Category] = true
			cats = append(cats, h.Category)
		}
	}
	start := (since.UTC().UnixMilli() / step) * step
	end := until.UTC().UnixMilli()
	out := []event.HourCat{}
	for t := start; t <= end; t += step {
		got := false
		for _, cat := range cats {
			n := by[key{t, cat}]
			if n == 0 {
				continue
			}
			out = append(out, event.HourCat{Time: time.UnixMilli(t).UTC(), Category: cat, Count: n})
			got = true
		}
		if !got {
			out = append(out, event.HourCat{Time: time.UnixMilli(t).UTC(), Category: "", Count: 0})
		}
	}
	return out
}

func (s *Store) ExportAlerts(since time.Time, source string, limit int) ([]event.Alert, error) {
	if limit <= 0 || limit > 10000 {
		limit = 5000
	}
	where, args := reportWhere(since, source, "")
	args = append(args, limit)
	rows, err := s.db.Query(`SELECT id, ts, event_id, rule_id, title, severity, category, src_ip, method, url, status, ua, evidence, mitre, count, source,
		COALESCE(country,''), COALESCE(country_name,''), COALESCE(lat,0), COALESCE(lon,0), COALESCE(tags,''), COALESCE(num,0)
		FROM alerts `+where+` ORDER BY ts DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []event.Alert
	for rows.Next() {
		var a event.Alert
		var ts int64
		var mitre, tags string
		if err := rows.Scan(&a.ID, &ts, &a.EventID, &a.RuleID, &a.Title, &a.Severity, &a.Category, &a.SrcIP, &a.Method, &a.URL, &a.Status, &a.UA, &a.Evidence, &mitre, &a.Count, &a.Source,
			&a.Country, &a.CountryName, &a.Lat, &a.Lon, &tags, &a.Num); err != nil {
			return nil, err
		}
		a.Time = time.UnixMilli(ts).UTC()
		_ = json.Unmarshal([]byte(mitre), &a.MITRE)
		_ = json.Unmarshal([]byte(tags), &a.Tags)
		out = append(out, a)
	}
	if out == nil {
		out = []event.Alert{}
	}
	return out, rows.Err()
}

func (s *Store) ExportEvents(since time.Time, source, kindFilter string, limit int) ([]event.Event, error) {
	if limit <= 0 || limit > 10000 {
		limit = 5000
	}
	where, args := reportWhere(since, source, kindFilter)
	args = append(args, limit)
	rows, err := s.db.Query(`SELECT id, ts, src_ip, method, url, path, query, status, bytes, ua, referer, host, source,
		COALESCE(user,''), COALESCE(kind,''), COALESCE(outcome,''), COALESCE(reason,'')
		FROM events `+where+` ORDER BY ts DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []event.Event
	for rows.Next() {
		var e event.Event
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.SrcIP, &e.Method, &e.URL, &e.Path, &e.Query, &e.Status, &e.Bytes, &e.UA, &e.Referer, &e.Host, &e.Source, &e.User, &e.Kind, &e.Outcome, &e.Reason); err != nil {
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

func (s *Store) mitreRollup(where string, args []any) ([]event.NameCount, error) {
	rows, err := s.db.Query(`SELECT mitre FROM alerts `+where+` AND IFNULL(mitre,'') NOT IN ('','null','[]')`, args...)
	if err != nil {
		return []event.NameCount{}, err
	}
	defer rows.Close()
	counts := map[string]int64{}
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) != nil {
			continue
		}
		var tags []string
		if json.Unmarshal([]byte(raw), &tags) != nil {
			continue
		}
		seen := map[string]bool{}
		for _, t := range tags {
			t = strings.TrimSpace(t)
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			counts[t]++
		}
	}
	out := make([]event.NameCount, 0, len(counts))
	for name, n := range counts {
		out = append(out, event.NameCount{Name: name, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > 16 {
		out = out[:16]
	}
	if out == nil {
		out = []event.NameCount{}
	}
	return out, rows.Err()
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
	case "probes", "secprobe", "sec":
		return "kind = 'secprobe'", "1=1"
	default:
		// Web: 401/403 or obvious login paths. Empty kind is legacy access-log rows.
		return "(IFNULL(kind,'') IN ('','web'))",
			`(status IN (401,403) OR lower(path) LIKE '%login%' OR lower(path) LIKE '%signin%'
			  OR lower(path) LIKE '%sign-in%' OR lower(path) LIKE '%/auth%'
			  OR lower(path) LIKE '%wp-login%' OR lower(path) LIKE '%session%')`
	}
}
