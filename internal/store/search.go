package store

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gpewebdefender/internal/event"
)

func (s *Store) initSearch() error {
	if rows, err := s.db.Query(`SELECT ts FROM search_idx LIMIT 1`); err != nil {
		_, _ = s.db.Exec(`DROP TABLE IF EXISTS search_idx`)
	} else {
		rows.Close()
	}
	_, err := s.db.Exec(`CREATE VIRTUAL TABLE IF NOT EXISTS search_idx USING fts5(
		bucket, ref, num, src_ip, user, host, source, path, url, title, evidence, kind, category, ts UNINDEXED
	)`)
	if err != nil {
		return err
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM search_idx`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err = s.db.Exec(`INSERT INTO search_idx(bucket, ref, num, src_ip, user, host, source, path, url, title, evidence, kind, category, ts)
		SELECT 'event', id, '', IFNULL(src_ip,''), IFNULL(user,''), IFNULL(host,''), IFNULL(source,''),
		       IFNULL(path,''), IFNULL(url,''), '', '', IFNULL(kind,''), '', CAST(ts AS TEXT)
		FROM events`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO search_idx(bucket, ref, num, src_ip, user, host, source, path, url, title, evidence, kind, category, ts)
		SELECT 'alert', id, CAST(IFNULL(num,0) AS TEXT), IFNULL(src_ip,''), '', '', IFNULL(source,''),
		       '', IFNULL(url,''), IFNULL(title,''), IFNULL(evidence,''), '', IFNULL(category,''), CAST(ts AS TEXT)
		FROM alerts`)
	return err
}

func (s *Store) indexEvent(ev event.Event) {
	_, _ = s.db.Exec(`DELETE FROM search_idx WHERE bucket = 'event' AND ref = ?`, ev.ID)
	_, _ = s.db.Exec(`INSERT INTO search_idx(bucket, ref, num, src_ip, user, host, source, path, url, title, evidence, kind, category, ts)
		VALUES('event', ?, '', ?, ?, ?, ?, ?, ?, ?, '', ?, '', ?)`,
		ev.ID, ev.SrcIP, ev.User, ev.Host, ev.Source, ev.Path, ev.URL, ev.Reason, ev.Kind, fmt.Sprintf("%d", ev.Time.UTC().UnixMilli()))
}

func (s *Store) indexAlert(al event.Alert) {
	_, _ = s.db.Exec(`DELETE FROM search_idx WHERE bucket = 'alert' AND ref = ?`, al.ID)
	_, _ = s.db.Exec(`INSERT INTO search_idx(bucket, ref, num, src_ip, user, host, source, path, url, title, evidence, kind, category, ts)
		VALUES('alert', ?, ?, ?, ?, '', ?, '', ?, ?, ?, ?, ?, ?)`,
		al.ID, fmt.Sprintf("%d", al.Num), al.SrcIP, al.User, al.Source, al.URL, al.Title, al.Evidence, al.Kind, al.Category, fmt.Sprintf("%d", al.Time.UTC().UnixMilli()))
}

type SearchQuery struct {
	Q, IP, Host, Source, Kind string
	Limit                     int
	OldestFirst               bool
}

func ftsMatch(q string) string {
	var parts []string
	for _, w := range strings.Fields(q) {
		w = strings.Trim(w, `"*()'`)
		if w == "" {
			continue
		}
		parts = append(parts, `"`+strings.ReplaceAll(w, `"`, "")+`"`)
	}
	return strings.Join(parts, " AND ")
}

func (s *Store) Search(q SearchQuery) (event.SearchPage, error) {
	start := time.Now()
	if q.Limit <= 0 || q.Limit > 100 {
		q.Limit = 40
	}
	var cond []string
	var args []any
	if match := ftsMatch(q.Q); match != "" {
		cond = append(cond, "search_idx MATCH ?")
		args = append(args, match)
	}
	if q.IP != "" {
		cond = append(cond, "src_ip = ?")
		args = append(args, q.IP)
	}
	if q.Host != "" {
		cond = append(cond, "(host = ? OR source = ?)")
		args = append(args, q.Host, q.Host)
	}
	if q.Source != "" {
		cond = append(cond, "source = ?")
		args = append(args, q.Source)
	}
	if q.Kind != "" {
		cond = append(cond, "kind = ?")
		args = append(args, q.Kind)
	}
	if len(cond) == 0 {
		return event.SearchPage{Hits: []event.SearchHit{}}, nil
	}
	args = append(args, q.Limit+1)
	order := "DESC"
	if q.OldestFirst {
		order = "ASC"
	}
	sql := `SELECT bucket, ref, num, src_ip, user, host, source, path, url, title, kind, category, ts
		FROM search_idx WHERE ` + strings.Join(cond, " AND ") + `
		ORDER BY CAST(ts AS INTEGER) ` + order + ` LIMIT ?`
	rows, err := s.db.Query(sql, args...)
	if err != nil {
		return event.SearchPage{}, err
	}
	defer rows.Close()
	var hits []event.SearchHit
	for rows.Next() {
		var h event.SearchHit
		var num, tsRaw string
		if err := rows.Scan(&h.Bucket, &h.Ref, &num, &h.SrcIP, &h.User, &h.Host, &h.Source, &h.Path, &h.URL, &h.Title, &h.Kind, &h.Category, &tsRaw); err != nil {
			return event.SearchPage{}, err
		}
		h.Num, _ = strconv.ParseInt(num, 10, 64)
		if ts, err := strconv.ParseInt(tsRaw, 10, 64); err == nil && ts > 0 {
			h.Time = time.UnixMilli(ts).UTC()
		}
		hits = append(hits, h)
	}
	if hits == nil {
		hits = []event.SearchHit{}
	}
	// Fill time/severity from the source tables (indexed by PK).
	for i := range hits {
		if hits[i].Bucket == "alert" {
			var ts int64
			var sev string
			_ = s.db.QueryRow(`SELECT ts, IFNULL(severity,'') FROM alerts WHERE id = ?`, hits[i].Ref).Scan(&ts, &sev)
			hits[i].Time = time.UnixMilli(ts).UTC()
			hits[i].Severity = sev
		} else {
			var ts int64
			_ = s.db.QueryRow(`SELECT ts FROM events WHERE id = ?`, hits[i].Ref).Scan(&ts)
			hits[i].Time = time.UnixMilli(ts).UTC()
		}
	}
	page := event.SearchPage{Hits: hits, TookMS: time.Since(start).Milliseconds()}
	if len(hits) > q.Limit {
		page.HasMore = true
		page.Hits = hits[:q.Limit]
	}
	return page, rows.Err()
}
