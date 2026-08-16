package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"gpewebdefender/internal/event"
	"gpewebdefender/internal/geo"
	"gpewebdefender/internal/hub"
	"gpewebdefender/internal/intel"
	"gpewebdefender/internal/pipeline"
	"gpewebdefender/internal/store"
	"gpewebdefender/ui"
)

type Server struct {
	Pipe    *pipeline.Pipeline
	Store   *store.Store
	Hub     *hub.Hub
	Token   string
	DocsDir string
	Version string
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/stats", s.stats)
	mux.HandleFunc("GET /api/alerts", s.alerts)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("GET /api/attackers", s.attackers)
	mux.HandleFunc("GET /api/rules", s.rules)
	mux.HandleFunc("GET /api/stream", s.Hub.ServeSSE)
	mux.HandleFunc("POST /api/ingest", s.ingest)
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/map", s.mapFeed)
	mux.HandleFunc("GET /api/sources", s.sources)
	mux.HandleFunc("GET /api/reports/vectors", s.reportVectors)
	mux.HandleFunc("GET /api/reports/auth", s.reportAuth)
	mux.HandleFunc("GET /api/export/alerts", s.exportAlerts)
	mux.HandleFunc("GET /api/export/events", s.exportEvents)
	mux.HandleFunc("GET /api/intel", s.intelIP)
	mux.HandleFunc("GET /api/settings", s.getSettings)
	mux.HandleFunc("PUT /api/settings", s.putSettings)
	mux.HandleFunc("GET /api/search", s.search)
	mux.HandleFunc("GET /api/auth-status", s.authStatus)
	mux.HandleFunc("GET /api/me", s.me)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/setup", s.setup)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /api/users", s.listUsers)
	mux.HandleFunc("POST /api/users", s.createUser)
	mux.HandleFunc("DELETE /api/users/{id}", s.deleteUser)
	mux.HandleFunc("POST /api/users/{id}/password", s.adminSetPassword)
	mux.HandleFunc("POST /api/users/{id}/disable", s.disableUser)
	mux.HandleFunc("POST /api/me/password", s.changePassword)
	mux.HandleFunc("GET /login", s.serveLogin)
	mux.HandleFunc("GET /login.html", s.serveLogin)
	s.registerAgentRoutes(mux)
	if s.DocsDir != "" {
		mux.HandleFunc("GET /docs", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/docs/", http.StatusFound)
		})
		mux.Handle("GET /docs/", http.StripPrefix("/docs/", s.docsHandler()))
	}
	mux.HandleFunc("GET /", serveUI)
	return s.auth(mux)
}

func (s *Server) docsHandler() http.Handler {
	root := os.DirFS(s.DocsDir)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := path.Clean("/" + r.URL.Path)
		p = strings.TrimPrefix(p, "/")
		if p == "." || p == "" || strings.HasSuffix(p, "/") {
			p = "index.html"
		}
		if strings.Contains(p, "..") {
			http.NotFound(w, r)
			return
		}
		st, err := fs.Stat(root, p)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if st.IsDir() {
			p = path.Join(p, "index.html")
			if _, err := fs.Stat(root, p); err != nil {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		b, err := fs.ReadFile(root, p)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		switch {
		case strings.HasSuffix(p, ".html"):
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case strings.HasSuffix(p, ".css"):
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		case strings.HasSuffix(p, ".js"):
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		}
		_, _ = w.Write(b)
	})
}

func serveUI(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/")
	if p == "" {
		p = "index.html"
	}
	// Only embedded UI files — never walk the process cwd.
	ok := p == "index.html" || p == "app.css" || p == "app.js" || p == "map-basemap.jpg"
	if strings.HasPrefix(p, "icons/") && strings.HasSuffix(p, ".svg") && !strings.Contains(p, "..") {
		ok = true
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	b, err := ui.FS.ReadFile(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(p, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case strings.HasSuffix(p, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(p, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case strings.HasSuffix(p, ".jpg"), strings.HasSuffix(p, ".jpeg"):
		w.Header().Set("Content-Type", "image/jpeg")
	case strings.HasSuffix(p, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	}
	_, _ = w.Write(b)
}



func (s *Server) mapFeed(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-24 * time.Hour)
	if v := r.URL.Query().Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			since = time.Now().Add(-d)
		}
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	source := r.URL.Query().Get("source")
	arcs, countries, err := s.Store.MapArcs(since, limit, source)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if s.Pipe.Geo != nil {
		for i := range arcs {
			if arcs[i].Country != "" && (arcs[i].Lat != 0 || arcs[i].Lon != 0) {
				continue
			}
			loc := s.Pipe.Geo.Lookup(arcs[i].SrcIP)
			if !loc.Ok {
				continue
			}
			arcs[i].Lat = loc.Lat
			arcs[i].Lon = loc.Lon
			arcs[i].Country = loc.Country
			if arcs[i].Name == "" {
				arcs[i].Name = loc.Name
			}
		}
		// rebuild country rollup after live lookup
		roll := map[string]*event.MapCountry{}
		for _, a := range arcs {
			if a.Country == "" {
				continue
			}
			c := roll[a.Country]
			if c == nil {
				c = &event.MapCountry{Country: a.Country, Name: a.Name}
				roll[a.Country] = c
			}
			c.Count++
		}
		countries = countries[:0]
		for _, c := range roll {
			countries = append(countries, *c)
		}
		sort.Slice(countries, func(i, j int) bool { return countries[i].Count > countries[j].Count })
	}
	feed := event.MapFeed{Arcs: arcs, Countries: countries}
	if s.Pipe.Geo != nil {
		h := s.Pipe.Geo.Home()
		feed.Home = event.MapHome{Lat: h.Lat, Lon: h.Lon, Country: h.Country, Name: h.Name}
		for _, loc := range s.Pipe.Geo.NamedHomes() {
			feed.Homes = append(feed.Homes, event.MapHome{
				Lat: loc.Lat, Lon: loc.Lon, Country: loc.Country, Name: loc.Name, Source: loc.Name,
			})
		}
		feed.GeoIP = s.Pipe.Geo.HasMMDB()
	}
	writeJSON(w, feed)
}

func (s *Server) sources(w http.ResponseWriter, _ *http.Request) {
	list, err := s.Store.Sources()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	seen := map[string]bool{}
	for _, src := range list {
		seen[src.Name] = true
	}
	var homes []event.MapHome
	if s.Pipe.Geo != nil {
		h := s.Pipe.Geo.Home()
		homes = append(homes, event.MapHome{Lat: h.Lat, Lon: h.Lon, Country: h.Country, Name: h.Name})
		for _, loc := range s.Pipe.Geo.NamedHomes() {
			homes = append(homes, event.MapHome{
				Lat: loc.Lat, Lon: loc.Lon, Country: loc.Country, Name: loc.Name, Source: loc.Name,
			})
			if !seen[loc.Name] {
				list = append(list, event.SourceInfo{Name: loc.Name})
				seen[loc.Name] = true
			}
		}
	}
	writeJSON(w, map[string]any{"sources": list, "homes": homes})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	geoip, rules := false, 0
	var seen, fired, drop, quiet int64
	if s.Pipe != nil {
		geoip = s.Pipe.Geo != nil && s.Pipe.Geo.HasMMDB()
		if s.Pipe.Engine != nil {
			rules = s.Pipe.Engine.Len()
		}
		seen = s.Pipe.Seen.Load()
		fired = s.Pipe.Fired.Load()
		drop = s.Pipe.Dropped.Load()
		quiet = s.Pipe.Quiet.Load()
	}
	writeJSON(w, map[string]any{
		"ok":    true,
		"seen":  seen,
		"fired": fired,
		"drop":  drop,
		"quiet": quiet,
		"rules": rules,
		"geoip": geoip,
	})
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	st, err := s.Store.Stats(s.Pipe.Engine.Len(), r.URL.Query().Get("source"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, st)
}

func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	since := time.Time{}
	if v := q.Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			since = time.Now().Add(-d)
		}
	}
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
	page, err := s.Store.Alerts(store.AlertQuery{
		Q: q.Get("q"), Severity: q.Get("severity"), IP: q.Get("ip"), Source: q.Get("source"),
		Plane: q.Get("plane"),
		Since: since, Limit: limit, BeforeNum: before, AfterNum: after,
	})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, page)
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	page, err := s.Store.Search(store.SearchQuery{
		Q: q.Get("q"), IP: q.Get("ip"), Host: q.Get("host"),
		Source: q.Get("source"), Kind: q.Get("kind"), Limit: limit,
		OldestFirst: q.Get("sort") == "oldest",
	})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, page)
}

func (s *Server) getSettings(w http.ResponseWriter, _ *http.Request) {
	st, err := s.Store.Settings()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if d, err := time.ParseDuration(st.Retain); err == nil && d > 0 {
		h := int(d.Hours())
		if h > 0 && time.Duration(h)*time.Hour == d {
			st.Retain = fmt.Sprintf("%dh", h)
		}
	}
	geoip, rules := false, 0
	if s.Pipe != nil {
		geoip = s.Pipe.Geo != nil && s.Pipe.Geo.HasMMDB()
		if s.Pipe.Engine != nil {
			rules = s.Pipe.Engine.Len()
		}
	}
	writeJSON(w, map[string]any{
		"settings":  st,
		"token_set": s.Token != "",
		"geoip":     geoip,
		"rules":     rules,
	})
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	if s.Store.UserCount() > 0 {
		if _, ok := s.requireAdmin(w, r); !ok {
			return
		}
	}
	var in event.Settings
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	in.Home = strings.TrimSpace(in.Home)
	in.Homes = strings.TrimSpace(in.Homes)
	in.SiteName = strings.TrimSpace(in.SiteName)
	in.Retain = strings.TrimSpace(in.Retain)
	in.Timezone = strings.TrimSpace(in.Timezone)
	if in.Home != "" {
		if _, err := geo.ParseHome(in.Home); err != nil {
			http.Error(w, "home: "+err.Error(), 400)
			return
		}
	}
	if in.Homes != "" {
		if _, err := geo.ParseHomes(in.Homes); err != nil {
			http.Error(w, "homes: "+err.Error(), 400)
			return
		}
	}
	if in.Retain != "" {
		d, err := time.ParseDuration(in.Retain)
		if err != nil || d < time.Hour {
			http.Error(w, "retain: use a Go duration of at least 1h (e.g. 168h)", 400)
			return
		}
	}
	if in.Timezone != "" && in.Timezone != "UTC" && in.Timezone != "local" {
		http.Error(w, "timezone: UTC or local", 400)
		return
	}
	if err := s.Store.PutSettings(in); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if s.Pipe.Geo != nil {
		if in.Home != "" {
			_ = s.Pipe.Geo.SetHome(in.Home)
		}
		_ = s.Pipe.Geo.SetHomes(in.Homes)
	}
	writeJSON(w, map[string]any{"ok": true, "settings": in})
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	ev, err := s.Store.Events(q.Get("q"), q.Get("ip"), q.Get("source"), limit)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, ev)
}

func (s *Server) attackers(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-24 * time.Hour)
	if v := r.URL.Query().Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			since = time.Now().Add(-d)
		}
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	at, err := s.Store.Attackers(since, limit, r.URL.Query().Get("source"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, at)
}

func (s *Server) rules(w http.ResponseWriter, _ *http.Request) {
	type info struct {
		ID       string   `json:"id"`
		Title    string   `json:"title"`
		Severity string   `json:"severity"`
		Category string   `json:"category"`
		MITRE    []string `json:"mitre,omitempty"`
		Kind     string   `json:"kind"`
	}
	var out []info
	for _, r := range s.Pipe.Engine.Rules() {
		out = append(out, info{
			ID: r.ID, Title: r.Title, Severity: r.Severity,
			Category: r.Category, MITRE: r.MITRE, Kind: r.Kind,
		})
	}
	writeJSON(w, out)
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "read", 400)
		return
	}
	ct := r.Header.Get("Content-Type")
	source := r.Header.Get("X-SIEM-Source")
	if source == "" {
		source = r.Header.Get("X-GPE-Source")
	}
	if source == "" {
		source = r.RemoteAddr
	}
	if ag, ok := s.reqAgent(r); ok {
		source = ag.Name
	}
	n := 0
	if strings.Contains(ct, "application/json") {
		var lines []string
		if json.Unmarshal(body, &lines) == nil {
			for _, line := range lines {
				s.Pipe.IngestLine(line, source)
				n++
			}
		} else {
			var ev event.Event
			if json.Unmarshal(body, &ev) == nil && ev.SrcIP != "" {
				if ev.Source == "" {
					ev.Source = source
				}
				s.Pipe.IngestEvent(ev)
				n++
			} else {
				var batch []event.Event
				if json.Unmarshal(body, &batch) == nil {
					for _, ev := range batch {
						if ev.Source == "" {
							ev.Source = source
						}
						s.Pipe.IngestEvent(ev)
						n++
					}
				}
			}
		}
	} else {
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			s.Pipe.IngestLine(line, source)
			n++
		}
	}
	writeJSON(w, map[string]any{"ingested": n})
}

func (s *Server) reportVectors(w http.ResponseWriter, r *http.Request) {
	since, source := reportQuery(r)
	rep, err := s.Store.VectorReport(since, source)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, rep)
}

func (s *Server) reportAuth(w http.ResponseWriter, r *http.Request) {
	since, source := reportQuery(r)
	ch := r.URL.Query().Get("channel")
	if ch == "" {
		ch = "web"
	}
	rep, err := s.Store.AuthReport(ch, since, source)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if s.Pipe.Geo != nil {
		for i := range rep.TopIPs {
			if rep.TopIPs[i].Country != "" {
				continue
			}
			loc := s.Pipe.Geo.Lookup(rep.TopIPs[i].SrcIP)
			if loc.Ok {
				if loc.Name != "" {
					rep.TopIPs[i].Country = loc.Name
				} else {
					rep.TopIPs[i].Country = loc.Country
				}
			}
		}
	}
	writeJSON(w, rep)
}

func (s *Server) intelIP(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	since := time.Now().Add(-24 * time.Hour)
	if v := r.URL.Query().Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			since = time.Now().Add(-d)
		}
	}
	rep, err := s.Store.IPIntel(ip, since)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if intel.Enabled() && !rep.Private && net.ParseIP(ip) != nil {
		if rep.Research == "local" || rep.Research == "stale" || rep.Research == "" {
			s.Store.EnqueueIntel(ip, 3, "ui")
			rep.Queued = true
			rep.Research = "queued"
		}
	} else if !intel.Enabled() && (rep.Research == "local" || rep.Research == "") {
		rep.Research = "off"
	}
	writeJSON(w, rep)
}

func (s *Server) exportAlerts(w http.ResponseWriter, r *http.Request) {
	since, source := reportQuery(r)
	rows, err := s.Store.ExportAlerts(since, source, 5000)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	name := exportFile("alerts", since, source, r.URL.Query().Get("format"))
	writeExport(w, r.URL.Query().Get("format"), name, map[string]any{
		"exported_at": time.Now().UTC(),
		"since":       since.UTC(),
		"until":       time.Now().UTC(),
		"source":      source,
		"count":       len(rows),
		"truncated":   len(rows) >= 5000,
		"alerts":      rows,
	}, func(cw *csv.Writer) {
		_ = cw.Write([]string{"num", "time", "severity", "category", "title", "src_ip", "country", "country_name", "method", "url", "status", "rule_id", "source", "mitre", "evidence"})
		for _, a := range rows {
			_ = cw.Write([]string{
				strconv.FormatInt(a.Num, 10), a.Time.UTC().Format(time.RFC3339), a.Severity, a.Category, a.Title,
				a.SrcIP, a.Country, a.CountryName, a.Method, a.URL, strconv.Itoa(a.Status), a.RuleID, a.Source,
				strings.Join(a.MITRE, " "), a.Evidence,
			})
		}
	})
}

func (s *Server) exportEvents(w http.ResponseWriter, r *http.Request) {
	since, source := reportQuery(r)
	ch := r.URL.Query().Get("channel")
	kindFilter := authFilter(ch)
	rows, err := s.Store.ExportEvents(since, source, kindFilter, 5000)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	name := exportFile("events-"+sanitizeFile(ch), since, source, r.URL.Query().Get("format"))
	writeExport(w, r.URL.Query().Get("format"), name, map[string]any{
		"exported_at": time.Now().UTC(),
		"since":       since.UTC(),
		"until":       time.Now().UTC(),
		"source":      source,
		"channel":     ch,
		"count":       len(rows),
		"truncated":   len(rows) >= 5000,
		"events":      rows,
	}, func(cw *csv.Writer) {
		_ = cw.Write([]string{"time", "kind", "outcome", "src_ip", "user", "method", "path", "url", "status", "source", "reason", "host"})
		for _, e := range rows {
			_ = cw.Write([]string{
				e.Time.UTC().Format(time.RFC3339), e.Kind, e.Outcome, e.SrcIP, e.User, e.Method, e.Path, e.URL,
				strconv.Itoa(e.Status), e.Source, e.Reason, e.Host,
			})
		}
	})
}

func authFilter(channel string) string {
	kind, fail := "", ""
	switch strings.ToLower(channel) {
	case "linux", "hostauth", "ssh":
		kind, fail = "kind = 'hostauth'", "(outcome = 'fail' OR status IN (401,403))"
	case "app", "applogin", "platform":
		kind, fail = "kind = 'applogin'", "(outcome = 'fail' OR status IN (401,403))"
	case "tenant", "tenantlogin", "owner", "ownerlogin":
		kind, fail = "kind = 'tenantlogin'", "(outcome = 'fail' OR status IN (401,403))"
	case "probes", "secprobe", "sec":
		return "kind = 'secprobe'"
	default:
		kind = "(IFNULL(kind,'') IN ('','web'))"
		fail = `(status IN (401,403) OR lower(path) LIKE '%login%' OR lower(path) LIKE '%signin%'
			  OR lower(path) LIKE '%sign-in%' OR lower(path) LIKE '%/auth%'
			  OR lower(path) LIKE '%wp-login%' OR lower(path) LIKE '%session%')`
	}
	return kind + " AND (" + fail + ")"
}

func exportFile(kind string, since time.Time, source, format string) string {
	if format != "json" {
		format = "csv"
	}
	win := "24h"
	d := time.Since(since)
	switch {
	case d <= 90*time.Minute:
		win = "1h"
	case d <= 30*time.Hour:
		win = "24h"
	default:
		win = "7d"
	}
	src := sanitizeFile(source)
	if src != "" {
		src = "-" + src
	}
	return "gwd-" + sanitizeFile(kind) + "-" + win + src + "." + format
}

func sanitizeFile(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func writeExport(w http.ResponseWriter, format, name string, payload any, csvFn func(*csv.Writer)) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(payload)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	cw := csv.NewWriter(w)
	csvFn(cw)
	cw.Flush()
}

func reportQuery(r *http.Request) (time.Time, string) {
	since := time.Now().Add(-24 * time.Hour)
	if v := r.URL.Query().Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			since = time.Now().Add(-d)
		}
	}
	return since, r.URL.Query().Get("source")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
