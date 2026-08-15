package server

import (
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"gpewebdefender/internal/event"
	"gpewebdefender/internal/hub"
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
	// Only the three embedded files — never walk the process cwd.
	switch p {
	case "index.html", "app.css", "app.js":
	default:
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
	}
	_, _ = w.Write(b)
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if s.Token == "" || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		// Health stays open so the box can be probed.
		if r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}
		got := r.Header.Get("Authorization")
		got = strings.TrimPrefix(got, "Bearer ")
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if got != s.Token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
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
	geoip := s.Pipe.Geo != nil && s.Pipe.Geo.HasMMDB()
	writeJSON(w, map[string]any{
		"ok":     true,
		"seen":   s.Pipe.Seen.Load(),
		"fired":  s.Pipe.Fired.Load(),
		"drop":   s.Pipe.Dropped.Load(),
		"rules":  s.Pipe.Engine.Len(),
		"geoip":  geoip,
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
	al, err := s.Store.Alerts(q.Get("q"), q.Get("severity"), q.Get("ip"), q.Get("source"), since, limit)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, al)
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
