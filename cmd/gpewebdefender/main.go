package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gpewebdefender/internal/detect"
	"gpewebdefender/internal/demo"
	"gpewebdefender/internal/geo"
	"gpewebdefender/internal/hub"
	"gpewebdefender/internal/pipeline"
	"gpewebdefender/internal/server"
	"gpewebdefender/internal/store"
	"gpewebdefender/internal/tail"
	"gpewebdefender/rules"
)

const version = "0.6.0"

func main() {
	log.SetFlags(0)
	log.SetPrefix("gpewebdefender: ")
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		serveCmd(os.Args[2:])
	case "demo":
		demoCmd(os.Args[2:])
	case "agent":
		agentCmd(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("gpewebdefender", version)
	case "help", "-h", "--help":
		usage()
	default:
		log.Printf("unknown command %q", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `gpewebdefender %s — web-attack monitor

  gpewebdefender serve   start the monitor (tail logs + UI)
  gpewebdefender demo    run a live simulated attack feed
  gpewebdefender agent   ship access logs from another host
  gpewebdefender version

Examples
  gpewebdefender serve --tail C:\logs\access.log --listen :8787
  gpewebdefender serve --tail /var/log/nginx/access.log
  gpewebdefender demo
  gpewebdefender agent --url http://siem:8787 --token SECRET --tail /var/log/nginx/access.log
`, version)
}

func serveCmd(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8787", "UI and API bind address")
	dbPath := fs.String("db", "gpewebdefender.db", "sqlite path")
	rulesDir := fs.String("rules", "", "extra rules dir or file (built-in rules always load)")
	tailPath := fs.String("tail", "", "access log to follow (repeat not needed; comma-separate)")
	journal := fs.Bool("journal", false, "follow systemd journal for sshd/sudo/login (when there is no auth.log)")
	fromStart := fs.Bool("from-start", false, "read existing log lines, not only new ones")
	token := fs.String("token", "", "shared secret for /api (also sent as Bearer)")
	retain := fs.Duration("retain", 168*time.Hour, "how long to keep raw events")
	home := fs.String("home", "US", "map home: ISO country (US, DE) or lat,lon")
	homes := fs.String("homes", "", "extra map pins: name=lat,lon;name=ISO (name matches agent --name)")
	geoip := fs.String("geoip", "", "optional MaxMind/DB-IP .mmdb for real client IPs")
	docsDir := fs.String("docs", "", "DocHub directory served at /docs/ (default: ./dochub if present)")
	_ = fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pipe, err := newPipeline(*dbPath, *rulesDir, *home, *homes, *geoip)
	if err != nil {
		log.Fatal(err)
	}
	defer pipe.Store.Close()
	seedAndApplySettings(pipe, *home, *homes, *retain)
	bootstrapAdmin(pipe.Store)

	go pruneLoop(ctx, pipe.Store)

	for _, p := range splitCSV(*tailPath) {
		p := p
		go func() {
			log.Printf("tailing %s", p)
			err := tail.Follow(ctx, p, *fromStart, func(line string) {
				pipe.IngestLine(line, filepath.Base(p))
			})
			if err != nil && ctx.Err() == nil {
				log.Printf("tail %s: %v", p, err)
			}
		}()
	}
	if *journal {
		go func() {
			log.Printf("following systemd journal (sshd/sudo)")
			err := tail.FollowJournal(ctx, *fromStart, func(line string) {
				pipe.IngestLine(line, "journal")
			})
			if err != nil && ctx.Err() == nil {
				log.Printf("journal: %v", err)
			}
		}()
	}

	docs := resolveDocs(*docsDir)
	srv := &server.Server{Pipe: pipe, Store: pipe.Store, Hub: pipe.Hub, Token: *token, DocsDir: docs}
	httpSrv := &http.Server{Addr: *listen, Handler: srv.Handler()}
	go func() {
		if docs != "" {
			log.Printf("live monitor on http://%s  (%d rules)  docs /docs/  (no simulated feed)", *listen, pipe.Engine.Len())
		} else {
			log.Printf("live monitor on http://%s  (%d rules)  (no simulated feed)", *listen, pipe.Engine.Len())
		}
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	<-ctx.Done()
	shctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shctx)
}

func demoCmd(args []string) {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8787", "UI bind address")
	dbPath := fs.String("db", "gpewebdefender-demo.db", "sqlite path")
	every := fs.Duration("every", 900*time.Millisecond, "interval between simulated requests")
	home := fs.String("home", "US", "map home: ISO country (US, DE) or lat,lon")
	_ = fs.Parse(args)
	if liveDBName(filepath.Base(*dbPath)) {
		log.Fatal("demo will not open a live database name; omit --db or use a *-demo.db file")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pipe, err := newPipeline(*dbPath, "", *home, "", "")
	if err != nil {
		log.Fatal(err)
	}
	defer pipe.Store.Close()
	if pipe.Geo != nil {
		pipe.Geo.EnableDemoPins()
	}

	go demo.Run(ctx, *every, func(line string) {
		pipe.IngestLine(line, "demo")
	})

	srv := &server.Server{Pipe: pipe, Store: pipe.Store, Hub: pipe.Hub, DocsDir: resolveDocs("")}
	httpSrv := &http.Server{Addr: *listen, Handler: srv.Handler()}
	go func() {
		log.Printf("DEMO mode — simulated web attacks on http://%s", *listen)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	<-ctx.Done()
	shctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shctx)
}

func agentCmd(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	url := fs.String("url", "", "manager URL (http://host:8787)")
	token := fs.String("token", "", "shared secret")
	tailPath := fs.String("tail", "", "access log to follow (comma-separated)")
	journal := fs.Bool("journal", false, "follow systemd journal for sshd/sudo/login")
	fromStart := fs.Bool("from-start", false, "ship existing lines too")
	name := fs.String("name", hostname(), "source name")
	_ = fs.Parse(args)
	if *url == "" || (*tailPath == "" && !*journal) {
		log.Fatal("agent requires --url and --tail and/or --journal")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ch := make(chan string, 256)
	for _, p := range splitCSV(*tailPath) {
		p := p
		go func() {
			_ = tail.Follow(ctx, p, *fromStart, func(line string) {
				select {
				case ch <- line:
				default:
					log.Printf("buffer full, dropping line from %s", p)
				}
			})
		}()
	}
	if *journal {
		go func() {
			log.Printf("following systemd journal (sshd/sudo)")
			err := tail.FollowJournal(ctx, *fromStart, func(line string) {
				select {
				case ch <- line:
				default:
					log.Printf("buffer full, dropping journal line")
				}
			})
			if err != nil && ctx.Err() == nil {
				log.Printf("journal: %v", err)
			}
		}()
	}

	client := &http.Client{Timeout: 10 * time.Second}
	endpoint := strings.TrimRight(*url, "/") + "/api/ingest"
	log.Printf("shipping to %s as %s", endpoint, *name)

	var batch []string
	flush := func() {
		if len(batch) == 0 {
			return
		}
		body := strings.Join(batch, "\n")
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("X-SIEM-Source", *name)
		if *token != "" {
			req.Header.Set("Authorization", "Bearer "+*token)
		}
		res, err := client.Do(req)
		if err != nil {
			log.Printf("ingest: %v", err)
			return
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode >= 300 {
			log.Printf("ingest status %s", res.Status)
			return
		}
		batch = batch[:0]
	}

	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case line := <-ch:
			batch = append(batch, line)
			if len(batch) >= 50 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func newPipeline(dbPath, extraRules, home, homes, geoip string) (*pipeline.Pipeline, error) {
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}
	eng := detect.New()
	if err := loadBuiltin(eng); err != nil {
		st.Close()
		return nil, err
	}
	if extraRules != "" {
		rs, err := extraFrom(extraRules)
		if err != nil {
			log.Printf("extra rules %s: %v (continuing with built-in)", extraRules, err)
		} else {
			eng.AddRules(rs)
		}
	}
	g := geo.New()
	if err := g.SetHome(home); err != nil {
		log.Printf("home %q: %v (using US)", home, err)
	}
	if homes != "" {
		if err := g.SetHomes(homes); err != nil {
			log.Printf("homes %q: %v (named pins ignored)", homes, err)
		} else {
			log.Printf("map homes: %d named pin(s)", len(g.NamedHomes()))
		}
	}
	if geoip == "" {
		geoip = resolveGeoIP()
	}
	if geoip != "" {
		if err := g.OpenMMDB(geoip); err != nil {
			log.Printf("geoip %s: %v (map will use built-in pins only)", geoip, err)
		} else {
			log.Printf("geoip loaded %s", geoip)
		}
	}
	h := hub.New()
	return &pipeline.Pipeline{Store: st, Engine: eng, Hub: h, Geo: g}, nil
}

func extraFrom(path string) ([]detect.Rule, error) {
	tmp := detect.New()
	if err := tmp.LoadDir(path); err != nil {
		return nil, err
	}
	return tmp.Rules(), nil
}

func loadBuiltin(eng *detect.Engine) error {
	// Prefer on-disk rules next to the binary / cwd so you can edit them.
	candidates := []string{
		"rules",
		filepath.Join(exeDir(), "rules"),
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			if err := eng.LoadDir(c); err == nil && eng.Len() > 0 {
				return nil
			}
		}
	}
	rs, err := detect.ParseRules(rules.WebYAML)
	if err != nil {
		return fmt.Errorf("builtin rules: %w", err)
	}
	if extra, err := detect.ParseRules(rules.AuthYAML); err == nil {
		rs = append(rs, extra...)
	}
	return eng.SetRules(rs)
}

func seedAndApplySettings(pipe *pipeline.Pipeline, home, homes string, retain time.Duration) {
	cur, err := pipe.Store.Settings()
	if err != nil {
		log.Printf("settings: %v", err)
		return
	}
	if cur.Home == "" {
		cur.Home = home
	}
	if cur.Homes == "" {
		cur.Homes = homes
	}
	if cur.Retain == "" {
		cur.Retain = fmt.Sprintf("%dh", int(retain.Hours()))
	}
	if err := pipe.Store.PutSettings(cur); err != nil {
		log.Printf("settings save: %v", err)
	}
	if pipe.Geo != nil {
		if cur.Home != "" {
			_ = pipe.Geo.SetHome(cur.Home)
		}
		_ = pipe.Geo.SetHomes(cur.Homes)
	}
}

func bootstrapAdmin(st *store.Store) {
	user := strings.TrimSpace(os.Getenv("SIEM_ADMIN_USER"))
	pass := os.Getenv("SIEM_ADMIN_PASSWORD")
	if user == "" && pass == "" {
		if st.UserCount() == 0 {
			log.Print("no operator accounts yet — open /login to create the first admin")
		}
		return
	}
	if user == "" || pass == "" {
		log.Fatal("SIEM_ADMIN_USER and SIEM_ADMIN_PASSWORD must be set together")
	}
	if st.UserCount() > 0 {
		log.Print("operator accounts already exist — remove SIEM_ADMIN_PASSWORD from the env file")
		return
	}
	if _, err := st.CreateUser(user, pass, "admin"); err != nil {
		log.Fatalf("bootstrap admin: %v", err)
	}
	log.Print("created first admin from SIEM_ADMIN_USER — remove SIEM_ADMIN_PASSWORD from the env file now")
}

func pruneLoop(ctx context.Context, st *store.Store) {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for {
		if err := st.Prune(st.Retain()); err != nil {
			log.Printf("prune: %v", err)
		}
		st.SweepSessions()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func liveDBName(base string) bool {
	switch strings.ToLower(base) {
	case "gpe-siem.db", "gpewebdefender.db":
		return true
	default:
		return false
	}
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func resolveGeoIP() string {
	for _, c := range []string{
		"geoip.mmdb",
		"GeoLite2-Country.mmdb",
		"dbip-country-lite.mmdb",
		filepath.Join(exeDir(), "geoip.mmdb"),
		"/var/lib/gpewebdefender/geoip.mmdb",
	} {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

func resolveDocs(explicit string) string {
	if explicit != "" {
		if _, err := os.Stat(filepath.Join(explicit, "index.html")); err == nil {
			return explicit
		}
		log.Printf("docs %s: no index.html (docs disabled)", explicit)
		return ""
	}
	for _, c := range []string{"dochub", filepath.Join(exeDir(), "dochub")} {
		if _, err := os.Stat(filepath.Join(c, "index.html")); err == nil {
			return c
		}
	}
	return ""
}

func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(p)
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		b := make([]byte, 3)
		_, _ = rand.Read(b)
		return "agent-" + hex.EncodeToString(b)
	}
	return h
}
