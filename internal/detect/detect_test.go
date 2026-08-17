package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gpewebdefender/internal/event"
	"gpewebdefender/internal/parse"
)

func loadWeb(t *testing.T) *Engine {
	t.Helper()
	// repo-relative: this file is internal/detect → ../../rules/web.yaml
	p := filepath.Join("..", "..", "rules")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("rules not found: %v", err)
	}
	e := New()
	if err := e.LoadDir(p); err != nil {
		t.Fatal(err)
	}
	if e.Len() < 10 {
		t.Fatalf("expected many rules, got %d", e.Len())
	}
	return e
}

func TestSecprobeReason(t *testing.T) {
	e := loadWeb(t)
	ev, ok := parse.Parse(`{"kind":"secprobe","src_ip":"203.0.113.9","reason":"canary_hit","path":"/.well-known/siem-canary"}`, "app")
	if !ok {
		t.Fatal("parse")
	}
	ev.ID = "s1"
	ev.Time = time.Now().UTC()
	got := e.Evaluate(ev)
	found := false
	for _, a := range got {
		if a.RuleID == "sec.canary.hit" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected sec.canary.hit, got %+v", got)
	}
	ev, ok = parse.Parse(`{"kind":"secprobe","src_ip":"203.0.113.9","reason":"arcade_score_abuse"}`, "app")
	if !ok {
		t.Fatal("parse score")
	}
	ev.ID = "s2"
	ev.Time = time.Now().UTC()
	got = e.Evaluate(ev)
	if !hasRule(got, "sec.score.abuse") {
		t.Fatalf("expected sec.score.abuse, got %+v", got)
	}
}

func hit(t *testing.T, e *Engine, line string) []event.Alert {
	t.Helper()
	ev, ok := parse.Parse(line, "t")
	if !ok {
		t.Fatalf("parse: %s", line)
	}
	ev.ID = "e1"
	ev.Time = time.Now().UTC()
	return e.Evaluate(ev)
}

func hasRule(alerts []event.Alert, id string) bool {
	for _, a := range alerts {
		if a.RuleID == id {
			return true
		}
	}
	return false
}

func TestSSHRootCarriesStory(t *testing.T) {
	e := loadWeb(t)
	ev, ok := parse.Parse(`Aug 16 00:18:01 box sshd[11]: Failed password for root from 203.0.113.9 port 22 ssh2`, "devbox")
	if !ok {
		t.Fatal("parse")
	}
	ev.ID = "ssh1"
	ev.Time = time.Now().UTC()
	got := e.Evaluate(ev)
	var hit event.Alert
	for _, a := range got {
		if a.RuleID == "linux.ssh.root" {
			hit = a
		}
	}
	if hit.RuleID == "" {
		t.Fatalf("expected linux.ssh.root, got %+v", got)
	}
	if hit.Kind != event.KindHostAuth || hit.User != "root" || hit.Outcome != event.OutcomeFail || hit.Source != "devbox" {
		t.Fatalf("story: %+v", hit)
	}
}

func TestSQLi(t *testing.T) {
	e := loadWeb(t)
	line := `1.1.1.1 - - [14/Aug/2026:12:00:01 +0000] "GET /x?id=1%20UNION%20SELECT%20password HTTP/1.1" 200 1 "-" "Mozilla"`
	al := hit(t, e, line)
	if !hasRule(al, "web.sqli.union") {
		t.Fatalf("missed sqli: %+v", al)
	}
}

func TestTraversal(t *testing.T) {
	e := loadWeb(t)
	line := `1.1.1.1 - - [14/Aug/2026:12:00:01 +0000] "GET /static/../../etc/passwd HTTP/1.1" 403 1 "-" "Mozilla"`
	al := hit(t, e, line)
	if !hasRule(al, "web.traversal") {
		t.Fatalf("missed traversal: %+v", al)
	}
}

func TestEnvProbe(t *testing.T) {
	e := loadWeb(t)
	line := `1.1.1.1 - - [14/Aug/2026:12:00:01 +0000] "GET /.env HTTP/1.1" 404 1 "-" "Mozilla"`
	al := hit(t, e, line)
	if !hasRule(al, "web.recon.env") {
		t.Fatalf("missed .env: %+v", al)
	}
}

func TestSecretServedAndLoopbackSkip(t *testing.T) {
	e := loadWeb(t)
	leak := `203.0.113.9 - - [14/Aug/2026:12:00:01 +0000] "GET /.env HTTP/1.1" 200 80 "-" "curl/8"`
	al := hit(t, e, leak)
	if !hasRule(al, "web.secret.served") {
		t.Fatalf("missed leak: %+v", al)
	}
	cfg := `198.51.100.4 - - [14/Aug/2026:12:00:01 +0000] "GET /wp-config.php HTTP/1.1" 404 1 "-" "Mozilla"`
	al = hit(t, e, cfg)
	if !hasRule(al, "web.recon.env") {
		t.Fatalf("missed wp-config probe: %+v", al)
	}
	local := `127.0.0.1 - - [14/Aug/2026:12:00:01 +0000] "GET /.env HTTP/1.1" 200 80 "-" "curl/8"`
	al = hit(t, e, local)
	if hasRule(al, "web.secret.served") || hasRule(al, "web.recon.env") {
		t.Fatalf("loopback should be quiet: %+v", al)
	}
}

func TestScannerUA(t *testing.T) {
	e := loadWeb(t)
	line := `1.1.1.1 - - [14/Aug/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 1 "-" "sqlmap/1.8.2"`
	al := hit(t, e, line)
	if !hasRule(al, "web.scanner.ua") {
		t.Fatalf("missed scanner: %+v", al)
	}
}

func TestCleanRequestSilent(t *testing.T) {
	e := loadWeb(t)
	line := `1.1.1.1 - - [14/Aug/2026:12:00:01 +0000] "GET /menu?id=42 HTTP/1.1" 200 800 "https://example.com/" "Mozilla/5.0"`
	al := hit(t, e, line)
	if len(al) != 0 {
		t.Fatalf("false positive: %+v", al)
	}
}

func Test404Storm(t *testing.T) {
	e := loadWeb(t)
	now := time.Now().UTC()
	var last []event.Alert
	for i := 0; i < 25; i++ {
		ev := event.Event{
			ID:     "e",
			Time:   now.Add(time.Duration(i) * time.Millisecond),
			SrcIP:  "9.9.9.9",
			Method: "GET",
			Path:   "/nope",
			URL:    "/nope",
			Status: 404,
		}
		last = e.Evaluate(ev)
	}
	if !hasRule(last, "web.scan.404storm") {
		t.Fatalf("expected 404 storm, last=%+v", last)
	}
}

func TestHumanSnoop404(t *testing.T) {
	e := loadWeb(t)
	now := time.Now().UTC()
	paths := []string{"/admin", "/admin/login", "/.env", "/.env.local", "/swagger.json"}
	var last []event.Alert
	for i, p := range paths {
		ev := event.Event{
			ID:      "e",
			Time:    now.Add(time.Duration(i) * 2 * time.Second),
			SrcIP:   "8.8.8.8",
			Method:  "GET",
			Path:    p,
			URL:     p,
			Decoded: p,
			Status:  404,
			UA:      "Mozilla/5.0",
		}
		last = e.Evaluate(ev)
	}
	if !hasRule(last, "web.snoop.slow404") && !hasRule(last, "web.snoop.secret_hunt") {
		t.Fatalf("expected human snoop, last=%+v", last)
	}
}

func TestFast404IsNotHumanSnoop(t *testing.T) {
	e := loadWeb(t)
	now := time.Now().UTC()
	for i := 0; i < 8; i++ {
		ev := event.Event{
			ID:     "e",
			Time:   now.Add(time.Duration(i) * 20 * time.Millisecond),
			SrcIP:  "7.7.7.7",
			Method: "GET",
			Path:   fmt.Sprintf("/nope-%d", i),
			URL:    "/nope",
			Status: 404,
		}
		al := e.Evaluate(ev)
		if hasRule(al, "web.snoop.slow404") {
			t.Fatalf("fast bust should not look human: %+v", al)
		}
	}
}

func TestCanaryPath(t *testing.T) {
	e := loadWeb(t)
	line := `1.1.1.1 - - [14/Aug/2026:12:00:01 +0000] "GET /super-admin-backup-2026/ HTTP/1.1" 404 1 "-" "Mozilla"`
	al := hit(t, e, line)
	if !hasRule(al, "web.canary.robots_trap") {
		t.Fatalf("missed canary: %+v", al)
	}
	al = hit(t, e, `1.1.1.1 - - [14/Aug/2026:12:00:01 +0000] "GET /api/public/__siem-canary__ HTTP/1.1" 404 1 "-" "Mozilla"`)
	if !hasRule(al, "web.canary.well_known") {
		t.Fatalf("missed public canary: %+v", al)
	}
}

func TestDevServerLeak(t *testing.T) {
	e := loadWeb(t)
	al := hit(t, e, `1.1.1.1 - - [17/Aug/2026:12:00:01 +0000] "GET /@vite/client HTTP/1.1" 200 80 "-" "Mozilla"`)
	if !hasRule(al, "web.recon.devserver") || !hasRule(al, "web.secret.dev_served") {
		t.Fatalf("vite 200: %+v", al)
	}
	al = hit(t, e, `1.1.1.1 - - [17/Aug/2026:12:00:01 +0000] "GET /assets/app.js.map HTTP/1.1" 200 80 "-" "Mozilla"`)
	if !hasRule(al, "web.secret.map_served") {
		t.Fatalf("map 200: %+v", al)
	}
}
