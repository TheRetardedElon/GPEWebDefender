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
}
