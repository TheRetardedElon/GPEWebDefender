package store

import (
	"path/filepath"
	"testing"
	"time"

	"gpewebdefender/internal/event"
)

func TestSourceFilterAndList(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.Now().UTC()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.InsertEvent(event.Event{ID: "e1", Time: now, SrcIP: "1.1.1.1", URL: "/a", Source: "edge"}))
	must(st.InsertEvent(event.Event{ID: "e2", Time: now, SrcIP: "2.2.2.2", URL: "/b", Source: "proxy"}))
	must(st.InsertAlert(&event.Alert{ID: "a1", Time: now, Title: "sqli", Severity: "high", Category: "sqli", SrcIP: "1.1.1.1", Source: "edge"}))
	must(st.InsertAlert(&event.Alert{ID: "a2", Time: now, Title: "xss", Severity: "medium", Category: "xss", SrcIP: "2.2.2.2", Source: "proxy"}))

	all, err := st.Alerts(AlertQuery{Limit: 10})
	if err != nil || len(all.Alerts) != 2 {
		t.Fatalf("all alerts: %d %v", len(all.Alerts), err)
	}
	if all.Alerts[0].Num == 0 || all.Alerts[1].Num == 0 {
		t.Fatalf("missing nums: %+v", all.Alerts)
	}
	edge, err := st.Alerts(AlertQuery{Source: "edge", Limit: 10})
	if err != nil || len(edge.Alerts) != 1 || edge.Alerts[0].Source != "edge" {
		t.Fatalf("edge: %+v %v", edge, err)
	}
	stats, err := st.Stats(1, "proxy")
	if err != nil || stats.Alerts1h != 1 || stats.Events1h != 1 {
		t.Fatalf("stats: %+v %v", stats, err)
	}
	srcs, err := st.Sources()
	if err != nil || len(srcs) != 2 {
		t.Fatalf("sources: %+v %v", srcs, err)
	}
	arcs, _, err := st.MapArcs(now.Add(-time.Hour), 10, "edge")
	if err != nil || len(arcs) != 1 || arcs[0].Source != "edge" {
		t.Fatalf("arcs: %+v %v", arcs, err)
	}
}

func TestReports(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	_ = st.InsertEvent(event.Event{ID: "e1", Time: now, SrcIP: "1.1.1.1", Path: "/api/login", URL: "/api/login", Status: 401, Kind: "web", Source: "edge"})
	_ = st.InsertEvent(event.Event{ID: "e2", Time: now, SrcIP: "9.9.9.9", Path: "sshd", URL: "failed password for root from 9.9.9.9", Status: 401, Kind: "hostauth", Outcome: "fail", User: "root", Method: "SSH", Source: "node"})
	_ = st.InsertEvent(event.Event{ID: "e3", Time: now, SrcIP: "8.8.8.8", Path: "/api/login", Status: 401, Kind: "applogin", Outcome: "fail", User: "alice", Method: "LOGIN", Source: "app"})
	_ = st.InsertAlert(&event.Alert{ID: "a1", Time: now, Title: "SQLi", Category: "sqli", Severity: "high", SrcIP: "1.1.1.1", URL: "/x?id=1", Source: "edge"})

	vec, err := st.VectorReport(now.Add(-time.Hour), "")
	if err != nil || vec.Alerts != 1 || len(vec.ByCategory) != 1 {
		t.Fatalf("vectors: %+v %v", vec, err)
	}
	web, err := st.AuthReport("web", now.Add(-time.Hour), "")
	if err != nil || web.Fails < 1 {
		t.Fatalf("web: %+v %v", web, err)
	}
	lin, err := st.AuthReport("linux", now.Add(-time.Hour), "")
	if err != nil || lin.Fails != 1 || lin.UniqueUsers != 1 {
		t.Fatalf("linux: %+v %v", lin, err)
	}
	app, err := st.AuthReport("app", now.Add(-time.Hour), "")
	if err != nil || app.Fails != 1 || len(app.ByUser) != 1 {
		t.Fatalf("app: %+v %v", app, err)
	}
}

func TestSettingsAndAlertNums(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	a1 := &event.Alert{ID: "n1", Time: now, Title: "one", SrcIP: "1.1.1.1"}
	a2 := &event.Alert{ID: "n2", Time: now, Title: "two", SrcIP: "1.1.1.1"}
	if err := st.InsertAlert(a1); err != nil || a1.Num != 1 {
		t.Fatalf("n1: %+v %v", a1, err)
	}
	if err := st.InsertAlert(a2); err != nil || a2.Num != 2 {
		t.Fatalf("n2: %+v %v", a2, err)
	}
	page, err := st.Alerts(AlertQuery{Q: "#2", Limit: 10})
	if err != nil || len(page.Alerts) != 1 || page.Alerts[0].Num != 2 {
		t.Fatalf("search #: %+v %v", page, err)
	}
	if err := st.PutSettings(event.Settings{SiteName: "lab", Home: "DE", Retain: "48h"}); err != nil {
		t.Fatal(err)
	}
	got, err := st.Settings()
	if err != nil || got.SiteName != "lab" || got.Home != "DE" || st.Retain() != 48*time.Hour {
		t.Fatalf("settings: %+v %v", got, err)
	}
}
