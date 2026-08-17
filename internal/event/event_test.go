package event

import "testing"

func TestQuietStatic(t *testing.T) {
	ok := Event{Kind: KindWeb, Status: 200, Path: "/assets/app.css"}
	if !QuietStatic(ok) {
		t.Fatal("css 200 should be quiet")
	}
	bad := Event{Kind: KindWeb, Status: 200, Path: "/assets/../.env"}
	if QuietStatic(bad) {
		t.Fatal("traversal must not be quiet")
	}
	fail := Event{Kind: KindWeb, Status: 404, Path: "/app.js"}
	if QuietStatic(fail) {
		t.Fatal("404 is not quiet")
	}
	login := Event{Kind: KindAppLogin, Status: 200, Path: "/login.js"}
	if QuietStatic(login) {
		t.Fatal("non-web kinds are never quiet")
	}
	sm := Event{Kind: KindWeb, Status: 200, Path: "/assets/app.js.map"}
	if QuietStatic(sm) {
		t.Fatal("source maps must not be quiet")
	}
}

func TestNormalizeReasonNew(t *testing.T) {
	if NormalizeReason("cross_tenant") != "idor" {
		t.Fatal(NormalizeReason("cross_tenant"))
	}
	if NormalizeReason("2fa_bypass") != "stepup_bypass" {
		t.Fatal(NormalizeReason("2fa_bypass"))
	}
	if NormalizeReason("arcade_score_abuse") != "score_abuse" {
		t.Fatal(NormalizeReason("arcade_score_abuse"))
	}
	if NormalizeReason("public_429") != "rate_limit" {
		t.Fatal(NormalizeReason("public_429"))
	}
}
