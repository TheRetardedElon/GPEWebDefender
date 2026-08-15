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
}

func TestNormalizeReasonNew(t *testing.T) {
	if NormalizeReason("cross_tenant") != "idor" {
		t.Fatal(NormalizeReason("cross_tenant"))
	}
	if NormalizeReason("2fa_bypass") != "stepup_bypass" {
		t.Fatal(NormalizeReason("2fa_bypass"))
	}
}
