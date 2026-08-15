package parse

import (
	"testing"
)

func TestParseCombined(t *testing.T) {
	line := `203.0.113.9 - - [14/Aug/2026:12:00:01 +0000] "GET /api/users?id=1%20UNION%20SELECT%20password HTTP/1.1" 200 512 "https://example.com/" "sqlmap/1.8"`
	ev, ok := Parse(line, "test")
	if !ok {
		t.Fatal("parse failed")
	}
	if ev.SrcIP != "203.0.113.9" {
		t.Fatalf("ip=%q", ev.SrcIP)
	}
	if ev.Method != "GET" {
		t.Fatalf("method=%q", ev.Method)
	}
	if ev.Status != 200 {
		t.Fatalf("status=%d", ev.Status)
	}
	if ev.Path != "/api/users" {
		t.Fatalf("path=%q", ev.Path)
	}
	if ev.UA != "sqlmap/1.8" {
		t.Fatalf("ua=%q", ev.UA)
	}
	if ev.Decoded == "" || ev.Decoded == ev.URL {
		// decoded should expand %20
		if !contains(ev.Decoded, "UNION SELECT") {
			t.Fatalf("decoded=%q", ev.Decoded)
		}
	}
}

func TestParseJSON(t *testing.T) {
	line := `{"remote_addr":"198.51.100.4","request_method":"GET","request_uri":"/../../../etc/passwd","status":403,"body_bytes_sent":18,"http_user_agent":"Mozilla/5.0","time_iso8601":"2026-08-14T12:00:00Z"}`
	ev, ok := Parse(line, "nginx.json")
	if !ok {
		t.Fatal("json parse failed")
	}
	if ev.SrcIP != "198.51.100.4" || ev.Status != 403 {
		t.Fatalf("%+v", ev)
	}
	if ev.Path != "/../../../etc/passwd" {
		t.Fatalf("path=%q", ev.Path)
	}
}

func TestDecodeDouble(t *testing.T) {
	got := DecodeForMatch("/%252e%252e/etc/passwd", "")
	if !contains(got, "..") {
		t.Fatalf("got %q", got)
	}
}

func TestParseAuthSSH(t *testing.T) {
	line := `Aug 15 01:40:03 box sshd[11]: Failed password for root from 185.220.101.47 port 22 ssh2`
	ev, ok := Parse(line, "auth")
	if !ok {
		t.Fatal("auth parse failed")
	}
	if ev.Kind != "hostauth" || ev.Method != "SSH" || ev.User != "root" || ev.SrcIP != "185.220.101.47" || ev.Outcome != "fail" {
		t.Fatalf("%+v", ev)
	}
	okLine := `2026-08-15T01:40:03+00:00 box sshd-session[12]: Accepted publickey for deploy from 198.51.100.9 port 22 ssh2`
	ev, ok = Parse(okLine, "auth")
	if !ok || ev.Outcome != "ok" || ev.User != "deploy" || ev.Status != 200 {
		t.Fatalf("accepted: %+v ok=%v", ev, ok)
	}
}

func TestParseAppLoginJSON(t *testing.T) {
	line := `{"kind":"applogin","src_ip":"203.0.113.9","user":"alice","path":"/api/login","status":401,"outcome":"fail"}`
	ev, ok := Parse(line, "platform")
	if !ok || ev.Kind != "applogin" || ev.User != "alice" || ev.Method != "LOGIN" || ev.Outcome != "fail" {
		t.Fatalf("%+v ok=%v", ev, ok)
	}
}

func TestParseTenantLogin(t *testing.T) {
	line := `{"kind":"applogin","role":"tenant","src_ip":"198.51.100.8","user":"owner@site","path":"/owner/login","status":401,"outcome":"fail"}`
	ev, ok := Parse(line, "platform")
	if !ok || ev.Kind != "tenantlogin" || ev.Method != "LOGIN" || ev.User != "owner@site" {
		t.Fatalf("%+v ok=%v", ev, ok)
	}
	line = `{"kind":"ownerlogin","src_ip":"198.51.100.8","user":"bob","status":401}`
	ev, ok = Parse(line, "platform")
	if !ok || ev.Kind != "tenantlogin" {
		t.Fatalf("alias: %+v", ev)
	}
}

func TestParseSecprobe(t *testing.T) {
	line := `{"kind":"secprobe","src_ip":"203.0.113.9","reason":"canary_hit","path":"/.well-known/siem-canary","status":200}`
	ev, ok := Parse(line, "app")
	if !ok || ev.Kind != "secprobe" || ev.Reason != "canary_hit" || ev.Path != "/.well-known/siem-canary" {
		t.Fatalf("%+v ok=%v", ev, ok)
	}
	line = `{"kind":"secprobe","src_ip":"203.0.113.9","reason":"enum_burst","path":"/api/public/x"}`
	ev, ok = Parse(line, "app")
	if !ok || ev.Reason != "enum_burst" {
		t.Fatalf("reason: %+v", ev)
	}
	line = `{"kind":"secprobe","src_ip":"203.0.113.9","reason":"feature_deny"}`
	ev, ok = Parse(line, "app")
	if !ok || ev.Reason != "app_deny" {
		t.Fatalf("app deny alias: %+v", ev)
	}
}

func TestSkipBlank(t *testing.T) {
	if _, ok := Parse("  ", "x"); ok {
		t.Fatal("blank should not parse")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		})())
}
