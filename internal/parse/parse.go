package parse

import (
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gpewebdefender/internal/event"
)

// Combined / common / NCSA-ish:
//   1.2.3.4 - user [10/Oct/2000:13:55:36 -0700] "GET /path?x=1 HTTP/1.1" 200 123 "ref" "ua"
// Optional vhost as the first field (tried second so it cannot steal the IP).
var combinedRe = regexp.MustCompile(`^(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) ([^"]*) (\S+)" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?`)

const nginxTime = "02/Jan/2006:15:04:05 -0700"

// Parse turns one log line into a normalized Event.
// Tries JSON first (nginx/caddy/traefik json), then combined.
func Parse(line, source string) (event.Event, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return event.Event{}, false
	}
	if line[0] == '{' {
		if ev, ok := parseJSON(line, source); ok {
			return ev, true
		}
	}
	if ev, ok := parseCombined(line, source); ok {
		if ev.Kind == "" {
			ev.Kind = event.KindWeb
		}
		return ev, true
	}
	return parseAuth(line, source)
}

func parseCombined(line, source string) (event.Event, bool) {
	if ev, ok := matchCombined(line, source, ""); ok {
		return ev, true
	}
	// vhost_combined: host ip - user [time] "req" status bytes ...
	if i := strings.IndexByte(line, ' '); i > 0 {
		host, rest := line[:i], strings.TrimSpace(line[i+1:])
		if ev, ok := matchCombined(rest, source, host); ok {
			return ev, true
		}
	}
	return event.Event{}, false
}

func matchCombined(line, source, host string) (event.Event, bool) {
	m := combinedRe.FindStringSubmatch(line)
	if m == nil {
		return event.Event{}, false
	}
	ip := stripHostPort(m[1])
	if ip == "" || ip == "-" {
		return event.Event{}, false
	}
	user := m[3]
	if user == "-" {
		user = ""
	}
	status, _ := strconv.Atoi(m[8])
	var bytes int64
	if m[9] != "-" && m[9] != "" {
		bytes, _ = strconv.ParseInt(m[9], 10, 64)
	}
	ts, err := time.Parse(nginxTime, m[4])
	if err != nil {
		ts = time.Now().UTC()
	} else {
		ts = ts.UTC()
	}
	rawURL := m[6]
	path, query := splitURL(rawURL)
	ua, ref := "", ""
	if len(m) > 11 {
		ref = dashEmpty(m[10])
		ua = m[11]
	}
	ev := event.Event{
		Time:     ts,
		SrcIP:    ip,
		Method:   strings.ToUpper(m[5]),
		URL:      rawURL,
		Path:     path,
		Query:    query,
		Decoded:  DecodeForMatch(path, query),
		Status:   status,
		Bytes:    bytes,
		UA:       ua,
		Referer:  ref,
		Host:     host,
		User:     user,
		Protocol: m[7],
		Source:   source,
		Raw:      line,
	}
	return ev, true
}

type jsonLine map[string]any

func parseJSON(line, source string) (event.Event, bool) {
	var raw jsonLine
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return event.Event{}, false
	}
	// Caddy wraps request fields.
	if req, ok := raw["request"].(map[string]any); ok {
		for k, v := range req {
			if _, exists := raw[k]; !exists {
				raw[k] = v
			}
		}
		if headers, ok := req["headers"].(map[string]any); ok {
			if ua := firstHeader(headers, "User-Agent", "user-agent"); ua != "" {
				raw["user_agent"] = ua
			}
			if ref := firstHeader(headers, "Referer", "referer"); ref != "" {
				raw["referer"] = ref
			}
		}
		if remote, ok := req["remote_ip"].(string); ok && rawString(raw, "remote_ip", "ip") == "" {
			raw["remote_ip"] = remote
		}
	}

	ip := stripHostPort(firstString(raw,
		"remote_addr", "remote_ip", "client_ip", "src_ip", "ip",
		"ClientHost", "clientip",
	))
	kindHint := strings.ToLower(firstString(raw, "kind", "channel"))
	if ip == "" && kindHint != event.KindAppLogin && kindHint != event.KindHostAuth &&
		kindHint != "app" && kindHint != "linux" && kindHint != "ssh" {
		return event.Event{}, false
	}
	rawURL := firstString(raw, "request_uri", "uri", "url", "path", "request")
	method := firstString(raw, "request_method", "method")
	// Some formats put "GET /x HTTP/1.1" in request.
	if method == "" && strings.Contains(rawURL, " ") {
		parts := strings.Fields(rawURL)
		if len(parts) >= 2 {
			method = parts[0]
			rawURL = parts[1]
		}
	}
	if method == "" {
		method = "GET"
	}
	path, query := splitURL(rawURL)
	if path == "" {
		path = firstString(raw, "path", "uri")
	}
	status := firstInt(raw, "status", "status_code", "statusCode")
	bytes := firstInt64(raw, "body_bytes_sent", "bytes_sent", "size", "bytes")
	ua := firstString(raw, "http_user_agent", "user_agent", "userAgent", "ua")
	ref := firstString(raw, "http_referer", "referer", "referrer")
	host := firstString(raw, "host", "http_host", "hostname")
	ts := firstTime(raw, "time_iso8601", "timestamp", "ts", "time", "@timestamp")
	kind := strings.ToLower(firstString(raw, "kind", "channel"))
	outcome := strings.ToLower(firstString(raw, "outcome", "result"))
	user := firstString(raw, "user", "username", "account")
	role := firstString(raw, "role", "audience", "scope", "actor")
	kind = event.NormalizeKind(kind, role)
	if kind == event.KindAppLogin || kind == event.KindTenantLogin {
		if method == "" || method == "GET" && firstString(raw, "request_method") == "" {
			method = "LOGIN"
		}
		if outcome == "failure" || outcome == "failed" || outcome == "error" {
			outcome = event.OutcomeFail
		}
		if outcome == "success" || outcome == "ok" || outcome == "allow" {
			outcome = event.OutcomeOK
		}
		if outcome == event.OutcomeFail && status == 0 {
			status = 401
		}
		if outcome == event.OutcomeOK && status == 0 {
			status = 200
		}
		if path == "" {
			path = "/login"
		}
		if rawURL == "" {
			rawURL = path
		}
	}
	if kind == "" {
		kind = event.KindWeb
	}

	ev := event.Event{
		Time:     ts,
		SrcIP:    ip,
		Method:   strings.ToUpper(method),
		URL:      rawURL,
		Path:     path,
		Query:    query,
		Decoded:  DecodeForMatch(path, query),
		Status:   status,
		Bytes:    bytes,
		UA:       ua,
		Referer:  ref,
		Host:     host,
		User:     user,
		Source:   source,
		Raw:      line,
		Kind:     kind,
		Outcome:  outcome,
		Role:     role,
	}
	ev.ApplyLoginDefaults()
	return ev, true
}

func firstHeader(headers map[string]any, names ...string) string {
	for _, n := range names {
		v, ok := headers[n]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			return t
		case []any:
			if len(t) > 0 {
				if s, ok := t[0].(string); ok {
					return s
				}
			}
		}
	}
	return ""
}

func firstString(m jsonLine, keys ...string) string {
	for _, k := range keys {
		if s := rawString(m, k); s != "" {
			return s
		}
	}
	return ""
}

func rawString(m jsonLine, keys ...string) string {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			if t != "" && t != "-" {
				return t
			}
		case float64:
			return strconv.FormatFloat(t, 'f', -1, 64)
		}
	}
	return ""
}

func firstInt(m jsonLine, keys ...string) int {
	return int(firstInt64(m, keys...))
}

func firstInt64(m jsonLine, keys ...string) int64 {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case float64:
			return int64(t)
		case string:
			if t == "" || t == "-" {
				continue
			}
			n, err := strconv.ParseInt(t, 10, 64)
			if err == nil {
				return n
			}
		}
	}
	return 0
}

func firstTime(m jsonLine, keys ...string) time.Time {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			if ts, ok := parseAnyTime(t); ok {
				return ts
			}
		case float64:
			// seconds or ms
			if t > 1e12 {
				return time.UnixMilli(int64(t)).UTC()
			}
			return time.Unix(int64(t), 0).UTC()
		}
	}
	return time.Now().UTC()
}

func parseAnyTime(s string) (time.Time, bool) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		nginxTime,
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05",
	}
	for _, l := range layouts {
		if ts, err := time.Parse(l, s); err == nil {
			return ts.UTC(), true
		}
	}
	return time.Time{}, false
}

func splitURL(raw string) (path, query string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/", ""
	}
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		return raw[:i], raw[i+1:]
	}
	return raw, ""
}

// DecodeForMatch url-decodes path+query up to twice so %252e%252e and %27or%271 are visible.
func DecodeForMatch(path, query string) string {
	joined := path
	if query != "" {
		joined = path + "?" + query
	}
	s := joined
	for i := 0; i < 2; i++ {
		// '+' in path is literal; in query it is space. Decode query-style.
		dec, err := url.QueryUnescape(s)
		if err != nil || dec == s {
			break
		}
		s = dec
	}
	return s
}

func stripHostPort(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `[]`)
	if s == "" || s == "-" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}

func dashEmpty(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
