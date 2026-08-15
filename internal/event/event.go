package event

import (
	"strings"
	"time"
)

// Event is one normalized HTTP (or HTTP-like) log line.
type Event struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	SrcIP     string    `json:"src_ip"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Path      string    `json:"path"`
	Query     string    `json:"query"`
	Decoded   string    `json:"decoded"` // path+query, url-decoded for matching
	Status    int       `json:"status"`
	Bytes     int64     `json:"bytes"`
	UA        string    `json:"ua"`
	Referer   string    `json:"referer"`
	Host      string    `json:"host"`
	User      string    `json:"user,omitempty"`
	Protocol  string    `json:"protocol,omitempty"`
	Source    string    `json:"source"`
	Raw       string    `json:"raw,omitempty"`
	Kind      string    `json:"kind,omitempty"`     // web | hostauth | applogin | tenantlogin | secprobe
	Outcome   string    `json:"outcome,omitempty"`  // fail | ok
	Role      string    `json:"role,omitempty"`     // tenant | owner | … (upgrades applogin)
	Reason    string    `json:"reason,omitempty"`   // canary_hit | path_probe | … (kind=secprobe)
}

const (
	KindWeb         = "web"
	KindHostAuth    = "hostauth"
	KindAppLogin    = "applogin"
	KindTenantLogin = "tenantlogin"
	KindSecProbe    = "secprobe"
	OutcomeFail     = "fail"
	OutcomeOK       = "ok"
)

// NormalizeKind maps shipper aliases onto the four kinds we store.
func NormalizeKind(kind, role string) string {
	k := strings.ToLower(strings.TrimSpace(kind))
	r := strings.ToLower(strings.TrimSpace(role))
	switch k {
	case KindTenantLogin, "ownerlogin", "tenant", "owner", "siteowner", "site-owner", "site_owner":
		return KindTenantLogin
	case KindSecProbe, "secevent", "securitywatch", "sec":
		return KindSecProbe
	case KindAppLogin, "app", "appauth", "login":
		k = KindAppLogin
	case KindHostAuth, "linux", "ssh", "auth":
		return KindHostAuth
	case KindWeb, "":
		k = KindWeb
	}
	switch r {
	case "tenant", "owner", "site-owner", "siteowner", "site_owner":
		return KindTenantLogin
	}
	return k
}

func (ev *Event) ApplyLoginDefaults() {
	if ev.Kind != KindAppLogin && ev.Kind != KindTenantLogin {
		return
	}
	if ev.Method == "" || ev.Method == "GET" {
		ev.Method = "LOGIN"
	}
	if ev.Outcome == "" {
		switch ev.Status {
		case 401, 403:
			ev.Outcome = OutcomeFail
		case 200, 201, 204, 302:
			ev.Outcome = OutcomeOK
		}
	}
	if ev.Path == "" {
		ev.Path = "/login"
	}
}

// NormalizeReason maps shipper aliases onto the public reason names.
func NormalizeReason(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "unknown":
		return ""
	case "canary_hit", "canary", "canary-hit":
		return "canary_hit"
	case "path_probe", "pathprobe", "path-probe":
		return "path_probe"
	case "sensitive_deny", "authz_deny", "authz-deny":
		return "sensitive_deny"
	case "webhook_reject", "webhook_fail", "webhook-reject":
		return "webhook_reject"
	case "auth_rate_limit", "ratelimit", "rate_limit", "auth-rate-limit":
		return "auth_rate_limit"
	case "enum_burst", "enum-burst":
		return "enum_burst"
	case "app_deny", "feature_deny", "app-deny":
		return "app_deny"
	case "idor", "id_or", "cross_tenant":
		return "idor"
	case "priv_esc", "privesc", "privilege_escalation":
		return "priv_esc"
	case "key_replay", "stolen_key", "api_key_replay":
		return "key_replay"
	case "ssrf_out", "ssrf", "outbound_ssrf":
		return "ssrf_out"
	case "upload_abuse", "upload", "stored_xss":
		return "upload_abuse"
	case "ws_abuse", "websocket":
		return "ws_abuse"
	case "logic_deny", "business_logic", "price_tamper":
		return "logic_deny"
	case "stepup_bypass", "2fa_bypass", "mfa_bypass":
		return "stepup_bypass"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}

// QuietStatic is a successful static file (CSS/JS/image) with nothing
// suspicious in the URL. The manager skips storing and alerting these
// so a busy site does not fill the disk with "someone loaded style.css".
func QuietStatic(ev Event) bool {
	if ev.Kind != "" && ev.Kind != KindWeb {
		return false
	}
	switch ev.Status {
	case 200, 204, 304:
	default:
		return false
	}
	blob := strings.ToLower(ev.Path + "?" + ev.Query + " " + ev.Decoded)
	for _, bad := range []string{"..", "%2e%2e", "union", "<script", "wp-config", ".env", ".git", "passwd"} {
		if strings.Contains(blob, bad) {
			return false
		}
	}
	p := strings.ToLower(ev.Path)
	dot := strings.LastIndex(p, ".")
	if dot < 0 || strings.Contains(p[dot+1:], "/") {
		return false
	}
	ext := p[dot:]
	switch ext {
	case ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mp3",
		".txt", ".xml", ".json" /* only as leaf static, not APIs — json often is API; skip */:
		if ext == ".json" || ext == ".xml" || ext == ".txt" {
			return strings.Contains(p, "/assets/") || strings.Contains(p, "/static/") ||
				strings.Contains(p, "/css/") || strings.Contains(p, "/js/")
		}
		return true
	default:
		return false
	}
}

// Alert is a detection fired against an event (or a threshold window).
type Alert struct {
	Num       int64     `json:"num,omitempty"`
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	EventID   string    `json:"event_id"`
	RuleID    string    `json:"rule_id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Category  string    `json:"category"`
	SrcIP     string    `json:"src_ip"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Status    int       `json:"status"`
	UA        string    `json:"ua"`
	Evidence  string    `json:"evidence"`
	MITRE     []string  `json:"mitre,omitempty"`
	Count     int       `json:"count,omitempty"`
	Source    string    `json:"source,omitempty"`
	Country   string    `json:"country,omitempty"`
	CountryName string  `json:"country_name,omitempty"`
	Lat       float64   `json:"lat,omitempty"`
	Lon       float64   `json:"lon,omitempty"`
	HasGeo    bool      `json:"has_geo,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
}

// Stats is a snapshot for the dashboard.
type Stats struct {
	EventsTotal  int64            `json:"events_total"`
	Events1h     int64            `json:"events_1h"`
	AlertsTotal  int64            `json:"alerts_total"`
	Alerts1h     int64            `json:"alerts_1h"`
	Critical1h   int64            `json:"critical_1h"`
	UniqueIPs1h  int64            `json:"unique_ips_1h"`
	BySeverity   map[string]int64 `json:"by_severity"`
	ByCategory   map[string]int64 `json:"by_category"`
	UptimeSec    int64            `json:"uptime_sec"`
	RulesLoaded  int              `json:"rules_loaded"`
	ByStatus     map[string]int64 `json:"by_status"`
}

// Attacker is an aggregated source IP.
type Attacker struct {
	SrcIP      string    `json:"src_ip"`
	Alerts     int64     `json:"alerts"`
	LastSeen   time.Time `json:"last_seen"`
	LastTitle  string    `json:"last_title"`
	MaxSev     string    `json:"max_severity"`
	Categories []string  `json:"categories"`
	Country    string    `json:"country,omitempty"`
}

// MapFeed is the live attack-map payload.
type MapFeed struct {
	Home      MapHome      `json:"home"`
	Homes     []MapHome    `json:"homes,omitempty"`
	GeoIP     bool         `json:"geoip"`
	Arcs      []MapArc     `json:"arcs"`
	Countries []MapCountry `json:"countries"`
}

type MapHome struct {
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Country string  `json:"country,omitempty"`
	Name    string  `json:"name,omitempty"`
	Source  string  `json:"source,omitempty"`
}

type MapArc struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	SrcIP    string    `json:"src_ip"`
	Title    string    `json:"title"`
	Severity string    `json:"severity"`
	Category string    `json:"category"`
	Country  string    `json:"country"`
	Name     string    `json:"name"`
	Lat      float64   `json:"lat"`
	Lon      float64   `json:"lon"`
	Source   string    `json:"source,omitempty"`
}

// SourceInfo is one shipper / local tail name for the host picker.
// Settings is operator config stored in SQLite (overrides flags after first save).
type Settings struct {
	SiteName string `json:"site_name"`
	Home     string `json:"home"`
	Homes    string `json:"homes"`
	Retain   string `json:"retain"`
	Timezone string `json:"timezone"`
}

// AlertPage is a lazy-loaded slice of the feed.
// SearchHit is one row from the FTS5 index (events + alerts).
type SearchHit struct {
	Bucket   string    `json:"bucket"`
	Ref      string    `json:"ref"`
	Num      int64     `json:"num,omitempty"`
	Time     time.Time `json:"time"`
	SrcIP    string    `json:"src_ip,omitempty"`
	User     string    `json:"user,omitempty"`
	Host     string    `json:"host,omitempty"`
	Source   string    `json:"source,omitempty"`
	Path     string    `json:"path,omitempty"`
	URL      string    `json:"url,omitempty"`
	Title    string    `json:"title,omitempty"`
	Kind     string    `json:"kind,omitempty"`
	Category string    `json:"category,omitempty"`
	Severity string    `json:"severity,omitempty"`
}

type SearchPage struct {
	Hits    []SearchHit `json:"hits"`
	HasMore bool        `json:"has_more"`
	TookMS  int64       `json:"took_ms"`
}

type AlertPage struct {
	Alerts   []Alert `json:"alerts"`
	HasMore  bool    `json:"has_more"`
	OldestNum int64  `json:"oldest_num,omitempty"`
	NewestNum int64  `json:"newest_num,omitempty"`
}

type SourceInfo struct {
	Name        string    `json:"name"`
	Events1h    int64     `json:"events_1h"`
	Alerts1h    int64     `json:"alerts_1h"`
	EventsTotal int64     `json:"events_total"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
}

type MapCountry struct {
	Country string `json:"country"`
	Name    string `json:"name"`
	Count   int64  `json:"count"`
}

// NameCount is a rollup row for reports.
type NameCount struct {
	Name  string `json:"name"`
	Key   string `json:"key,omitempty"`
	Count int64  `json:"count"`
	IPs   int64  `json:"ips,omitempty"`
}

type RuleCount struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

type HourCount struct {
	Time  time.Time `json:"time"`
	Count int64     `json:"count"`
}

// HourCat is one hour × category cell for stacked volume.
type HourCat struct {
	Time     time.Time `json:"time"`
	Category string    `json:"category"`
	Count    int64     `json:"count"`
}

type AuthIP struct {
	SrcIP    string    `json:"src_ip"`
	Count    int64     `json:"count"`
	Users    int64     `json:"users,omitempty"`
	LastUser string    `json:"last_user,omitempty"`
	LastSeen time.Time `json:"last_seen"`
	Country  string    `json:"country,omitempty"`
}

// VectorReport is the attack-vector insight page.
type VectorReport struct {
	Since      time.Time   `json:"since"`
	Until      time.Time   `json:"until"`
	Bucket     string      `json:"bucket,omitempty"`
	Timezone   string      `json:"timezone,omitempty"`
	Source     string      `json:"source,omitempty"`
	Alerts     int64       `json:"alerts"`
	UniqueIPs  int64       `json:"unique_ips"`
	Critical   int64       `json:"critical"`
	ByCategory []NameCount `json:"by_category"`
	BySeverity []NameCount `json:"by_severity"`
	BySource   []NameCount `json:"by_source"`
	ByMITRE    []NameCount `json:"by_mitre"`
	ByRule     []RuleCount `json:"by_rule"`
	ByPath     []NameCount `json:"by_path"`
	ByCountry  []NameCount `json:"by_country"`
	ByHour     []HourCount `json:"by_hour"`
	HourMix    []HourCat   `json:"hour_mix"`
	TopIPs     []Attacker  `json:"top_ips"`
}

// AuthReport is one authentication channel (web, linux, app).
type AuthReport struct {
	Channel     string         `json:"channel"`
	Since       time.Time      `json:"since"`
	Until       time.Time      `json:"until"`
	Source      string         `json:"source,omitempty"`
	Fails       int64          `json:"fails"`
	Fails1h     int64          `json:"fails_1h"`
	Success     int64          `json:"success"`
	UniqueIPs   int64          `json:"unique_ips"`
	UniqueUsers int64          `json:"unique_users"`
	ByStatus    map[string]int64 `json:"by_status"`
	ByPath      []NameCount    `json:"by_path"`
	ByUser      []NameCount    `json:"by_user"`
	BySource    []NameCount    `json:"by_source"`
	TopIPs      []AuthIP       `json:"top_ips"`
	Recent      []Event        `json:"recent"`
}
