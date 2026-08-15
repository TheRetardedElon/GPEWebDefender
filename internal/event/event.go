package event

import "time"

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
	Kind      string    `json:"kind,omitempty"`     // web | hostauth | applogin
	Outcome   string    `json:"outcome,omitempty"`  // fail | ok
}

const (
	KindWeb      = "web"
	KindHostAuth = "hostauth"
	KindAppLogin = "applogin"
	OutcomeFail  = "fail"
	OutcomeOK    = "ok"
)

// Alert is a detection fired against an event (or a threshold window).
type Alert struct {
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
	Source     string      `json:"source,omitempty"`
	Alerts     int64       `json:"alerts"`
	UniqueIPs  int64       `json:"unique_ips"`
	Critical   int64       `json:"critical"`
	ByCategory []NameCount `json:"by_category"`
	ByRule     []RuleCount `json:"by_rule"`
	ByPath     []NameCount `json:"by_path"`
	ByCountry  []NameCount `json:"by_country"`
	ByHour     []HourCount `json:"by_hour"`
	TopIPs     []Attacker  `json:"top_ips"`
}

// AuthReport is one authentication channel (web, linux, app).
type AuthReport struct {
	Channel     string         `json:"channel"`
	Since       time.Time      `json:"since"`
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
