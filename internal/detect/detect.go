package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"gpewebdefender/internal/event"
)

// Rule is a web-attack detector. Pattern rules fire on a single request.
// Threshold rules fire when count events matching filters land in a window.
type Rule struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Severity    string   `yaml:"severity"`
	Category    string   `yaml:"category"`
	MITRE       []string `yaml:"mitre"`
	Fields      []string `yaml:"fields"`
	Pattern     string   `yaml:"pattern"`
	Patterns    []string `yaml:"patterns"`
	NotPattern  string   `yaml:"not_pattern"`
	Methods     []string `yaml:"methods"`
	StatusIn    []int    `yaml:"status"`
	Kind        string   `yaml:"kind"`
	GroupBy     string   `yaml:"group_by"`
	Count       int      `yaml:"count"`
	Window      string   `yaml:"window"`
	PathPrefix   []string `yaml:"path_prefix"`
	PathContains []string `yaml:"path_contains"`
	Tags         []string `yaml:"tags"`
	MinGap       string   `yaml:"min_gap"`
	DistinctPaths int     `yaml:"distinct_paths"`
	EmptyReferer bool     `yaml:"empty_referer"`
	MaxAssetRatio float64 `yaml:"max_asset_ratio"`

	re     *regexp.Regexp
	notRe  *regexp.Regexp
	window time.Duration
	minGap time.Duration
}

type fileDoc struct {
	Rules []Rule `yaml:"rules"`
}

type bucket struct {
	times []time.Time
}

type sessHit struct {
	t       time.Time
	path    string
	status  int
	referer string
	static  bool
}

type session struct {
	hits []sessHit
}

// Engine evaluates events against compiled rules.
type Engine struct {
	mu     sync.Mutex
	rules  []Rule
	thresh map[string]map[string]*bucket // ruleID -> key -> times
	sess   map[string]*session           // src_ip -> recent hits
}

func New() *Engine {
	return &Engine{
		thresh: map[string]map[string]*bucket{},
		sess:   map[string]*session{},
	}
}

func (e *Engine) Len() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.rules)
}

func (e *Engine) Rules() []Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// LoadDir loads every *.yaml / *.yml in dir, or a single file.
func (e *Engine) LoadDir(dir string) error {
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	var files []string
	if !st.IsDir() {
		files = []string{dir}
	} else {
		err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".yaml" || ext == ".yml" {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	var all []Rule
	for _, f := range files {
		rs, err := loadFile(f)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		all = append(all, rs...)
	}
	return e.SetRules(all)
}

func loadFile(path string) ([]Rule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseRules(b)
}

// ParseRules compiles a YAML rules document.
func ParseRules(b []byte) ([]Rule, error) {
	var doc fileDoc
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	out := make([]Rule, 0, len(doc.Rules))
	for i := range doc.Rules {
		r := doc.Rules[i]
		if r.ID == "" || r.Title == "" {
			return nil, fmt.Errorf("rule #%d missing id/title", i)
		}
		if r.Severity == "" {
			r.Severity = "medium"
		}
		if r.Category == "" {
			r.Category = "web"
		}
		if r.Kind == "" {
			r.Kind = "pattern"
		}
		if len(r.Fields) == 0 {
			r.Fields = []string{"decoded", "ua"}
		}
		pats := r.Patterns
		if r.Pattern != "" {
			pats = append([]string{r.Pattern}, pats...)
		}
		if r.Kind == "pattern" && len(pats) == 0 {
			return nil, fmt.Errorf("rule %s: no pattern", r.ID)
		}
		if len(pats) > 0 {
			joined := "(?:" + strings.Join(pats, ")|(?:") + ")"
			re, err := regexp.Compile(joined)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.ID, err)
			}
			r.re = re
		}
		if r.NotPattern != "" {
			nre, err := regexp.Compile(r.NotPattern)
			if err != nil {
				return nil, fmt.Errorf("rule %s not_pattern: %w", r.ID, err)
			}
			r.notRe = nre
		}
		if r.Kind == "threshold" || r.Kind == "snoop" {
			if r.Count <= 0 {
				if r.Kind == "snoop" {
					r.Count = 5
				} else {
					r.Count = 20
				}
			}
			if r.Window == "" {
				if r.Kind == "snoop" {
					r.Window = "8m"
				} else {
					r.Window = "60s"
				}
			}
			d, err := time.ParseDuration(r.Window)
			if err != nil {
				return nil, fmt.Errorf("rule %s window: %w", r.ID, err)
			}
			r.window = d
			if r.GroupBy == "" {
				r.GroupBy = "src_ip"
			}
		}
		if r.Kind == "snoop" {
			if r.MinGap == "" {
				r.MinGap = "1500ms"
			}
			g, err := time.ParseDuration(r.MinGap)
			if err != nil {
				return nil, fmt.Errorf("rule %s min_gap: %w", r.ID, err)
			}
			r.minGap = g
			if r.DistinctPaths <= 0 {
				r.DistinctPaths = r.Count
			}
		}
		out = append(out, r)
	}
	return out, nil
}

func (e *Engine) SetRules(rules []Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
	e.thresh = map[string]map[string]*bucket{}
	e.sess = map[string]*session{}
	return nil
}

// AddRules appends compiled rules without dropping ones already loaded.
func (e *Engine) AddRules(rules []Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rules...)
}

// Evaluate returns zero or more alerts for one event.
func (e *Engine) Evaluate(ev event.Event) []event.Alert {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.note(ev)
	var out []event.Alert
	for i := range e.rules {
		r := &e.rules[i]
		if !preFilter(r, ev) {
			continue
		}
		switch r.Kind {
		case "threshold":
			if al, ok := e.hitThreshold(r, ev); ok {
				out = append(out, al)
			}
		case "snoop":
			if al, ok := e.hitSnoop(r, ev); ok {
				out = append(out, al)
			}
		default:
			if evd, ok := fieldMatch(r, ev); ok {
				out = append(out, makeAlert(r, ev, evd, 1))
			}
		}
	}
	return out
}

func preFilter(r *Rule, ev event.Event) bool {
	if len(r.Methods) > 0 {
		ok := false
		for _, m := range r.Methods {
			if strings.EqualFold(m, ev.Method) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.StatusIn) > 0 {
		ok := false
		for _, s := range r.StatusIn {
			if ev.Status == s {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.PathPrefix) > 0 {
		ok := false
		p := strings.ToLower(ev.Path)
		for _, pre := range r.PathPrefix {
			if strings.HasPrefix(p, strings.ToLower(pre)) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.PathContains) > 0 {
		ok := false
		p := strings.ToLower(ev.Path + "?" + ev.Query)
		for _, c := range r.PathContains {
			if strings.Contains(p, strings.ToLower(c)) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func fieldMatch(r *Rule, ev event.Event) (evidence string, ok bool) {
	if r.re == nil {
		return "", true
	}
	for _, f := range r.Fields {
		val := fieldOf(ev, f)
		if val == "" {
			continue
		}
		if loc := r.re.FindStringIndex(val); loc != nil {
			evd := clip(val, loc[0], loc[1])
			if r.notRe != nil && r.notRe.MatchString(val) {
				continue
			}
			return evd, true
		}
	}
	return "", false
}

func fieldOf(ev event.Event, name string) string {
	switch strings.ToLower(name) {
	case "url":
		return ev.URL
	case "path":
		return ev.Path
	case "query":
		return ev.Query
	case "decoded":
		return ev.Decoded
	case "ua", "user_agent":
		return ev.UA
	case "method":
		return ev.Method
	case "referer", "referrer":
		return ev.Referer
	case "host":
		return ev.Host
	case "raw":
		return ev.Raw
	case "src_ip", "ip":
		return ev.SrcIP
	case "user", "username":
		return ev.User
	case "kind":
		return ev.Kind
	case "outcome":
		return ev.Outcome
	case "reason", "why":
		return ev.Reason
	default:
		return ""
	}
}

func (e *Engine) hitThreshold(r *Rule, ev event.Event) (event.Alert, bool) {
	if r.re != nil {
		if _, ok := fieldMatch(r, ev); !ok {
			return event.Alert{}, false
		}
	}
	key := ev.SrcIP
	if r.GroupBy == "path" {
		key = ev.SrcIP + " " + ev.Path
	}
	byKey := e.thresh[r.ID]
	if byKey == nil {
		byKey = map[string]*bucket{}
		e.thresh[r.ID] = byKey
	}
	b := byKey[key]
	if b == nil {
		b = &bucket{}
		byKey[key] = b
	}
	now := ev.Time
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cut := now.Add(-r.window)
	kept := b.times[:0]
	for _, t := range b.times {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	b.times = kept
	if len(b.times) < r.Count {
		return event.Alert{}, false
	}
	// Fire once per crossing, then reset the window so we don't alert every extra hit.
	n := len(b.times)
	b.times = nil
	al := makeAlert(r, ev, fmt.Sprintf("%d hits in %s", n, r.window), n)
	return al, true
}

func (e *Engine) note(ev event.Event) {
	if ev.SrcIP == "" {
		return
	}
	now := ev.Time
	if now.IsZero() {
		now = time.Now().UTC()
	}
	st := e.sess[ev.SrcIP]
	if st == nil {
		st = &session{}
		e.sess[ev.SrcIP] = st
	}
	cut := now.Add(-15 * time.Minute)
	kept := st.hits[:0]
	for _, h := range st.hits {
		if h.t.After(cut) {
			kept = append(kept, h)
		}
	}
	st.hits = append(kept, sessHit{
		t: now, path: ev.Path, status: ev.Status,
		referer: ev.Referer, static: isStatic(ev.Path),
	})
	if len(st.hits) > 400 {
		st.hits = st.hits[len(st.hits)-400:]
	}
	// Bound map size.
	if len(e.sess) > 4000 {
		for ip, s := range e.sess {
			if len(s.hits) == 0 || s.hits[len(s.hits)-1].t.Before(cut) {
				delete(e.sess, ip)
			}
		}
	}
}

func isStatic(path string) bool {
	p := strings.ToLower(path)
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	for _, ext := range []string{".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

func (e *Engine) hitSnoop(r *Rule, ev event.Event) (event.Alert, bool) {
	st := e.sess[ev.SrcIP]
	if st == nil {
		return event.Alert{}, false
	}
	now := ev.Time
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cut := now.Add(-r.window)
	var probes []sessHit
	total, assets := 0, 0
	for _, h := range st.hits {
		if !h.t.After(cut) {
			continue
		}
		total++
		if h.static {
			assets++
			continue
		}
		tmp := ev
		tmp.Path = h.path
		tmp.URL = h.path
		tmp.Decoded = h.path
		tmp.Status = h.status
		tmp.Referer = h.referer
		if !preFilter(r, tmp) {
			continue
		}
		if r.re != nil {
			if _, ok := fieldMatch(r, tmp); !ok {
				continue
			}
		}
		if r.EmptyReferer && strings.Trim(h.referer, "- ") != "" {
			continue
		}
		probes = append(probes, h)
	}
	need := r.DistinctPaths
	if need <= 0 {
		need = r.Count
	}
	seen := map[string]struct{}{}
	for _, h := range probes {
		seen[h.path] = struct{}{}
	}
	if len(seen) < need {
		return event.Alert{}, false
	}
	if r.minGap > 0 && len(probes) >= 2 {
		gaps := make([]time.Duration, 0, len(probes)-1)
		for i := 1; i < len(probes); i++ {
			g := probes[i].t.Sub(probes[i-1].t)
			if g < 0 {
				g = -g
			}
			gaps = append(gaps, g)
		}
		// median gap
		for i := 1; i < len(gaps); i++ {
			for j := i; j > 0 && gaps[j] < gaps[j-1]; j-- {
				gaps[j], gaps[j-1] = gaps[j-1], gaps[j]
			}
		}
		med := gaps[len(gaps)/2]
		if med < r.minGap {
			return event.Alert{}, false
		}
	}
	if r.MaxAssetRatio > 0 && total > 0 {
		if float64(assets)/float64(total) > r.MaxAssetRatio {
			return event.Alert{}, false
		}
	}
	// Fire once per window per IP.
	key := ev.SrcIP
	byKey := e.thresh[r.ID]
	if byKey == nil {
		byKey = map[string]*bucket{}
		e.thresh[r.ID] = byKey
	}
	if b := byKey[key]; b != nil && len(b.times) > 0 && now.Sub(b.times[len(b.times)-1]) < r.window {
		return event.Alert{}, false
	}
	byKey[key] = &bucket{times: []time.Time{now}}
	paths := make([]string, 0, len(seen))
	for p := range seen {
		paths = append(paths, p)
		if len(paths) >= 6 {
			break
		}
	}
	evd := fmt.Sprintf("%d distinct paths in %s (median pace ≥ %s): %s",
		len(seen), r.window, r.minGap, strings.Join(paths, ", "))
	return makeAlert(r, ev, evd, len(seen)), true
}

func makeAlert(r *Rule, ev event.Event, evidence string, count int) event.Alert {
	return event.Alert{
		Time:     ev.Time,
		EventID:  ev.ID,
		RuleID:   r.ID,
		Title:    r.Title,
		Severity: r.Severity,
		Category: r.Category,
		SrcIP:    ev.SrcIP,
		Method:   ev.Method,
		URL:      ev.URL,
		Status:   ev.Status,
		UA:       ev.UA,
		Evidence: evidence,
		MITRE:    append([]string(nil), r.MITRE...),
		Count:    count,
		Source:   ev.Source,
		Tags:     append([]string(nil), r.Tags...),
	}
}

func clip(s string, start, end int) string {
	const pad = 24
	a := start - pad
	if a < 0 {
		a = 0
	}
	b := end + pad
	if b > len(s) {
		b = len(s)
	}
	out := s[a:b]
	if a > 0 {
		out = "…" + out
	}
	if b < len(s) {
		out = out + "…"
	}
	return out
}
