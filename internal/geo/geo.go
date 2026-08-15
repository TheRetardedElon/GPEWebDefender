package geo

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// Loc is a map point. Private IPs have Ok=false.
type Loc struct {
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Country string  `json:"country,omitempty"`
	Name    string  `json:"name,omitempty"`
	City    string  `json:"city,omitempty"`
	Ok      bool    `json:"ok"`
}

// Resolver looks up client IPs for the attack map.
type Resolver struct {
	mu    sync.RWMutex
	mmdb  *maxminddb.Reader
	pins  map[string]string // exact IP → ISO
	home  Loc
	homes map[string]Loc // agent --name / X-SIEM-Source → pin
}

func New() *Resolver {
	return &Resolver{
		pins:  defaultPins(),
		home:  mustHome("US"),
		homes: map[string]Loc{},
	}
}

func (r *Resolver) Home() Loc {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.home
}

// SetHome accepts "US", "DE", or "lat,lon" (e.g. 40.7,-74.0).
func (r *Resolver) SetHome(s string) error {
	loc, err := ParseHome(s)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.home = loc
	r.mu.Unlock()
	return nil
}

// SetHomes accepts "name=ISO;name=lat,lon". Name should match agent --name.
func (r *Resolver) SetHomes(s string) error {
	parsed, err := ParseHomes(s)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.homes = parsed
	r.mu.Unlock()
	return nil
}

// HomeFor returns the named pin for source, or the default --home.
func (r *Resolver) HomeFor(source string) Loc {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if source != "" {
		if loc, ok := r.homes[source]; ok {
			return loc
		}
	}
	return r.home
}

// NamedHomes is the configured extra pins, sorted by name.
func (r *Resolver) NamedHomes() []Loc {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Loc, 0, len(r.homes))
	for _, loc := range r.homes {
		out = append(out, loc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func ParseHome(s string) (Loc, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return mustHome("US"), nil
	}
	if loc, ok := Centroid(strings.ToUpper(s)); ok {
		loc.Ok = true
		return loc, nil
	}
	parts := strings.Split(s, ",")
	if len(parts) != 2 {
		return Loc{}, fmt.Errorf("geo: home must be ISO country or lat,lon")
	}
	lat, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	if err != nil {
		return Loc{}, err
	}
	lon, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	if err != nil {
		return Loc{}, err
	}
	return Loc{Lat: lat, Lon: lon, Country: "HOME", Name: "Home", Ok: true}, nil
}

// ParseHomes parses "edge=40.7,-74.0;proxy=US". Semicolons separate entries
// because lat,lon already uses a comma.
func ParseHomes(s string) (map[string]Loc, error) {
	out := map[string]Loc{}
	s = strings.TrimSpace(s)
	if s == "" {
		return out, nil
	}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, spec, ok := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		spec = strings.TrimSpace(spec)
		if !ok || name == "" || spec == "" {
			return nil, fmt.Errorf("geo: homes entry %q needs name=ISO or name=lat,lon", part)
		}
		loc, err := ParseHome(spec)
		if err != nil {
			return nil, fmt.Errorf("geo: homes %s: %w", name, err)
		}
		loc.Name = name
		out[name] = loc
	}
	return out, nil
}

func mustHome(iso string) Loc {
	loc, _ := Centroid(iso)
	loc.Ok = true
	return loc
}

// OpenMMDB loads a MaxMind / DB-IP country or city database. Optional.
func (r *Resolver) OpenMMDB(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return err
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	r.mu.Lock()
	if r.mmdb != nil {
		r.mmdb.Close()
	}
	r.mmdb = db
	r.mu.Unlock()
	return nil
}

func (r *Resolver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.mmdb != nil {
		r.mmdb.Close()
		r.mmdb = nil
	}
}

func (r *Resolver) HasMMDB() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mmdb != nil
}

// Lookup returns a plottable location for ip, or Ok=false.
func (r *Resolver) Lookup(ip string) Loc {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return Loc{}
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return Loc{}
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsUnspecified() {
		return Loc{}
	}
	if iso, ok := r.pin(ip); ok {
		return pinLoc(iso, ip)
	}
	if loc := r.fromMMDB(parsed); loc.Ok {
		return jitter(loc, ip)
	}
	return Loc{}
}

func (r *Resolver) pin(ip string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	iso, ok := r.pins[ip]
	return iso, ok
}

func pinLoc(iso, ip string) Loc {
	loc, ok := Centroid(iso)
	if !ok {
		return Loc{}
	}
	loc.Ok = true
	return jitter(loc, ip)
}

func jitter(loc Loc, ip string) Loc {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ip))
	n := h.Sum32()
	// ±1.8° so many hits in one country do not stack on a single pixel.
	dlat := (float64(n%360) / 360.0) * 3.6 - 1.8
	dlon := (float64((n/360)%360) / 360.0) * 3.6 - 1.8
	loc.Lat += dlat
	loc.Lon += dlon
	if loc.Lat > 85 {
		loc.Lat = 85
	}
	if loc.Lat < -85 {
		loc.Lat = -85
	}
	return loc
}

type mmdbCountry struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

func (r *Resolver) fromMMDB(ip net.IP) Loc {
	r.mu.RLock()
	db := r.mmdb
	r.mu.RUnlock()
	if db == nil {
		return Loc{}
	}
	var rec mmdbCountry
	if err := db.Lookup(ip, &rec); err != nil || rec.Country.ISOCode == "" {
		return Loc{}
	}
	iso := rec.Country.ISOCode
	name := rec.Country.Names["en"]
	if name == "" {
		if c, ok := Centroid(iso); ok {
			name = c.Name
		}
	}
	lat, lon := rec.Location.Latitude, rec.Location.Longitude
	if lat == 0 && lon == 0 {
		if c, ok := Centroid(iso); ok {
			lat, lon = c.Lat, c.Lon
		}
	}
	city := rec.City.Names["en"]
	return Loc{Lat: lat, Lon: lon, Country: iso, Name: name, City: city, Ok: true}
}

// IPKey is a stable uint32 for IPv4 (used by tests / pins).
func IPKey(ip string) uint32 {
	p := net.ParseIP(ip)
	if p == nil {
		return 0
	}
	v4 := p.To4()
	if v4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v4)
}
